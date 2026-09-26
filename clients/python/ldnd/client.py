from __future__ import annotations

import contextlib
import math
import re
import secrets
import sys

from collections.abc import AsyncIterator

import trio

from . import protocol
from .protocol import (
    DaemonError,
    ProtocolError,
    Reader,
    Writer,
    parse_header,
    read_reply_prefix,
)

CLIENT_NAME = "ldnd-py"
CLIENT_VERSION = "0.1.0"


class WindowsPipeConnection:
    def __init__(self, handle: int):
        self._handle = handle

    @classmethod
    async def connect(cls, path: str) -> "WindowsPipeConnection":
        handle = await trio.to_thread.run_sync(cls._connect_sync, path)
        trio.lowlevel.register_with_iocp(handle)
        return cls(handle)

    @staticmethod
    def _connect_sync(path: str) -> int:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE

        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        OPEN_EXISTING = 3
        FILE_FLAG_OVERLAPPED = 0x40000000
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )

        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise OSError(ctypes.get_last_error(), "CreateFileW failed for %s" % path)

        return int(handle)

    async def sendall(self, data: bytes) -> None:
        buf = memoryview(data)
        offset = 0

        while offset < len(buf):
            written = await trio.lowlevel.write_overlapped(self._handle, buf[offset:])
            if written == 0:
                raise OSError(None, "WriteFile wrote 0 bytes")
            offset += written

    async def recvn(self, n: int) -> bytes | None:
        """Exactly ``n`` bytes, or None at end of stream."""
        if n == 0:
            return b""

        buf = bytearray()
        while len(buf) < n:
            chunk = bytearray(n - len(buf))
            try:
                got = await trio.lowlevel.readinto_overlapped(self._handle, chunk)
            except OSError:
                return None
            if got == 0:
                return None
            buf += chunk[:got]

        return bytes(buf)

    async def close(self) -> None:
        import ctypes

        try:
            ctypes.windll.kernel32.CloseHandle(self._handle)
        except Exception:
            pass


class SerialConnection:
    """
    ldnd on a serial port rather than a pipe: the GB-Link bridge firmware, an ESP32 whose USB
    console serves the daemon protocol with the board's own radio.

    The console is text until asked for the daemon, so opening the port writes the line
    ``LDN_DAEMON <token>`` and skips everything up to ``LDN_DAEMON_READY <token>``; after that the
    port carries frames exactly as the pipe does. The token tells this answer from one left over
    for a client that went away, whose frames may still be ahead of it.

    A pipe closing tells ldnd its client has gone. A serial port says nothing when it closes, so
    :meth:`close` writes the line again, which has the board let go of whatever this connection
    held. The board stays with the daemon until a client sends ``Shutdown``, which gives it back
    to its standalone bridge; after that the line is not sent, since it would take the console
    back.

    Needs pyserial. ``name`` is a port (``COM5``, ``/dev/ttyACM0``) or a pyserial URL
    (``socket://host:port``, ``rfc2217://host:port``).
    """

    BAUD = 921600
    """The original ESP32's console runs through a USB-to-UART bridge at this rate; a board on
    native USB ignores it."""

    READ_TIMEOUT = 0.1
    """How long one blocking read waits, which bounds how late a cancellation is noticed."""

    WRITE_TIMEOUT = 5.0
    ANSWER_TIMEOUT = 1.5
    ATTEMPTS = 3
    """The board drops a frame left unfinished for 300 ms, so a second attempt gets through
    even when the client before this one died halfway through writing one."""

    def __init__(self, port, name: str):
        self._port = port
        self._name = name
        self._pending = bytearray()
        self._closed = False
        self._shut_down = False

    @classmethod
    async def connect(cls, name: str) -> "SerialConnection":
        port = await trio.to_thread.run_sync(cls._open_sync, name)
        connection = cls(port, name)

        try:
            await connection._attach()
        except BaseException:
            await trio.to_thread.run_sync(port.close)
            raise

        return connection

    @classmethod
    def _open_sync(cls, name: str):
        try:
            import serial
        except ImportError as err:
            raise OSError(None, "the serial transport needs pyserial: pip install pyserial") from err

        if "://" in name:
            return serial.serial_for_url(
                name, timeout=cls.READ_TIMEOUT, write_timeout=cls.WRITE_TIMEOUT
            )

        port = serial.Serial()
        port.port = name
        port.baudrate = cls.BAUD
        port.timeout = cls.READ_TIMEOUT
        port.write_timeout = cls.WRITE_TIMEOUT
        # A board's reset circuit, or the ESP32's own USB port, restarts the chip when RTS is
        # asserted without DTR. Open with DTR held and RTS released, then let DTR go.
        port.dtr = True
        port.rts = False
        port.open()
        port.dtr = False
        return port

    async def _attach(self) -> None:
        token = secrets.token_hex(4)
        line = ("\nLDN_DAEMON %s\n" % token).encode()
        ready = ("LDN_DAEMON_READY %s\n" % token).encode()

        for _ in range(self.ATTEMPTS):
            await self.sendall(line)
            seen = bytearray()

            with trio.move_on_after(self.ANSWER_TIMEOUT):
                while True:
                    seen += await trio.to_thread.run_sync(self._read_sync)

                    at = seen.find(ready)
                    if at >= 0:
                        # Frames start right after the line.
                        self._pending = seen[at + len(ready) :]
                        return

                    # Console text before the answer; only a tail that could hold its start is kept.
                    del seen[: -len(ready)]

        raise OSError(
            None,
            "%s did not answer LDN_DAEMON: is it an ESP32 running bridge firmware with ldnd in it?"
            % self._name,
        )

    def _read_sync(self) -> bytes:
        # The first byte waits up to the timeout; whatever else has arrived comes with it, so a
        # frame is not held back waiting for a buffer to fill.
        data = self._port.read(1)
        if data:
            waiting = self._port.in_waiting
            if waiting:
                data += self._port.read(waiting)

        return data

    async def sendall(self, data: bytes) -> None:
        await trio.to_thread.run_sync(self._port.write, data)

        # The connection writes each frame whole, so its first byte is the op.
        if data[:1] == bytes([protocol.OP_SHUTDOWN]):
            self._shut_down = True

    async def recvn(self, n: int) -> bytes | None:
        """Exactly ``n`` bytes, or None once the port is gone."""
        while len(self._pending) < n:
            if self._closed:
                return None

            try:
                chunk = await trio.to_thread.run_sync(self._read_sync)
            except OSError:
                return None

            self._pending += chunk

        data = bytes(self._pending[:n])
        del self._pending[:n]
        return data

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        def release() -> None:
            # Best effort: a port that is already gone has nothing left to release.
            if not self._shut_down:
                try:
                    self._port.write(b"\nLDN_DAEMON\n")
                    self._port.flush()
                except Exception:
                    pass

            self._port.close()

        await trio.to_thread.run_sync(release)


SERIAL_PREFIX = "serial:"


def is_serial_path(path: str) -> bool:
    """
    Whether :func:`connect` takes ``path`` as a serial port rather than a pipe: ``serial:<port>``,
    where the port may also be a pyserial URL, or a bare ``COM5`` or ``/dev/...``.
    """
    return (
        path.startswith(SERIAL_PREFIX)
        or bool(re.fullmatch(r"(?i)com\d+", path))
        or path.startswith("/dev/")
    )


def serial_port_name(path: str) -> str:
    """The port, or pyserial URL, in a serial path."""
    return path[len(SERIAL_PREFIX) :] if path.startswith(SERIAL_PREFIX) else path


async def _open_connection(path: str) -> "WindowsPipeConnection | SerialConnection":
    """A named pipe to ldnd, or a serial port with ldnd behind it; see :func:`is_serial_path`."""
    if is_serial_path(path):
        return await SerialConnection.connect(serial_port_name(path))

    if sys.platform == "win32":
        return await WindowsPipeConnection.connect(path)

    raise NotImplementedError(
        "named pipes are Windows-only; name a serial port as serial:<port> instead of %r" % path
    )


class HelloResult:
    def __init__(self, body: bytes, wireless_protocol: int = protocol.WIRELESS_LDN):
        reader = Reader(body)
        self.status, self.error_message, bare = read_reply_prefix(reader)

        self.wireless_protocol = wireless_protocol

        # A Hello the daemon could not parse at all is answered with a bare status reply, so a
        # failure may stop here.
        if bare:
            self.protocol_version = 0
            self.daemon_version = ""
            self.ldn_capabilities = 0
            self.nwm_capabilities = 0
            self.radio_ready = False
            return

        self.protocol_version = reader.u32()
        self.daemon_version = reader.str()
        self.ldn_capabilities = reader.u8()
        self.nwm_capabilities = reader.u8()
        self.radio_ready = reader.bool()
        reader.expect_end()

    @property
    def capabilities(self) -> int:
        """The ``CAP_*`` bits for the wireless protocol this connection selected."""
        if self.wireless_protocol == protocol.WIRELESS_NWM:
            return self.nwm_capabilities

        return self.ldn_capabilities

    def __repr__(self) -> str:
        return (
            "HelloResult(status=%s, wireless=%s, daemon_version=%r, capabilities=%s, "
            "radio_ready=%s)"
            % (
                protocol.status_name(self.status),
                protocol.WIRELESS_NAMES.get(self.wireless_protocol, self.wireless_protocol),
                self.daemon_version,
                protocol.capability_names(self.capabilities),
                self.radio_ready,
            )
        )


class LogLine:
    def __init__(self, line: str):
        self.line = line

    def __repr__(self) -> str:
        return "LogLine(%r)" % self.line


class LogDropped:
    """The daemon dropped lines because this client fell behind."""

    def __init__(self, lines: int):
        self.lines = lines

    def __repr__(self) -> str:
        return "LogDropped(%i)" % self.lines


class RadioStateChanged:
    def __init__(self, state: int, message: str | None):
        self.state = state
        self.message = message

    def __repr__(self) -> str:
        return "RadioStateChanged(%s, %r)" % (protocol.radio_name(self.state), self.message)


class Joined:
    def __init__(self, handle: int, index: int, participant: "ParticipantInfo"):
        self.handle = handle
        self.index = index
        self.participant = participant

    def __repr__(self) -> str:
        return "Joined(slot=%i, %r)" % (self.index, self.participant)


class Left:
    def __init__(self, handle: int, index: int, participant: "ParticipantInfo"):
        self.handle = handle
        self.index = index
        self.participant = participant

    def __repr__(self) -> str:
        return "Left(slot=%i, %r)" % (self.index, self.participant)


class Disconnected:
    def __init__(self, handle: int, reason: int):
        self.handle = handle
        self.reason = reason

    def __repr__(self) -> str:
        return "Disconnected(reason=%i)" % self.reason


class ApplicationDataChanged:
    def __init__(self, handle: int, old: bytes, new: bytes):
        self.handle = handle
        self.old = old
        self.new = new

    def __repr__(self) -> str:
        return "ApplicationDataChanged(%i -> %i bytes)" % (len(self.old), len(self.new))


class AcceptPolicyChanged:
    def __init__(self, handle: int, old: int, new: int):
        self.handle = handle
        self.old = old
        self.new = new

    def __repr__(self) -> str:
        return "AcceptPolicyChanged(%s -> %s)" % (
            protocol.ACCEPT_POLICY_NAMES.get(self.old, self.old),
            protocol.ACCEPT_POLICY_NAMES.get(self.new, self.new),
        )


class ChannelError:
    """A data channel failed. This is how an unacknowledged send reports trouble."""

    def __init__(self, handle: int, status: int, message: str):
        self.handle = handle
        self.status = status
        self.message = message

    def __repr__(self) -> str:
        return "ChannelError(%s: %s)" % (
            protocol.STATUS_NAMES.get(self.status, self.status),
            self.message,
        )


class DataFrame:
    def __init__(self, handle: int, payload: bytes):
        self.handle = handle
        self.payload = payload

    def __repr__(self) -> str:
        return "DataFrame(handle=%i, %i bytes)" % (self.handle, len(self.payload))


class Datagram:
    def __init__(self, handle: int, peer: str, port: int, payload: bytes):
        self.handle = handle
        self.peer = peer
        self.port = port
        self.payload = payload

    def __repr__(self) -> str:
        return "Datagram(handle=%i, from %s:%i, %i bytes)" % (
            self.handle,
            self.peer,
            self.port,
            len(self.payload),
        )


def _decode_event(body: bytes):
    reader = Reader(body)
    kind = reader.u8()

    if kind == protocol.EV_LOG:
        event = LogLine(reader.str())
    elif kind == protocol.EV_LOG_DROPPED:
        event = LogDropped(reader.u32())
    elif kind == protocol.EV_NETWORK_FOUND:
        event = NetworkFound(NetworkInfo(reader))
    elif kind == protocol.EV_SCAN_DONE:
        event = ScanDone(reader.u32())
    elif kind in (protocol.EV_JOIN, protocol.EV_LEAVE):
        handle = reader.u32()
        index = reader.u8()
        participant = ParticipantInfo(reader)
        kind_class = Joined if kind == protocol.EV_JOIN else Left
        event = kind_class(handle, index, participant)
    elif kind == protocol.EV_DISCONNECT:
        handle = reader.u32()
        event = Disconnected(handle, reader.u8())
    elif kind == protocol.EV_APPDATA_CHANGED:
        handle = reader.u32()
        old = reader.bytes()
        event = ApplicationDataChanged(handle, old, reader.bytes())
    elif kind == protocol.EV_POLICY_CHANGED:
        handle = reader.u32()
        old = reader.u8()
        event = AcceptPolicyChanged(handle, old, reader.u8())
    elif kind == protocol.EV_CHANNEL_ERROR:
        handle = reader.u32()
        status = reader.u8()
        event = ChannelError(handle, status, reader.str())
    elif kind == protocol.EV_RADIO_STATE:
        state = reader.u8()
        event = RadioStateChanged(state, reader.optional(reader.str))
    else:
        raise ProtocolError("unknown event kind %i" % kind)

    reader.expect_end()
    return event


class ParticipantInfo:
    def __init__(self, reader: Reader):
        self.ip_address = _ipv4(reader.fixed(4))
        self.mac_address = _mac(reader.fixed(6))
        self.connected = reader.bool()
        self.name = reader.bytes()
        self.app_version = reader.u16()
        self.platform = reader.u8()

    def name_str(self) -> str:
        return self.name.decode("utf-8", "replace")

    def __repr__(self) -> str:
        return "ParticipantInfo(%r, %s, %s, connected=%s)" % (
            self.name_str(),
            self.ip_address,
            self.mac_address,
            self.connected,
        )


class NetworkInfo:
    def __init__(self, reader: Reader):
        start = reader.offset

        self.protocol = reader.u8()
        self.address = _mac(reader.fixed(6))
        self.band = reader.u8()
        self.channel = reader.u8()
        self.local_communication_id = reader.u64()
        self.scene_id = reader.u16()
        self.ssid = reader.fixed(16)
        self.version = reader.u8()
        self.server_random = reader.fixed(16)
        self.security_mode = reader.u16()
        self.app_version = reader.u16()
        self.accept_policy = reader.u8()
        self.max_participants = reader.u8()
        self.num_participants = reader.u8()
        # All eight slots, connected or not: a participant's index is its position.
        self.participants = reader.list(lambda: ParticipantInfo(reader))
        self.application_data = reader.bytes()
        self.challenge = reader.u64()
        self.nonce = reader.fixed(4)

        self.raw = reader.body[start : reader.offset]

    def is_joinable(self) -> bool:
        return (
            self.accept_policy != protocol.ACCEPT_NONE
            and self.num_participants < self.max_participants
        )

    def connected_participants(self) -> list[ParticipantInfo]:
        return [p for p in self.participants if p.connected]

    def __repr__(self) -> str:
        return (
            "NetworkInfo(comm_id=%016x, scene=%i, channel=%i, %i/%i, policy=%s)"
            % (
                self.local_communication_id,
                self.scene_id,
                self.channel,
                self.num_participants,
                self.max_participants,
                protocol.ACCEPT_POLICY_NAMES.get(self.accept_policy, self.accept_policy),
            )
        )


class NetworkFound:
    def __init__(self, network: NetworkInfo):
        self.network = network

    def __repr__(self) -> str:
        return "NetworkFound(%r)" % (self.network,)


class ScanDone:
    def __init__(self, count: int):
        self.count = count

    def __repr__(self) -> str:
        return "ScanDone(%i)" % self.count


class MacAddress:
    """
    Compares equal to the string and to the raw bytes, so existing code that does either keeps
    working.
    """

    __slots__ = ("_octets",)

    def __init__(self, value):
        if isinstance(value, MacAddress):
            octets = value._octets
        elif isinstance(value, str):
            octets = bytes(int(part, 16) for part in value.split(":"))
        else:
            octets = bytes(value)

        if len(octets) != 6:
            raise ValueError("a MAC address is six bytes, got %i" % len(octets))

        self._octets = octets

    def __bytes__(self) -> bytes:
        return self._octets

    def __str__(self) -> str:
        return ":".join("%02x" % b for b in self._octets)

    def __repr__(self) -> str:
        return "MacAddress('%s')" % self

    def __eq__(self, other) -> bool:
        if isinstance(other, MacAddress):
            return self._octets == other._octets
        if isinstance(other, str):
            return str(self) == other.lower()
        if isinstance(other, (bytes, bytearray)):
            return self._octets == bytes(other)

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._octets)

    def __len__(self) -> int:
        return 6

    def __iter__(self):
        return iter(self._octets)

    def __getitem__(self, index):
        return self._octets[index]

    def hex(self) -> str:
        return self._octets.hex()

    def is_zero(self) -> bool:
        return self._octets == b"\0" * 6


def _mac(raw: bytes) -> MacAddress:
    return MacAddress(raw)


def _ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _handle_body(handle: int) -> bytes:
    """The body of a request whose only argument is the network or channel it acts on."""
    return Writer().u32(handle).build()


def _read_network_reply(reply: Reader) -> "tuple[int, NetworkInfo | None, int]":
    handle = reply.u32()
    reply.optional(reply.u8)  # auth_status, which only a refused join carries
    info = reply.optional(lambda: NetworkInfo(reply))
    index = reply.optional(reply.u8)
    reply.expect_end()

    return handle, info, index or 0


class Network:
    """
    A joined network.

    The counterpart of what ``ldn.connect()`` yields. Events for the network arrive on the
    connection's :meth:`Connection.events`, not here, because a client usually wants one stream for
    everything rather than one per handle.
    """

    def __init__(self, connection: "Connection", reply: Reader):
        self._connection = connection
        self._closed = False

        self._handle, self._info, self.participant_index = _read_network_reply(reply)

    @property
    def handle(self) -> int:
        return self._handle

    def info(self) -> NetworkInfo | None:
        """The network as it was when the join completed."""
        return self._info

    def participant(self) -> "ParticipantInfo | None":
        if self._info is None:
            return None
        if self.participant_index >= len(self._info.participants):
            return None

        return self._info.participants[self.participant_index]

    def local_address(self) -> str | None:
        participant = self.participant()
        return participant.ip_address if participant else None

    def broadcast_address(self) -> str | None:
        address = self.local_address()
        if address is None:
            return None

        parts = address.split(".")
        if len(parts) != 4:
            return None

        return "%s.%s.%s.255" % (parts[0], parts[1], parts[2])

    async def refresh(self) -> NetworkInfo | None:
        reply = await self._connection.ldn_request(
            protocol.LDN_GET_NETWORK_INFO, _handle_body(self._handle)
        )

        _handle, info, _index = _read_network_reply(reply)
        if info is not None:
            self._info = info

        return self._info

    async def close(self) -> None:
        """Leaves the network. Harmless to call twice."""
        if self._closed:
            return

        self._closed = True
        await self._connection.ldn_request(protocol.LDN_CLOSE_NETWORK, _handle_body(self._handle))

    async def __aenter__(self) -> "Network":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()


class Channel:
    """
    An open data channel: raw Ethernet frames to and from the LDN interface.

    The counterpart of ``create_packet_socket()`` in the Python stack. Frames arrive on the
    connection's event stream as :class:`DataFrame`, because one stream for everything is easier to
    drive than one per handle.

    A packet socket also sees what it sends, so a client that echoes what it receives will talk to
    itself. Filter on the source address -- which a client has to do anyway to tell participants
    apart.
    """

    def __init__(self, connection: "Connection", handle: int):
        self._connection = connection
        self._handle = handle
        self._closed = False

    @property
    def handle(self) -> int:
        return self._handle

    async def send(self, frame: bytes) -> None:
        """
        Sends one Ethernet frame, header included.

        Deliberately unacknowledged: acking every frame would halve throughput. A send that fails
        arrives later as a :class:`ChannelError` event.
        """
        await self._connection.send_data(self._handle, frame)

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        await self._connection.ldn_request(protocol.LDN_CLOSE_CHANNEL, _handle_body(self._handle))

    def close_nowait(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._connection.close_channel_nowait(self._handle)

    async def __aenter__(self) -> "Channel":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()


class DatagramChannel:
    """
    An open UDP channel on the LDN interface.
    """

    def __init__(self, connection: "Connection", handle: int, port: int):
        self._connection = connection
        self._handle = handle
        self._port = port
        self._closed = False

    @property
    def handle(self) -> int:
        return self._handle

    @property
    def port(self) -> int:
        """The port actually bound, which differs from the one requested if that was 0."""
        return self._port

    async def send_to(self, payload: bytes, peer: str, port: int = protocol.LDN_PORT) -> None:
        """
        Sends one payload to one peer, addressed as a dotted quad.

        Unacknowledged, exactly as :meth:`Channel.send` is; a send that fails arrives later as a
        :class:`ChannelError` event.

        Note that sending to a broadcast address is currently refused by the daemon's kernel --
        ``SO_BROADCAST`` is not exposed by the shim yet. Unicast to each participant works.
        """
        body = protocol.pack_datagram(peer, port, payload)
        await self._connection.send_data(self._handle, body)

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._connection._datagram_handles.discard(self._handle)
        await self._connection.ldn_request(protocol.LDN_CLOSE_CHANNEL, _handle_body(self._handle))

    async def __aenter__(self) -> "DatagramChannel":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()


class Connection:
    def __init__(self, conn: WindowsPipeConnection | SerialConnection):
        self._conn = conn
        self._next_request_id = 1
        self._pending: dict[int, trio.Event] = {}
        self._replies: dict[int, bytes] = {}
        self._out_send, self._out_recv = trio.open_memory_channel(math.inf)
        self._event_send, self._event_recv = trio.open_memory_channel(math.inf)
        self._closed = False
        # DATA carries no channel kind, so the reader cannot tell a frame from a datagram by
        # looking at one. It has to remember which handles were opened as datagram channels.
        self._datagram_handles: set[int] = set()
        self._nowait: dict[int, str] = {}
        # Nothing after the reply to Shutdown comes from the daemon: ldnd exits, and the bridge
        # firmware gives its serial port back to its text console.
        self._shutdown_request: int | None = None

        self.hello: HelloResult | None = None


    async def request(self, op: int, body: bytes = b"", sub_op: int = 0) -> Reader:
        """
        Sends a request and waits for its Reply, raising on a non-zero status.

        Returns a reader positioned after the reply's status prefix, for the fields that follow.
        """
        reader = Reader(await self.request_raw(op, body, sub_op))

        status, message, _bare = read_reply_prefix(reader)
        if status != protocol.STATUS_NONE:
            raise DaemonError(protocol.op_name(op, sub_op), status, message)

        return reader

    async def ldn_request(self, sub_op: int, body: bytes = b"") -> Reader:
        """An OP_LDN :meth:`request`; ``sub_op`` is an ``LDN_*`` value."""
        return await self.request(protocol.OP_LDN, body, sub_op)

    async def request_raw(self, op: int, body: bytes = b"", sub_op: int = 0) -> bytes:
        """Sends a request and returns the Reply's body without checking the status."""
        request_id = self._next_request_id
        self._next_request_id += 1

        if op == protocol.OP_SHUTDOWN:
            self._shutdown_request = request_id

        event = trio.Event()
        self._pending[request_id] = event

        await self._out_send.send(protocol.pack_frame(op, request_id, body, sub_op))
        await event.wait()

        reply = self._replies.pop(request_id, None)
        if reply is None:
            raise ConnectionError("the daemon closed the connection before replying")

        return reply

    async def wait_for_radio(self, timeout_ms: int = 30_000) -> bool:
        """
        Waits until the adapter is usable, and says whether it got there.
        Events seen while waiting are put back in the order they arrived, so this can be called
        without swallowing anything.
        """
        if self.hello is not None and self.hello.radio_ready:
            return True

        held: list = []
        ready = False

        with trio.move_on_after(timeout_ms / 1000):
            while True:
                event = await self.next_event()
                if event is None:
                    break

                if isinstance(event, RadioStateChanged):
                    if event.state == protocol.RADIO_READY:
                        ready = True
                        break

                    if event.state == protocol.RADIO_FAILED:
                        break

                    continue

                held.append(event)

        for event in held:
            try:
                self._event_send.send_nowait(event)
            except (trio.BrokenResourceError, trio.WouldBlock, trio.ClosedResourceError):
                pass

        return ready

    async def subscribe_log(self) -> None:
        await self.request(protocol.OP_SUBSCRIBE_LOG)

    async def scan(
        self,
        *,
        channels: list[int] | None = None,
        dwell_ms: int | None = None,
        protocols: list[int] | None = None,
        timeout_ms: int | None = None,
    ) -> list[NetworkInfo]:
        """
        Scans for nearby LDN networks.

        Omitted arguments use the daemon's defaults (channels 1/6/11, 110 ms dwell, protocols
        1 and 3). Takes roughly ``len(channels) * dwell_ms`` to return. ``EV_NETWORK_FOUND``
        events arrive on :meth:`events` as the scan runs if you would rather fill a list live.
        """
        body = Writer()
        body.bytes(bytes(channels or []))
        body.optional(dwell_ms, body.u32)
        body.bytes(bytes(protocols or []))
        body.optional(timeout_ms, body.u32)

        reply = await self.ldn_request(protocol.LDN_SCAN, body.build())

        networks = reply.list(lambda: NetworkInfo(reply))
        reply.expect_end()
        return networks

    async def connect(
        self,
        network: NetworkInfo,
        *,
        password: bytes = b"",
        name: bytes = b"",
        app_version: int | None = None,
        platform: int = protocol.PLATFORM_NX,
        enable_challenge: bool = True,
        device_id: int = 0,
        dev: bool = False,
        timeout_ms: int | None = None,
    ) -> Network:
        """
        Joins ``network``, which is one of the entries :meth:`scan` returned.

        The counterpart of ``ldn.connect()``. There is no ``keys`` argument (the daemon owns
        ``prod.keys``), but ``password`` is **not** optional for a game that uses one: it goes into
        the link key, and with the wrong one the host acknowledges every frame and then silently
        drops it, which is indistinguishable from being ignored.

        ``app_version`` defaults to the network's own, which is what a client joining an existing
        session usually wants.

        Takes several seconds: the daemon scans for the network on its station interface, then
        associates, then runs the LDN handshake. It retries the whole sequence a few times, so the
        worst case is considerably longer than the typical one -- pass ``timeout_ms`` if you have a
        deadline of your own. Doing so does not make a join faster; it stops the daemon starting an
        attempt you have already given up on, which is what otherwise leaves the radio busy and
        your own retry refused as ``BUSY``.
        """
        if app_version is None:
            app_version = network.app_version

        body = Writer()
        body.fixed(network.raw, len(network.raw))
        body.bytes(password)
        body.bytes(name)
        body.u16(app_version)
        body.u8(platform)
        body.bool(enable_challenge)
        body.u64(device_id)
        body.optional(None, lambda value: body.fixed(value, 16))  # client_random: the daemon picks
        body.bool(dev)
        body.optional(timeout_ms, body.u32)

        reply = await self.ldn_request(protocol.LDN_CONNECT, body.build())

        return Network(self, reply)

    async def create_network(
        self,
        local_communication_id: int,
        *,
        scene_id: int = 0,
        password: bytes = b"",
        name: bytes = b"",
        app_version: int = 0,
        platform: int = protocol.PLATFORM_NX,
        max_participants: int | None = None,
        application_data: bytes = b"",
        accept_policy: int | None = None,
        accept_filter: "list[MacAddress] | None" = None,
        security_mode: int | None = None,
        ssid: bytes | None = None,
        channel: int | None = None,
        server_random: bytes | None = None,
        version: int | None = None,
        enable_challenge: bool = True,
        device_id: int = 0,
        ldn_protocol: int | None = None,
        dev: bool = False,
    ) -> Network:
        """
        Hosts a network, and returns it as the host's own :class:`Network`.

        Only ``local_communication_id`` is positional, because it is the one thing a game cannot
        default -- it is what stations filter a scan on. Everything else has a working default, and
        the two that must be unpredictable, ``ssid`` and ``server_random``, are generated by the
        daemon unless you pass them. Pass them only to reproduce a fixed network in a test.

        ``password`` matters here for the same reason it matters when joining: it goes into the
        CCMP key alongside the server random, so a host and a station that disagree about it
        associate and then exchange nothing.

        The returned network is slot zero of its own participant table. It stays on the air for as
        long as it is open -- the daemon advertises it roughly ten times a second -- so close it
        when you are done, or use it as a context manager.
        """
        body = Writer()
        body.u64(local_communication_id)
        body.u16(scene_id)
        body.optional(max_participants, body.u8)
        body.bytes(application_data)
        body.optional(accept_policy, body.u8)
        body.list(accept_filter or [], lambda address: body.fixed(bytes(MacAddress(address)), 6))
        body.optional(security_mode, body.u16)
        body.optional(ssid, lambda value: body.fixed(value, 16))
        body.bytes(name)
        body.u16(app_version)
        body.u8(platform)
        body.optional(channel, body.u8)
        body.optional(server_random, lambda value: body.fixed(value, 16))
        body.bytes(password)
        body.optional(version, body.u8)
        body.bool(enable_challenge)
        body.u64(device_id)
        body.optional(ldn_protocol, body.u8)
        body.bool(dev)

        reply = await self.ldn_request(protocol.LDN_CREATE_NETWORK, body.build())

        return Network(self, reply)

    async def set_prod_keys(self, prod_keys: str) -> None:
        """
        Replaces the daemon's loaded ``prod.keys``, in the same ``name = hex`` text format the
        file itself uses.

        Not tied to a network handle; it affects every network opened after it returns.
        """
        await self.ldn_request(protocol.LDN_SET_PROD_KEYS, Writer().str(prod_keys).build())

    async def has_prod_keys(self) -> bool:
        """Whether the daemon has ``prod.keys`` loaded, from ``--keys`` or :meth:`set_prod_keys`."""
        reply = await self.ldn_request(protocol.LDN_HAS_PROD_KEYS)

        loaded = reply.bool()
        reply.expect_end()

        return loaded

    async def set_application_data(self, network: "Network", data: bytes) -> None:
        """
        Replaces the game-specific payload a hosted network advertises.

        Host only. Stations see the change on their next advertisement and report it as an
        :class:`ApplicationDataChanged` event carrying both the old value and the new one.

        An empty payload is a value, not an omission: passing ``b""`` clears it.
        """
        await self._connection_request_host(
            network,
            protocol.LDN_SET_APPLICATION_DATA,
            Writer().bytes(data).build(),
        )

    async def set_accept_policy(self, network: "Network", policy: int) -> None:
        """
        Changes who a hosted network will accept: one of the ``ACCEPT_*`` constants.

        Host only. ``ACCEPT_NONE`` closes the network to new stations without disturbing the ones
        already in it, which is how a game locks a lobby.
        """
        await self._connection_request_host(
            network,
            protocol.LDN_SET_ACCEPT_POLICY,
            Writer().u8(policy).build(),
        )

    async def set_accept_filter(
        self, network: "Network", addresses: "list[MacAddress]"
    ) -> None:
        """
        Replaces the addresses a hosted network's accept policy names.

        Host only, and meaningful only under ``ACCEPT_BLACKLIST`` or ``ACCEPT_WHITELIST``. The
        filter is the host's own business rather than something it advertises, so changing it
        produces no event and no visible change on the air.

        An empty list clears the filter, which under a whitelist means nobody may join.
        """
        body = Writer()
        body.list(addresses, lambda address: body.fixed(bytes(MacAddress(address)), 6))

        await self._connection_request_host(network, protocol.LDN_SET_ACCEPT_FILTER, body.build())

    async def kick(self, network: "Network", index: int) -> None:
        """
        Removes the participant in slot ``index`` from a hosted network.

        Host only. Slot zero is the host itself, so this raises rather than removing you.

        The station is told before it is removed, because once the association is gone there is no
        way left to say why. It sees a :class:`Disconnected` event; every other participant sees a
        :class:`Left`.
        """
        if index == 0:
            raise ValueError("slot 0 is the host; it cannot be kicked")

        await self._connection_request_host(
            network,
            protocol.LDN_KICK,
            Writer().u8(index).build(),
        )

    async def _connection_request_host(
        self, network: "Network", sub_op: int, body: bytes
    ) -> None:
        await self.ldn_request(sub_op, _handle_body(network.handle) + body)

    async def open_raw(self, network: "Network") -> Channel:
        reply = await self.ldn_request(protocol.LDN_OPEN_RAW, _handle_body(network.handle))

        handle = reply.u32()
        reply.expect_end()

        return Channel(self, handle)

    async def open_datagram(self, network: "Network", port: int = protocol.LDN_PORT) -> "DatagramChannel":
        """
        Opens a UDP channel on a joined network.

        ``port`` defaults to LDN's own 12345, which is where a game's traffic actually is. Pass 0 to
        let the daemon's kernel choose one; the channel's ``port`` then reports what it got.

        The socket binds the wildcard address rather than this station's, because the host's
        traffic is broadcast to ``169.254.<net>.255`` and would otherwise not be delivered here.
        """
        reply = await self.ldn_request(
            protocol.LDN_OPEN_DATAGRAM,
            Writer().u32(network.handle).u16(port).build(),
        )

        handle = reply.u32()
        bound = reply.u16()
        reply.expect_end()

        self._datagram_handles.add(handle)

        return DatagramChannel(self, handle, bound)

    async def send_data(self, handle: int, payload: bytes) -> None:
        """Sends one DATA frame. Not acknowledged; failures arrive as ChannelError events."""
        await self._out_send.send(
            protocol.pack_frame(protocol.OP_DATA, 0, protocol.pack_data(handle, payload))
        )

    def request_nowait(
        self, op: int, body: bytes = b"", *, sub_op: int = 0, label: str = ""
    ) -> None:
        """
        Queues a request without waiting for its Reply.
        No waiter is registered, so the Reply is read by the loop and discarded. ``label`` is what
        the failure is called if one comes back: a dropped success is what "nowait" means, but a
        dropped *failure* would leave the caller believing the daemon did what it asked. Pass the
        operation's name to have that reported on stderr; leave it empty to drop both.

        The outbound channel is unbounded, so this cannot block.
        """
        request_id = self._next_request_id
        self._next_request_id += 1

        if label:
            self._nowait[request_id] = label

        # RuntimeError is caught alongside the trio errors, and it is the interesting one: a trio
        # memory channel's send_nowait reschedules a waiting task, so it may only be touched from
        # inside the trio run. Teardown does not always happen there -- `LiveTransport.stop()` runs
        # on the thread that *started* the trio run, from outside it -- and there is nothing to do
        # about that here. Falling through is correct rather than merely tolerable: the caller has
        # already recorded whatever it was closing, and the daemon frees everything when the
        # connection drops, which in every such path is moments away.
        try:
            self._out_send.send_nowait(protocol.pack_frame(op, request_id, body, sub_op))
        except (
            RuntimeError,
            trio.BrokenResourceError,
            trio.WouldBlock,
            trio.ClosedResourceError,
        ):
            self._nowait.pop(request_id, None)

    def ldn_request_nowait(self, sub_op: int, body: bytes = b"", *, label: str = "") -> None:
        """An OP_LDN :meth:`request_nowait`; ``sub_op`` is an ``LDN_*`` value."""
        self.request_nowait(protocol.OP_LDN, body, sub_op=sub_op, label=label)

    def close_channel_nowait(self, handle: int) -> None:
        self.ldn_request_nowait(protocol.LDN_CLOSE_CHANNEL, _handle_body(handle))

    def _report_unwaited(self, request_id: int, body: bytes) -> None:
        label = self._nowait.pop(request_id, None)
        if label is None:
            return

        status, message, _bare = read_reply_prefix(Reader(body))
        if status == protocol.STATUS_NONE:
            return

        print(
            "ldnd: %s failed: %s%s"
            % (label, protocol.status_name(status), ": %s" % message if message else ""),
            file=sys.stderr,
            flush=True,
        )

    async def scan_cancel(self) -> None:
        """Asks an in-flight scan to stop early. Harmless if none is running."""
        await self.ldn_request(protocol.LDN_SCAN_CANCEL)

    async def shutdown(self) -> None:
        await self.request(protocol.OP_SHUTDOWN)


    async def next_event(self):
        """The next unsolicited event, or None once the connection closes."""
        try:
            return await self._event_recv.receive()
        except (trio.EndOfChannel, trio.ClosedResourceError):
            return None

    def pending_event(self):
        """
        The next event if one is already queued, or None. Never waits.
        """
        try:
            return self._event_recv.receive_nowait()
        except (trio.WouldBlock, trio.EndOfChannel, trio.ClosedResourceError):
            return None

    async def events(self) -> AsyncIterator:
        while True:
            event = await self.next_event()
            if event is None:
                return
            yield event


    async def _handshake(
        self,
        name: str = CLIENT_NAME,
        version: str = CLIENT_VERSION,
        wireless: int = protocol.WIRELESS_LDN,
    ) -> HelloResult:
        body = (
            Writer()
            .u32(protocol.PROTOCOL_VERSION)
            .u8(wireless)
            .str(name)
            .str(version)
            .build()
        )

        reply = await self.request_raw(protocol.OP_HELLO, body)
        self.hello = HelloResult(reply, wireless)
        return self.hello

    async def _read_loop(self) -> None:
        while True:
            header = await self._conn.recvn(protocol.FRAME_HEADER_LEN)
            if header is None:
                await self._shutdown()
                return

            op, _sub_op, request_id, body_length = parse_header(header)

            if body_length > protocol.MAX_BODY:
                await self._shutdown()
                raise ProtocolError("daemon announced a %i byte body" % body_length)

            body = await self._conn.recvn(body_length)
            if body is None:
                await self._shutdown()
                return

            if op == protocol.OP_REPLY:
                waiter = self._pending.pop(request_id, None)
                if waiter is not None:
                    self._replies[request_id] = body
                    waiter.set()
                else:
                    self._report_unwaited(request_id, body)

                if request_id == self._shutdown_request:
                    await self._shutdown()
                    return

            elif op == protocol.OP_DATA:
                try:
                    handle, payload = protocol.unpack_data(body)
                except ValueError:
                    continue

                if handle in self._datagram_handles:
                    try:
                        peer, port, payload = protocol.unpack_datagram(payload)
                    except ValueError:
                        continue

                    arrival = Datagram(handle, peer, port, payload)
                else:
                    arrival = DataFrame(handle, payload)

                try:
                    self._event_send.send_nowait(arrival)
                except trio.WouldBlock:
                    pass

            elif op == protocol.OP_EVENT:
                event = _decode_event(body)
                try:
                    self._event_send.send_nowait(event)
                except (trio.BrokenResourceError, trio.WouldBlock, trio.ClosedResourceError):
                    pass

    async def _writer_loop(self) -> None:
        async for data in self._out_recv:
            try:
                await self._conn.sendall(data)
            except OSError:
                return

    async def _shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True

        for waiter in list(self._pending.values()):
            waiter.set()
        self._pending.clear()

        with contextlib.suppress(trio.ClosedResourceError):
            await self._out_send.aclose()
        with contextlib.suppress(trio.ClosedResourceError):
            await self._event_send.aclose()

    async def aclose(self) -> None:
        """Closes the pipe or port. Only safe once no I/O is outstanding."""
        await self._conn.close()


@contextlib.asynccontextmanager
async def connect(
    path: str,
    *,
    require_ok: bool = True,
    name: str = CLIENT_NAME,
    version: str = CLIENT_VERSION,
    busy_retry_ms: int = 0,
    wireless: int = protocol.WIRELESS_LDN,
) -> AsyncIterator[Connection]:
    """
    Connects to ldnd and performs the Hello handshake.

    ``path`` is ldnd's named pipe (``\\\\.\\pipe\\ldnd``), or a serial port with ldnd behind it --
    the GB-Link bridge firmware on an ESP32 -- written ``serial:COM5`` or ``serial:/dev/ttyACM0``,
    or as a pyserial URL such as ``serial:socket://host:port``. A bare ``COM5`` or ``/dev/...``
    is taken as a serial port too. See :class:`SerialConnection`.

    With ``require_ok`` (the default) a refused handshake raises :class:`DaemonError` -- most
    usefully ``BUSY``, which carries the name of the client that already holds the daemon. Pass
    ``require_ok=False`` to inspect the refusal yourself; the daemon closes the pipe either way.

    ``wireless`` selects what the connection speaks: :data:`WIRELESS_LDN` (the default) or
    :data:`WIRELESS_NWM`. The daemon accepts NWM but does not implement any of its operations yet.

    ``name`` is what *this* client is called in that refusal when someone else runs into it, so a
    program with more than one entry point should set it.

    ``busy_retry_ms`` re-attempts the handshake for that long when it is refused as ``BUSY``. The
    default of 0 is right for a client that is genuinely second in the queue -- being told at once
    is the point. It is *not* right for a program that just closed its own connection and is
    opening another: the daemon releases control when it notices the pipe close, which is quick but
    not instant, so back-to-back connections race against their own predecessor. Anything doing
    scan-then-join wants a second or two here.
    """
    deadline = trio.current_time() + busy_retry_ms / 1000

    while True:
        try:
            async with _connect_once(path, require_ok, name, version, wireless) as conn:
                yield conn
            return
        except protocol.HandshakeRefused as refusal:
            if refusal.code != protocol.STATUS_BUSY or trio.current_time() >= deadline:
                raise

        await trio.sleep(0.1)


@contextlib.asynccontextmanager
async def _connect_once(
    path: str,
    require_ok: bool,
    name: str,
    version: str,
    wireless: int,
) -> AsyncIterator[Connection]:
    conn = Connection(await _open_connection(path))
    refusal: protocol.HandshakeRefused | None = None

    async with trio.open_nursery() as nursery:
        nursery.start_soon(conn._read_loop)
        nursery.start_soon(conn._writer_loop)

        try:
            hello = await conn._handshake(name, version, wireless)

            if require_ok and hello.status != protocol.STATUS_NONE:
                # Deliberately not raised here. An exception thrown inside a nursery comes out
                # wrapped in an ExceptionGroup, and "daemon is busy" is the single most likely
                # thing a caller wants to catch by type. Record it and raise once the nursery has
                # closed, so callers get a plain DaemonError.
                refusal = protocol.HandshakeRefused("Hello", hello.status, hello.error_message)
            else:
                yield conn
        finally:
            # Order matters: cancelling first lets trio call CancelIoEx on a handle that is still
            # valid. Closing the handle first makes that fail with WinError 6, which trio escalates
            # to TrioInternalError.
            await conn._shutdown()
            nursery.cancel_scope.cancel()

    await conn.aclose()

    if refusal is not None:
        raise refusal
