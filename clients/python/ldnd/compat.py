"""
The ``ldn`` package's API, backed by ldnd.

Lets a program written against the original library keep its shape while the daemon does the work.
An existing script changes its import and drops its ``keys=`` argument; nothing else::

    # import ldn
    from ldnd import compat as ldn

Three differences are deliberate and cannot be papered over:

* **Keys are ignored.** :func:`load_keys` returns a marker and :attr:`ConnectNetworkParam.keys` is
  accepted and dropped. An ldnd client never handles key material, so a script that passes one is
  not doing what it thinks it is -- which is why this returns a marker rather than the file.
* **The password is not optional.** It goes into the link key, so a wrong or missing one produces a
  join that looks exactly like the host ignoring you. The original library had the same property;
  it is restated here because it is the single most likely thing to get wrong.
* **A host's three setters cannot report failure by raising.** They were plain methods in the
  original and stay callable without ``await`` here, which costs the reply -- see
  :class:`APNetwork`. A failure is printed to stderr instead of being lost.

The daemon serves one controlling client at a time, so :func:`scan` opens a connection and closes it
again before :func:`connect` or :func:`create_network` opens its own. For the same reason a program
may join or host, never both at once -- which is a property of the radio rather than of this shim.
"""

import contextlib
import os
import random
import sys

import trio

from . import client as _client
from . import protocol as _protocol

ACCEPT_ALL = _protocol.ACCEPT_ALL
ACCEPT_NONE = _protocol.ACCEPT_NONE
ACCEPT_BLACKLIST = _protocol.ACCEPT_BLACKLIST
ACCEPT_WHITELIST = _protocol.ACCEPT_WHITELIST

PLATFORM_NX = _protocol.PLATFORM_NX
PLATFORM_OUNCE = _protocol.PLATFORM_OUNCE

SECURITY_MODE_PROD = _protocol.SECURITY_MODE_PROD
SECURITY_MODE_DEBUG = _protocol.SECURITY_MODE_DEBUG
SECURITY_MODE_SYSTEM_DEBUG = _protocol.SECURITY_MODE_SYSTEM_DEBUG

NetworkInfo = _client.NetworkInfo
ParticipantInfo = _client.ParticipantInfo
DaemonError = _client.DaemonError

JoinEvent = _client.Joined
LeaveEvent = _client.Left
DisconnectEvent = _client.Disconnected
ApplicationDataChanged = _client.ApplicationDataChanged
AcceptPolicyChanged = _client.AcceptPolicyChanged

_VALID_CHANNELS = (1, 6, 11)

MacAddress = _client.MacAddress
MACAddress = _client.MacAddress

RADIO_TIMEOUT_MS = 30_000

BUSY_RETRY_MS = 5_000

#: The join budget handed to the daemon: how long *this* client will wait, not how long a join
#: should take.
#:
#: Measured on an RTL8822BU through LKL: a join is about 30 seconds, essentially all of it two
#: driver reconfigurations -- bringing the station interface up, and ``CMD_CONNECT`` -- that cost
#: roughly 14.5 seconds each over USB. Netlink itself is microseconds, and the LDN handshake on top
#: is under 5 ms. A budget below ~35 s therefore does not make a join fail faster; it makes every
#: join fail. This allows one full attempt plus most of a second.
JOIN_TIMEOUT_MS = 70_000

KEYS_ARE_THE_DAEMONS = object()


def _socket(ldnd_socket=None) -> str:
    return ldnd_socket or os.environ.get("LDN_DAEMON") or r"\\.\pipe\ldnd"


async def _wait_for_radio(connection) -> None:
    if await connection.wait_for_radio(RADIO_TIMEOUT_MS):
        return

    raise DaemonError(
        "wait_for_radio",
        _protocol.STATUS_NO_RADIO,
        "the adapter did not become ready within %is; is ldnd running with --usb?"
        % (RADIO_TIMEOUT_MS // 1000),
    )


def _unwrap(error: BaseException) -> BaseException:
    """
    The single exception inside a nested ``ExceptionGroup``, or the group unchanged.
    """
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]

    return error


def load_keys(path=None):
    """
    Accepted and ignored: the daemon loads ``prod.keys`` itself.
    """
    return KEYS_ARE_THE_DAEMONS


class ConnectNetworkParam:
    """
    The join parameters. ``keys``, ``ifname`` and ``phyname`` are accepted and ignored: the daemon
    owns the keys and the radio, so it chooses the interface.
    """

    def __init__(self):
        self.network = None
        self.password = b""
        self.name = b""
        self.app_version = 0
        self.platform = PLATFORM_NX
        self.enable_challenge = True
        self.device_id = 0
        self.dev = False

        self.keys = None
        self.client_random = None
        self.ifname = None
        self.phyname = None


class _Completed:
    """
    An awaitable that is already finished.
    """

    __slots__ = ()

    def __await__(self):
        return iter(())


class PacketChannel:
    def __init__(self, channel: "_client.Channel"):
        self._channel = channel
        self._send, self._recv = trio.open_memory_channel(1024)
        self._closed = False

    @property
    def handle(self) -> int:
        return self._channel.handle

    def _deliver(self, payload: bytes) -> None:
        try:
            self._send.send_nowait(payload)
        except trio.WouldBlock:
            pass

    async def recv(self) -> bytes:
        return await self._recv.receive()

    async def send(self, frame: bytes) -> None:
        await self._channel.send(frame)

    def close(self):
        """
        Closes the channel.

        Deliberately not ``async``, while still awaitable: callers do both. ``async with`` and the
        library's own teardown write ``await channel.close()``; ``LiveTransport.stop()`` calls
        ``s.close()`` synchronously, because for the real socket this replaces that was the whole
        API. Both now close the channel.
        """
        if not self._closed:
            self._closed = True
            self._channel.close_nowait()

        return _Completed()


class CreateNetworkParam:
    """
    The hosting parameters. ``keys`` is accepted and ignored; see the module docstring.

    Several of the original's fields are accepted and dropped rather than honoured:

    * ``keys`` and the three ``override_*_key`` fields, because an ldnd client never handles key
      material. The daemon derives every key from its own ``prod.keys``.
    * ``ifname_tap``. The original hand-built each data frame onto a tap interface, because its AP
      path never installed pairwise keys. The daemon does install them, so a host's data plane
      rides the AP interface exactly as a station's rides its own, and there is no tap to name.
      :meth:`APNetwork.create_packet_socket` is where that channel comes from.
    * ``ifname``, ``phyname``, ``ifname_monitor`` and ``phyname_monitor``, because the daemon owns
      the radio and chooses the interfaces it hosts on.
    """

    def __init__(self):
        self.local_communication_id = 0
        self.scene_id = 0

        self.max_participants = 8
        self.application_data = b""
        self.accept_policy = ACCEPT_ALL
        self.accept_filter = []
        self.security_mode = SECURITY_MODE_PROD
        self.ssid = None

        self.name = b""
        self.app_version = 0
        self.platform = PLATFORM_NX

        self.channel = None
        self.server_random = None
        self.password = b""

        self.version = 4
        self.enable_challenge = True
        self.device_id = random.randint(0, 0xFFFFFFFFFFFFFFFF)

        self.protocol = 1
        self.dev = False

        self.keys = None
        self.ifname = None
        self.ifname_monitor = None
        self.phyname = None
        self.phyname_monitor = None
        self.ifname_tap = None
        self.override_data_key = None
        self.override_advertise_key = None
        self.override_challenge_key = None

    def check(self):
        if self.max_participants > 8:
            raise ValueError("max_participants is too high")

        if len(self.application_data) > 0x180:
            raise ValueError("application_data is too large")

        if self.ssid is not None and len(self.ssid) != 16:
            raise ValueError("ssid has wrong size")

        if self.channel is not None and self.channel not in _VALID_CHANNELS:
            raise ValueError("channel is invalid")

        if self.server_random is not None and len(self.server_random) != 16:
            raise ValueError("server_random has wrong size")

        if self.version not in (2, 3, 4):
            raise ValueError("version is invalid")

        if self.protocol not in (1, 3):
            raise ValueError("protocol is not supported")


class _Network:
    def __init__(self, connection: "_client.Connection", network: "_client.Network"):
        self._connection = connection
        self._network = network
        self._channels: dict[int, PacketChannel] = {}
        self._events_send, self._events_recv = trio.open_memory_channel(256)

    def info(self) -> NetworkInfo:
        return self._network.info()

    def participant(self):
        return self._network.participant()

    def broadcast_address(self) -> str | None:
        return self._network.broadcast_address()

    async def next_event(self):
        """The next network event. Data frames are not events; they go to their channel."""
        return await self._events_recv.receive()

    async def create_packet_socket(self) -> PacketChannel:
        channel = await self._connection.open_raw(self._network)
        wrapper = PacketChannel(channel)
        self._channels[channel.handle] = wrapper

        return wrapper

    async def _pump(self) -> None:
        while True:
            event = await self._connection.next_event()
            if event is None:
                return

            if isinstance(event, _client.DataFrame):
                channel = self._channels.get(event.handle)
                if channel is not None:
                    channel._deliver(event.payload)
                continue

            if isinstance(event, _client.ChannelError):
                print("ldnd: channel error: %s" % event.message, file=sys.stderr, flush=True)

            try:
                self._events_send.send_nowait(event)
            except trio.WouldBlock:
                # A caller that never reads events must not be able to stall the frame path.
                pass


class STANetwork(_Network):
    """A joined network, shaped like the original library's."""


class APNetwork(_Network):
    """
    A hosted network, shaped like the original library's.

    **The three setters are not coroutines, and that is deliberate.** They were plain methods in
    the original -- local mutations that the advertisement thread picked up on its next pass -- so
    a script written against it calls them bare. Here each one is a request to the daemon, but it
    is queued rather than awaited, and what comes back is an already-finished awaitable. Both
    ``network.set_accept_policy(p)`` and ``await network.set_accept_policy(p)`` therefore work,
    which is the same treatment :meth:`PacketChannel.close` gets and for the same reason.

    What that costs is the reply: a setter cannot raise. It does not go unnoticed, though -- a
    non-zero status is printed to stderr by the connection, because a lobby that quietly stays open
    after being locked is the kind of failure nobody would trace back to here.

    :meth:`kick` is a coroutine, as it was in the original, so it is the one host operation that
    reports its failure by raising.
    """

    def set_application_data(self, data: bytes):
        self._connection.ldn_request_nowait(
            _protocol.LDN_SET_APPLICATION_DATA,
            _protocol.Writer().u32(self._network.handle).bytes(data).build(),
            label="SetApplicationData",
        )

        return _Completed()

    def set_accept_policy(self, policy: int):
        self._connection.ldn_request_nowait(
            _protocol.LDN_SET_ACCEPT_POLICY,
            _protocol.Writer().u32(self._network.handle).u8(policy).build(),
            label="SetAcceptPolicy",
        )

        return _Completed()

    def set_accept_filter(self, filter: list):
        """
        Replaces the addresses the accept policy names.

        Meaningful only under ``ACCEPT_BLACKLIST`` or ``ACCEPT_WHITELIST``. The filter is the
        host's own business rather than something it advertises, so nothing a station can see
        changes. An empty list clears it, which under a whitelist means nobody may join.
        """
        body = _protocol.Writer().u32(self._network.handle)
        body.list(filter, lambda address: body.fixed(bytes(MacAddress(address)), 6))

        self._connection.ldn_request_nowait(
            _protocol.LDN_SET_ACCEPT_FILTER,
            body.build(),
            label="SetAcceptFilter",
        )

        return _Completed()

    async def kick(self, index: int) -> None:
        """
        Removes the participant in slot ``index``.

        Slot zero is the host's own, and the daemon refuses it rather than letting a host
        disassociate itself from its own network.

        The original ignored a kick of an empty slot. This raises :class:`DaemonError` instead,
        because the daemon has to answer something and silence would be a worse answer: a slot
        index that is off by one is a live bug in the caller either way.
        """
        await self._connection.kick(self._network, index)


async def scan(
    keys=None,
    *,
    channels=None,
    dwell_time=None,
    protocols=None,
    phyname=None,
    ifname=None,
    ldnd_socket=None,
) -> list[NetworkInfo]:
    """
    ``keys``, ``phyname`` and ``ifname`` are accepted for source compatibility. The daemon owns the
    keys and the radio, so it chooses the interface; ``dwell_time`` is in seconds, as before.
    """
    dwell_ms = int(dwell_time * 1000) if dwell_time else None

    async with _client.connect(
        _socket(ldnd_socket), name="ldn-compat", busy_retry_ms=BUSY_RETRY_MS
    ) as connection:
        await _wait_for_radio(connection)

        networks = await connection.scan(
            channels=channels,
            dwell_ms=dwell_ms,
            protocols=protocols,
        )

        while connection.pending_event() is not None:
            pass

        return networks


@contextlib.asynccontextmanager
async def connect(param: ConnectNetworkParam, ldnd_socket=None):
    """
    Joins ``param.network`` and yields it, leaving the network when the block exits.

    Raises :class:`DaemonError` if the join fails; its message carries the daemon's own reason.
    """
    if param.network is None:
        raise ValueError("param.network is required")

    try:
        async with _client.connect(
            _socket(ldnd_socket), name="ldn-compat", busy_retry_ms=BUSY_RETRY_MS
        ) as connection:
            await _wait_for_radio(connection)

            network = await connection.connect(
                param.network,
                password=param.password,
                name=param.name,
                app_version=param.app_version or None,
                platform=param.platform,
                enable_challenge=param.enable_challenge,
                device_id=param.device_id,
                dev=param.dev,
                timeout_ms=JOIN_TIMEOUT_MS,
            )

            sta = STANetwork(connection, network)

            async with trio.open_nursery() as nursery:
                nursery.start_soon(sta._pump)
                try:
                    yield sta
                finally:
                    with trio.CancelScope(shield=True):
                        try:
                            await network.close()
                        except Exception:
                            pass

                    nursery.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        raise _unwrap(group) from None


@contextlib.asynccontextmanager
async def create_network(param: CreateNetworkParam, ldnd_socket=None):
    """
    Starts hosting a network and yields it, taking it down when the block exits.

    """
    param.check()

    try:
        async with _client.connect(
            _socket(ldnd_socket), name="ldn-compat", busy_retry_ms=BUSY_RETRY_MS
        ) as connection:
            await _wait_for_radio(connection)

            network = await connection.create_network(
                param.local_communication_id,
                scene_id=param.scene_id,
                password=param.password,
                name=param.name,
                app_version=param.app_version,
                platform=param.platform,
                max_participants=param.max_participants,
                application_data=param.application_data,
                accept_policy=param.accept_policy,
                accept_filter=param.accept_filter,
                security_mode=param.security_mode,
                ssid=param.ssid,
                channel=param.channel,
                server_random=param.server_random,
                version=param.version,
                enable_challenge=param.enable_challenge,
                device_id=param.device_id,
                ldn_protocol=param.protocol,
                dev=param.dev,
            )

            hosted = APNetwork(connection, network)

            async with trio.open_nursery() as nursery:
                nursery.start_soon(hosted._pump)
                try:
                    yield hosted
                finally:
                    with trio.CancelScope(shield=True):
                        try:
                            await network.close()
                        except Exception:
                            pass

                    nursery.cancel_scope.cancel()
    except BaseExceptionGroup as group:
        raise _unwrap(group) from None
