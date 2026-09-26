"""
ldnd wire format.

Mirrors ``crates/ldn/src/protocol`` in the ldnrs tree, which is the source of truth. A connection
picks LDN or NWM in Hello and then speaks in whole operations.

Frame::

    offset size field
    0      1    op
    1      1    sub_op        an LDN_* under OP_LDN, an NWM op under OP_NWM; 0 otherwise
    2      4    request_id    echoed in Reply; 0 in Event and Data
    6      4    body_length
    10     ..   body

There is no handle in the header: a message about a network or channel carries it in its body, as
the first field of a request or event and right after the status prefix of a reply.

The body is the Rust message struct's fields in declaration order, except for ``OP_DATA`` whose
body is the raw payload. All integers are little-endian, and:

    bool          one byte, 0 or 1
    bytes[N]      the bytes as they are (addresses, SSIDs, randoms)
    bytes, str    u32 length, then the bytes (UTF-8 for str)
    list          u32 count, then each element
    optional      one byte, 0 or 1, then the value only when it is 1

There are no tags, so there is nothing to skip: a body must be read exactly, and any layout change
is a ``PROTOCOL_VERSION`` bump. Every reply starts with ``status: u8, error_message: optional
str``, and a failed reply may stop there -- see :func:`read_reply_prefix`.
"""

from __future__ import annotations

import struct

PROTOCOL_VERSION = 7


OP_HELLO = 0x01
OP_SUBSCRIBE_LOG = 0x02
OP_SHUTDOWN = 0x03

OP_LDN = 0x10
OP_NWM = 0x11

# The sub_op of an OP_LDN frame.

LDN_SCAN = 0x20
LDN_SCAN_CANCEL = 0x21

LDN_CONNECT = 0x30
LDN_CREATE_NETWORK = 0x31
LDN_CLOSE_NETWORK = 0x32
LDN_GET_NETWORK_INFO = 0x33

LDN_SET_APPLICATION_DATA = 0x40
LDN_SET_ACCEPT_POLICY = 0x41
LDN_SET_ACCEPT_FILTER = 0x42
LDN_KICK = 0x43

LDN_OPEN_DATAGRAM = 0x50
LDN_OPEN_RAW = 0x51
LDN_CLOSE_CHANNEL = 0x52

LDN_SET_PROD_KEYS = 0x60
LDN_HAS_PROD_KEYS = 0x61

OP_REPLY = 0x80
OP_EVENT = 0x81
OP_DATA = 0x82

OP_NAMES = {
    OP_HELLO: "HELLO",
    OP_SUBSCRIBE_LOG: "SUBSCRIBE_LOG",
    OP_SHUTDOWN: "SHUTDOWN",
    OP_LDN: "LDN",
    OP_NWM: "NWM",
    OP_REPLY: "REPLY",
    OP_EVENT: "EVENT",
    OP_DATA: "DATA",
}

LDN_NAMES = {
    LDN_SCAN: "SCAN",
    LDN_SCAN_CANCEL: "SCAN_CANCEL",
    LDN_CONNECT: "CONNECT",
    LDN_CREATE_NETWORK: "CREATE_NETWORK",
    LDN_CLOSE_NETWORK: "CLOSE_NETWORK",
    LDN_GET_NETWORK_INFO: "GET_NETWORK_INFO",
    LDN_SET_APPLICATION_DATA: "SET_APPLICATION_DATA",
    LDN_SET_ACCEPT_POLICY: "SET_ACCEPT_POLICY",
    LDN_SET_ACCEPT_FILTER: "SET_ACCEPT_FILTER",
    LDN_KICK: "KICK",
    LDN_OPEN_DATAGRAM: "OPEN_DATAGRAM",
    LDN_OPEN_RAW: "OPEN_RAW",
    LDN_CLOSE_CHANNEL: "CLOSE_CHANNEL",
    LDN_SET_PROD_KEYS: "SET_PROD_KEYS",
    LDN_HAS_PROD_KEYS: "HAS_PROD_KEYS",
}


STATUS_NONE = 0
STATUS_BAD_REQUEST = 1
STATUS_UNSUPPORTED_VERSION = 2
STATUS_INVALID_HANDLE = 3
STATUS_INVALID_PARAM = 4
STATUS_BUSY = 5
STATUS_NO_RADIO = 6
STATUS_NO_KEYS = 7
STATUS_NOT_FOUND = 8
STATUS_TIMEOUT = 9
STATUS_AUTH_FAILED = 10
STATUS_IO = 11
STATUS_UNSUPPORTED = 12
STATUS_INTERNAL = 13

STATUS_NAMES = {
    STATUS_NONE: "NONE",
    STATUS_BAD_REQUEST: "BAD_REQUEST",
    STATUS_UNSUPPORTED_VERSION: "UNSUPPORTED_VERSION",
    STATUS_INVALID_HANDLE: "INVALID_HANDLE",
    STATUS_INVALID_PARAM: "INVALID_PARAM",
    STATUS_BUSY: "BUSY",
    STATUS_NO_RADIO: "NO_RADIO",
    STATUS_NO_KEYS: "NO_KEYS",
    STATUS_NOT_FOUND: "NOT_FOUND",
    STATUS_TIMEOUT: "TIMEOUT",
    STATUS_AUTH_FAILED: "AUTH_FAILED",
    STATUS_IO: "IO",
    STATUS_UNSUPPORTED: "UNSUPPORTED",
    STATUS_INTERNAL: "INTERNAL",
}


EV_NETWORK_FOUND = 1
EV_SCAN_DONE = 2
EV_JOIN = 3
EV_LEAVE = 4
EV_DISCONNECT = 5
EV_APPDATA_CHANGED = 6
EV_POLICY_CHANGED = 7
EV_CHANNEL_ERROR = 8
EV_LOG = 9
EV_RADIO_STATE = 10
EV_LOG_DROPPED = 11


BACKEND_LKL = 0
BACKEND_HOST = 1
BACKEND_ESP32 = 2

# Chosen once, in Hello. NWM (3DS local wireless) is accepted by the daemon but every operation
# past the shared control ones is answered UNSUPPORTED for now.

WIRELESS_LDN = 0
WIRELESS_NWM = 1

WIRELESS_NAMES = {
    WIRELESS_LDN: "LDN",
    WIRELESS_NWM: "NWM",
}

RADIO_IDLE = 0
RADIO_ATTACHING = 1
RADIO_READY = 2
RADIO_LOST = 3
RADIO_FAILED = 4

RADIO_NAMES = {
    RADIO_IDLE: "IDLE",
    RADIO_ATTACHING: "ATTACHING",
    RADIO_READY: "READY",
    RADIO_LOST: "LOST",
    RADIO_FAILED: "FAILED",
}

# Hello's reply carries one byte per wireless protocol, LDN's then NWM's, and both use these bits.
# The kernel log is not a capability: it belongs to the radio, so every connection can subscribe.

CAP_SCAN = 1 << 0
CAP_STATION = 1 << 1
CAP_ACCESS_POINT = 1 << 2

CAP_NAMES = {
    CAP_SCAN: "SCAN",
    CAP_STATION: "STATION",
    CAP_ACCESS_POINT: "ACCESS_POINT",
}

LDN_PORT = 12345

# A DATA body is not a message struct: the channel's handle as a u32, then the payload with no
# length in front of it, because the frame header already says how long the body is.
DATA_HANDLE_LEN = 4

# A datagram channel's payload: four address bytes in dotted-quad order, then the port
# little-endian, then the datagram.
DATAGRAM_PREFIX_LEN = 6


def pack_data(handle: int, payload: bytes) -> bytes:
    return struct.pack("<I", handle & 0xFFFFFFFF) + payload


def unpack_data(body: bytes) -> tuple[int, bytes]:
    if len(body) < DATA_HANDLE_LEN:
        raise ValueError("DATA body is %i bytes, need %i" % (len(body), DATA_HANDLE_LEN))

    (handle,) = struct.unpack_from("<I", body, 0)
    return handle, body[DATA_HANDLE_LEN:]


def pack_datagram(peer: str, port: int, payload: bytes) -> bytes:
    octets = bytes(int(part) for part in peer.split("."))
    if len(octets) != 4:
        raise ValueError("peer must be a dotted quad, not %r" % (peer,))

    return octets + struct.pack("<H", port) + payload


def unpack_datagram(body: bytes) -> tuple[str, int, bytes]:
    if len(body) < DATAGRAM_PREFIX_LEN:
        raise ValueError("datagram body is %i bytes, need %i" % (len(body), DATAGRAM_PREFIX_LEN))

    peer = ".".join(str(byte) for byte in body[:4])
    (port,) = struct.unpack_from("<H", body, 4)

    return peer, port, body[DATAGRAM_PREFIX_LEN:]


ACCEPT_ALL = 0
ACCEPT_NONE = 1
ACCEPT_BLACKLIST = 2
ACCEPT_WHITELIST = 3

SECURITY_MODE_PROD = 1
SECURITY_MODE_DEBUG = 2
SECURITY_MODE_SYSTEM_DEBUG = 3

PLATFORM_NX = 0
PLATFORM_OUNCE = 1

ACCEPT_POLICY_NAMES = {
    ACCEPT_ALL: "ALL",
    ACCEPT_NONE: "NONE",
    ACCEPT_BLACKLIST: "BLACKLIST",
    ACCEPT_WHITELIST: "WHITELIST",
}

PLATFORM_NAMES = {
    PLATFORM_NX: "Switch",
    PLATFORM_OUNCE: "Switch 2",
}


HEADER = struct.Struct("<BBII")
FRAME_HEADER_LEN = 10
MAX_BODY = 256 * 1024

assert HEADER.size == FRAME_HEADER_LEN


def status_name(code: int) -> str:
    return STATUS_NAMES.get(code, "UNKNOWN(%i)" % code)


def radio_name(code: int) -> str:
    return RADIO_NAMES.get(code, "UNKNOWN(%i)" % code)


def capability_names(mask: int) -> list[str]:
    return [name for bit, name in CAP_NAMES.items() if mask & bit]


class DaemonError(Exception):
    """A Reply frame that carried a non-zero status."""

    def __init__(self, operation: str, code: int, message: str | None = None) -> None:
        self.code = code
        self.message = message

        detail = ": %s" % message if message else ""
        super().__init__("daemon %s failed: %s%s" % (operation, status_name(code), detail))


class HandshakeRefused(DaemonError):
    """
    The daemon refused the Hello itself.

    A subclass rather than a flag so a retry can tell it apart from an operation that merely
    *answered* ``BUSY`` -- a second ``CONNECT`` on one connection does that, and reconnecting would
    not help it. Anything catching :class:`DaemonError` still catches this.
    """


class ProtocolError(Exception):
    """The daemon sent something that does not decode."""


def op_name(op: int, sub_op: int = 0) -> str:
    if op == OP_LDN:
        return LDN_NAMES.get(sub_op, "LDN op %#04x" % sub_op)

    return OP_NAMES.get(op, "op %#04x" % op)


def pack_frame(op: int, request_id: int = 0, body: bytes = b"", sub_op: int = 0) -> bytes:
    if len(body) > MAX_BODY:
        raise ValueError(
            "body of %i bytes exceeds the daemon's limit of %i" % (len(body), MAX_BODY)
        )

    return HEADER.pack(op, sub_op, request_id & 0xFFFFFFFF, len(body)) + body


def parse_header(data: bytes) -> tuple[int, int, int, int]:
    """Returns ``(op, sub_op, request_id, body_length)``."""
    return HEADER.unpack_from(data, 0)


class Reader:
    def __init__(self, body: bytes, offset: int = 0) -> None:
        self.body = body
        self.offset = offset

    def remaining(self) -> int:
        return len(self.body) - self.offset

    def at_end(self) -> bool:
        return self.offset >= len(self.body)

    def expect_end(self) -> None:
        if not self.at_end():
            raise ProtocolError("%i bytes left over after the last field" % self.remaining())

    def fixed(self, length: int) -> bytes:
        end = self.offset + length
        if end > len(self.body):
            raise ProtocolError(
                "wanted %i bytes at offset %i, only %i left" % (length, self.offset, self.remaining())
            )

        value = self.body[self.offset : end]
        self.offset = end
        return value

    def _unpack(self, fmt: str, size: int) -> int:
        return struct.unpack("<" + fmt, self.fixed(size))[0]

    def u8(self) -> int:
        return self._unpack("B", 1)

    def u16(self) -> int:
        return self._unpack("H", 2)

    def u32(self) -> int:
        return self._unpack("I", 4)

    def u64(self) -> int:
        return self._unpack("Q", 8)

    def bool(self) -> bool:
        value = self.u8()
        if value not in (0, 1):
            raise ProtocolError("flag byte at offset %i is %i, not 0 or 1" % (self.offset - 1, value))
        return value == 1

    def bytes(self) -> bytes:
        return self.fixed(self.u32())

    def str(self) -> str:
        try:
            return self.bytes().decode("utf-8")
        except UnicodeDecodeError as err:
            raise ProtocolError("a string is not valid UTF-8") from err

    def optional(self, read):
        return read() if self.bool() else None

    def list(self, read) -> list:
        return [read() for _ in range(self.u32())]


class Writer:
    def __init__(self) -> None:
        self._buf = bytearray()

    def build(self) -> bytes:
        return bytes(self._buf)

    def fixed(self, value: bytes, length: int) -> "Writer":
        if len(value) != length:
            raise ValueError("expected %i bytes, got %i" % (length, len(value)))
        self._buf += value
        return self

    def u8(self, value: int) -> "Writer":
        self._buf += struct.pack("<B", value & 0xFF)
        return self

    def u16(self, value: int) -> "Writer":
        self._buf += struct.pack("<H", value & 0xFFFF)
        return self

    def u32(self, value: int) -> "Writer":
        self._buf += struct.pack("<I", value & 0xFFFFFFFF)
        return self

    def u64(self, value: int) -> "Writer":
        self._buf += struct.pack("<Q", value)
        return self

    def bool(self, value: bool) -> "Writer":
        return self.u8(1 if value else 0)

    def bytes(self, value: bytes) -> "Writer":
        self.u32(len(value))
        self._buf += value
        return self

    def str(self, value: str) -> "Writer":
        return self.bytes(value.encode("utf-8"))

    def optional(self, value, write) -> "Writer":
        if value is None:
            return self.u8(0)

        self.u8(1)
        write(value)
        return self

    def list(self, values, write) -> "Writer":
        values = list(values)
        self.u32(len(values))
        for value in values:
            write(value)
        return self


def read_reply_prefix(reader: Reader) -> tuple[int, str | None, bool]:
    """
    Reads the ``status, error_message`` every reply starts with.

    Returns ``(status, message, bare)``, where ``bare`` says the reply stopped there. Only a
    failure may: the daemon answers any request it could not carry out with a bare status reply,
    whatever the op, so a failed reply of any type can be just these two fields.
    """
    status = reader.u8()
    message = reader.optional(reader.str)

    return status, message, status != STATUS_NONE and reader.at_end()
