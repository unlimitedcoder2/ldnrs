"""
A client for the ldnd protocol.

Every operation the protocol defines is implemented: ``scan``, ``connect``, ``create_network``,
the data channels and the four host-only mutators. Check :attr:`Connection.hello` capabilities
rather than assuming, though -- a daemon built without one still answers ``UNSUPPORTED``, and a
capability is a promise about the protocol rather than about the adapter that happens to be
attached.

    async with ldnd.connect(r"\\\\.\\pipe\\ldnd") as conn:
        print(conn.hello)
        await conn.subscribe_log()
        async for event in conn.events():
            print(event)

The same protocol also comes over a serial port from the GB-Link bridge firmware on an ESP32, whose
own radio does the work: ``ldnd.connect("serial:COM5")``. That needs pyserial.
"""

from ldnd.client import (
    CLIENT_NAME,
    CLIENT_VERSION,
    Connection,
    HelloResult,
    LogDropped,
    LogLine,
    MacAddress,
    NetworkFound,
    NetworkInfo,
    ParticipantInfo,
    RadioStateChanged,
    ScanDone,
    connect,
)
from ldnd.protocol import (
    ACCEPT_ALL,
    ACCEPT_BLACKLIST,
    ACCEPT_NONE,
    ACCEPT_WHITELIST,
    BACKEND_ESP32,
    BACKEND_HOST,
    BACKEND_LKL,
    CAP_ACCESS_POINT,
    CAP_SCAN,
    CAP_STATION,
    PROTOCOL_VERSION,
    RADIO_ATTACHING,
    RADIO_FAILED,
    RADIO_IDLE,
    RADIO_LOST,
    RADIO_READY,
    PLATFORM_NX,
    PLATFORM_OUNCE,
    SECURITY_MODE_DEBUG,
    SECURITY_MODE_PROD,
    SECURITY_MODE_SYSTEM_DEBUG,
    STATUS_BUSY,
    STATUS_NONE,
    STATUS_NO_KEYS,
    STATUS_NO_RADIO,
    STATUS_UNSUPPORTED,
    STATUS_UNSUPPORTED_VERSION,
    WIRELESS_LDN,
    WIRELESS_NWM,
    DaemonError,
    ProtocolError,
    capability_names,
    radio_name,
    status_name,
)

__all__ = [
    "ACCEPT_ALL",
    "ACCEPT_BLACKLIST",
    "ACCEPT_NONE",
    "ACCEPT_WHITELIST",
    "BACKEND_ESP32",
    "BACKEND_HOST",
    "BACKEND_LKL",
    "CAP_ACCESS_POINT",
    "CAP_SCAN",
    "CAP_STATION",
    "CLIENT_NAME",
    "CLIENT_VERSION",
    "PROTOCOL_VERSION",
    "RADIO_ATTACHING",
    "RADIO_FAILED",
    "RADIO_IDLE",
    "RADIO_LOST",
    "RADIO_READY",
    "PLATFORM_NX",
    "PLATFORM_OUNCE",
    "SECURITY_MODE_DEBUG",
    "SECURITY_MODE_PROD",
    "SECURITY_MODE_SYSTEM_DEBUG",
    "STATUS_BUSY",
    "STATUS_NONE",
    "STATUS_NO_KEYS",
    "STATUS_NO_RADIO",
    "STATUS_UNSUPPORTED",
    "STATUS_UNSUPPORTED_VERSION",
    "WIRELESS_LDN",
    "WIRELESS_NWM",
    "Connection",
    "DaemonError",
    "HelloResult",
    "LogDropped",
    "LogLine",
    "NetworkFound",
    "MacAddress",
    "NetworkInfo",
    "ParticipantInfo",
    "ProtocolError",
    "RadioStateChanged",
    "ScanDone",
    "capability_names",
    "connect",
    "radio_name",
    "status_name",
]
