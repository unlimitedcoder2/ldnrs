"""
A drop-in replacement for the ``ldn`` package, backed by ldnd.

The point of this file is its *name*. :mod:`ldnd.compat` already provides the original library's
API, but an existing program says ``import ldn`` and there is no line to change if you do not own
that program -- ``frlg-ldn-trade`` is the case in point. Putting this directory ahead of the real
library on ``PYTHONPATH`` swaps the backend without touching the script::

    $env:PYTHONPATH = 'C:\\Users\\archbtw\\frlg\\ldnrs\\clients\\python'
    $env:LDN_DAEMON = '\\\\.\\pipe\\ldn-frlg3'
    python -u frlgtrade.py --bridge ...
"""

from ldnd.compat import (  # noqa: F401
    ACCEPT_ALL,
    ACCEPT_BLACKLIST,
    ACCEPT_NONE,
    ACCEPT_WHITELIST,
    KEYS_ARE_THE_DAEMONS,
    MACAddress,
    MacAddress,
    PLATFORM_NX,
    PLATFORM_OUNCE,
    RADIO_TIMEOUT_MS,
    SECURITY_MODE_DEBUG,
    SECURITY_MODE_PROD,
    SECURITY_MODE_SYSTEM_DEBUG,
    APNetwork,
    AcceptPolicyChanged,
    ApplicationDataChanged,
    ConnectNetworkParam,
    CreateNetworkParam,
    DaemonError,
    DisconnectEvent,
    JoinEvent,
    LeaveEvent,
    NetworkInfo,
    PacketChannel,
    ParticipantInfo,
    STANetwork,
    connect,
    create_network,
    load_keys,
    scan,
)

BACKEND = "ldnd"

__all__ = [
    "ACCEPT_ALL",
    "ACCEPT_BLACKLIST",
    "ACCEPT_NONE",
    "ACCEPT_WHITELIST",
    "APNetwork",
    "AcceptPolicyChanged",
    "ApplicationDataChanged",
    "BACKEND",
    "ConnectNetworkParam",
    "CreateNetworkParam",
    "DaemonError",
    "DisconnectEvent",
    "JoinEvent",
    "KEYS_ARE_THE_DAEMONS",
    "LeaveEvent",
    "MACAddress",
    "MacAddress",
    "NetworkInfo",
    "PLATFORM_NX",
    "PLATFORM_OUNCE",
    "PacketChannel",
    "ParticipantInfo",
    "RADIO_TIMEOUT_MS",
    "SECURITY_MODE_DEBUG",
    "SECURITY_MODE_PROD",
    "SECURITY_MODE_SYSTEM_DEBUG",
    "STANetwork",
    "connect",
    "create_network",
    "load_keys",
    "scan",
]
