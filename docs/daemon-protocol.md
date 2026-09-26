# ldnd protocol

Protocol version **7**.

Transport is a named pipe (default `\\.\pipe\ldnd`).

Notes:

- One network per Daemon; a second Connect/CreateNetwork is `BUSY`.
- `Ldn` is only accepted on a connection that picked LDN in Hello, `Nwm` only on NWM. The wrong one, an unknown op or an unknown sub-op gets `UNSUPPORTED`.

## Frame

| Offset | Size | Field         | Notes                                   |
|--------|------|---------------|-----------------------------------------|
| 0      | 1    | `op`          |                                         |
| 1      | 1    | `sub_op`      | LDN/NWM operation; 0 for other ops      |
| 2      | 4    | `request_id`  | 0 in Event/Data                         |
| 6      | 4    | `body_length` | Max 256 KiB                             |
| 10     | ..   | body          |                                         |

## Encoding

All integers little-endian. Bodies are fields in order, no padding.

| Type       | Encoding                         |
|------------|----------------------------------|
| `bool`     | u8, 0 or 1                       |
| `[u8; N]`  | N raw bytes                      |
| `mac`      | `[u8; 6]`                        |
| `bytes`    | u32 length + bytes               |
| `str`      | u32 length + UTF-8               |
| `list<T>`  | u32 count + elements             |
| `opt<T>`   | u8 flag, then T if flag is 1     |

## Replies

Every reply starts with:

```
status        u8
error_message opt<str>
```

A failed reply may not contain all expected fields if status != 0

## Opcodes

| Op     | Name         | Direction       | Request body | Reply body  |
|--------|--------------|-----------------|--------------|-------------|
| `0x01` | Hello        | client → daemon | Hello        | HelloReply  |
| `0x02` | SubscribeLog | client → daemon | empty        | StatusReply |
| `0x03` | Shutdown     | client → daemon | empty        | StatusReply |
| `0x10` | Ldn          | client → daemon | by `sub_op`  | by `sub_op` |
| `0x11` | Nwm          | client → daemon | by `sub_op`  | by `sub_op` |
| `0x80` | Reply        | daemon → client |              |             |
| `0x81` | Event        | daemon → client | see Events   |             |
| `0x82` | Data         | both            | see Data     |             |

### LDN sub-ops

| Sub-op | Name               | Request body                          | Reply body        |
|--------|--------------------|---------------------------------------|-------------------|
| `0x20` | Scan               | ScanRequest                           | ScanReply         |
| `0x21` | ScanCancel         | empty                                 | StatusReply       |
| `0x30` | Connect            | ConnectRequest                        | NetworkReply      |
| `0x31` | CreateNetwork      | CreateNetworkRequest                  | NetworkReply      |
| `0x32` | CloseNetwork       | `handle u32`                          | StatusReply       |
| `0x33` | GetNetworkInfo     | `handle u32`                          | NetworkReply      |
| `0x40` | SetApplicationData | `handle u32, application_data bytes`  | StatusReply       |
| `0x41` | SetAcceptPolicy    | `handle u32, accept_policy u8`        | StatusReply       |
| `0x42` | SetAcceptFilter    | `handle u32, accept_filter list<mac>` | StatusReply       |
| `0x43` | Kick               | `handle u32, participant_index u8`    | StatusReply       |
| `0x50` | OpenDatagram       | `handle u32, port u16` (0 = any)      | OpenDatagramReply |
| `0x51` | OpenRaw            | `handle u32`                          | ChannelReply      |
| `0x52` | CloseChannel       | `handle u32`                          | StatusReply       |
| `0x60` | SetProdKeys        | SetProdKeysRequest                    | StatusReply       |
| `0x61` | HasProdKeys        | empty                                 | HasProdKeysReply  |

### NWM sub-ops

Not Implemented Yet.

## Messages

### Hello

```
protocol_version  u32   must be 7
wireless_protocol u8    0 = LDN, 1 = NWM
client_name       str
client_version    str
```

### HelloReply

```
protocol_version  u32
daemon_version    str
ldn_caps          u8    bit 0 scan, 1 join, 2 host
nwm_caps          u8    same bits
radio_ready       bool
```

### StatusReply

### ScanRequest

```
channels          list<u8>   empty = default
dwell_ms          opt<u32>
protocols         list<u8>   empty = default
timeout_ms        opt<u32>
```

### ScanReply

```
networks          list<NetworkInfo>
```

### ConnectRequest

```
network           NetworkInfo   from a scan
password          bytes
name              bytes
app_version       u16
platform          u8            0 = Switch, 1 = Switch 2
enable_challenge  bool
device_id         u64
client_random     opt<[u8;16]>  absent = daemon picks
dev               bool
timeout_ms        opt<u32>
```

### CreateNetworkRequest

```
local_communication_id u64
scene_id          u16
max_participants  opt<u8>       max 8
application_data  bytes
accept_policy     opt<u8>       absent = accept all
accept_filter     list<mac>
security_mode     opt<u16>      absent = prod
ssid              opt<[u8;16]>  absent = daemon picks
name              bytes
app_version       u16
platform          u8
channel           opt<u8>       absent = daemon picks
server_random     opt<[u8;16]>  absent = daemon picks
password          bytes
version           opt<u8>       2, 3 or 4
enable_challenge  bool
device_id         u64
protocol          opt<u8>       1 or 3
dev               bool
```

### SetProdKeysRequest

```
prod_keys         str           text of a prod.keys file, `name = hex` per line
```

### HasProdKeysReply

```
loaded            bool          prod.keys loaded
```

### NetworkReply

```
handle            u32            network; 0 on failure
auth_status       opt<u8>        LDN AUTH_* code on AUTH_FAILED
network           opt<NetworkInfo>
participant_index opt<u8>        0 when hosting
```

### OpenDatagramReply

```
handle            u32            new channel; 0 on failure
port              u16            bound port
```

### ChannelReply

```
handle            u32            new channel; 0 on failure
```

### NetworkInfo

```
protocol          u8
address           mac
band              u8
channel           u8            the host's own, as it advertises it; Connect joins on it
local_communication_id u64
scene_id          u16
ssid              [u8;16]
version           u8
server_random     [u8;16]
security_mode     u16
app_version       u16
accept_policy     u8
max_participants  u8
num_participants  u8
participants      list<ParticipantInfo>
application_data  bytes
challenge         u64
nonce             [u8;4]
```

### ParticipantInfo

```
ip_address        [u8;4]
mac_address       mac
connected         bool
name              bytes
app_version       u16
platform          u8
```

## Events

Body is `kind u8` then the fields. `handle` is the network the event concerns, or the channel for ChannelError.

| Kind | Name           | Fields                                         |
|------|----------------|------------------------------------------------|
| 1    | NetworkFound   | `NetworkInfo` (during Scan)                    |
| 2    | ScanDone       | `count u32`                                    |
| 3    | Join           | `handle u32, index u8, participant ParticipantInfo` |
| 4    | Leave          | `handle u32, index u8, participant ParticipantInfo` |
| 5    | Disconnect     | `handle u32, reason u8`                        |
| 6    | AppDataChanged | `handle u32, old bytes, new bytes`             |
| 7    | PolicyChanged  | `handle u32, old u8, new u8`                   |
| 8    | ChannelError   | `handle u32, status u8, message str`           |
| 9    | Log            | `line str` (after SubscribeLog)                |
| 10   | RadioState     | `state u8, message opt<str>`                   |
| 11   | LogDropped     | `lines u32`                                    |

Data sends are not acknowledged; failures come back as ChannelError.

## Data

Body is `handle u32` (the channel), then the payload. The payload has no length prefix; `body_length` covers it.

- **Datagram:** `peer [u8;4], port u16, payload`. Peer is the destination when sending, the source when received.
- **Raw:** a whole Ethernet frame, both ways.

## Status

| Value | Name                | Meaning                                                      |
|-------|---------------------|--------------------------------------------------------------|
| 0     | NONE                | Success                                                      |
| 1     | BAD_REQUEST         | Malformed body, Hello not first or repeated, request op sent to daemon |
| 2     | UNSUPPORTED_VERSION | Hello `protocol_version` mismatch                            |
| 3     | INVALID_HANDLE      | `handle` names no open network or channel                    |
| 4     | INVALID_PARAM       | A field value is out of range (channel, participants, ...)   |
| 5     | BUSY                | Daemon held by another client, or scan/network already open  |
| 6     | NO_RADIO            | Adapter not attached                                         |
| 7     | NO_KEYS             | No `prod.keys` loaded, or key derivation failed (missing or wrong keys) |
| 8     | NOT_FOUND           | Not currently returned                                       |
| 9     | TIMEOUT             | Join failed: network not found or association dropped        |
| 10    | AUTH_FAILED         | Host refused the join; see `auth_status`                     |
| 11    | IO                  | Radio or socket error                                        |
| 12    | UNSUPPORTED         | Unknown op/sub-op, wrong wireless protocol for the op        |
| 13    | INTERNAL            | Daemon bug                                                   |

## Values

**Radio state:** 0 IDLE, 1 ATTACHING, 2 READY, 3 LOST, 4 FAILED

**Accept policy:** 0 ALL, 1 NONE, 2 BLACKLIST, 3 WHITELIST

**Security mode:** 1 PROD, 2 DEBUG, 3 SYSTEM_DEBUG

**Disconnect reason:** 3 NETWORK_DESTROYED, 4 NETWORK_DESTROYED_FORCEFULLY, 5 STATION_REJECTED_BY_HOST, 6 CONNECTION_LOST
