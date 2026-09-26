use crate::advertisement::{NetworkInfo, PLATFORM_NX, ParticipantInfo};
use crate::wlan::MacAddress;

use super::bytes::{DecodeError, Reader};
use super::frame::{FRAME_HEADER_LEN, Header};
use super::tables::{EventKind, Op, RadioState, Status, WirelessProtocol};
use super::wire::{WireRead, WireWrite};
use super::writer::{EncodeError, Writer};

impl WireWrite for Status {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u8(self.value());
		Ok(())
	}
}

impl WireWrite for ParticipantInfo {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.ip_address.put(writer)?;
		self.mac_address.put(writer)?;
		self.connected.put(writer)?;
		self.name.put(writer)?;
		self.app_version.put(writer)?;
		self.platform.put(writer)?;
		Ok(())
	}
}

impl WireRead for ParticipantInfo {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			ip_address: WireRead::get(reader)?,
			mac_address: WireRead::get(reader)?,
			connected: WireRead::get(reader)?,
			name: WireRead::get(reader)?,
			app_version: WireRead::get(reader)?,
			platform: WireRead::get(reader)?,
		})
	}
}

impl WireWrite for NetworkInfo {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.protocol.put(writer)?;
		self.address.put(writer)?;
		self.band.put(writer)?;
		self.channel.put(writer)?;
		self.local_communication_id.put(writer)?;
		self.scene_id.put(writer)?;
		self.ssid.put(writer)?;
		self.version.put(writer)?;
		self.server_random.put(writer)?;
		self.security_mode.put(writer)?;
		self.app_version.put(writer)?;
		self.accept_policy.put(writer)?;
		self.max_participants.put(writer)?;
		self.num_participants.put(writer)?;
		self.participants.put(writer)?;
		self.application_data.put(writer)?;
		self.challenge.put(writer)?;
		self.nonce.put(writer)?;
		Ok(())
	}
}

impl WireRead for NetworkInfo {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			protocol: WireRead::get(reader)?,
			address: WireRead::get(reader)?,
			band: WireRead::get(reader)?,
			channel: WireRead::get(reader)?,
			local_communication_id: WireRead::get(reader)?,
			scene_id: WireRead::get(reader)?,
			ssid: WireRead::get(reader)?,
			version: WireRead::get(reader)?,
			server_random: WireRead::get(reader)?,
			security_mode: WireRead::get(reader)?,
			app_version: WireRead::get(reader)?,
			accept_policy: WireRead::get(reader)?,
			max_participants: WireRead::get(reader)?,
			num_participants: WireRead::get(reader)?,
			participants: WireRead::get(reader)?,
			application_data: WireRead::get(reader)?,
			challenge: WireRead::get(reader)?,
			nonce: WireRead::get(reader)?,
		})
	}
}

#[must_use]
pub fn frame(op: Op, request_id: u32, body: &[u8]) -> Vec<u8> {
	let body_length = u32::try_from(body.len()).unwrap_or(u32::MAX);
	let header = Header::new(op, request_id, body_length);

	let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
	out.extend_from_slice(&header.encode());
	out.extend_from_slice(body);
	out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
	/// The protocol version the client speaks; it must be [`super::tables::PROTOCOL_VERSION`].
	pub protocol_version: u32,
	/// Kept raw so an unknown value can be refused with a reply rather than failing to decode.
	pub wireless_protocol: u8,
	pub client_name: String,
	pub client_version: String,
}

impl WireRead for Hello {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			protocol_version: WireRead::get(reader)?,
			wireless_protocol: WireRead::get(reader)?,
			client_name: WireRead::get(reader)?,
			client_version: WireRead::get(reader)?,
		})
	}
}

impl Hello {
	#[must_use]
	pub const fn wireless_protocol(&self) -> Option<WirelessProtocol> {
		WirelessProtocol::from_value(self.wireless_protocol)
	}
}

bitflags::bitflags! {
	#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
	pub struct LdnCapability : u8 {
		const Scan = 1 << 0;
		const Join = 1 << 1;
		const Host = 1 << 2;
	}
}

bitflags::bitflags! {
	#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
	pub struct NwmCapability : u8 {
		const Scan = 1 << 0;
		const Join = 1 << 1;
		const Host = 1 << 2;
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Capabilities {
	pub ldn: LdnCapability,
	pub nwm: NwmCapability,
}

impl WireWrite for Capabilities {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u8(self.ldn.0.0);
		writer.u8(self.nwm.0.0);

		Ok(())
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloReply {
	pub status: Status,
	pub error_message: Option<String>,
	pub protocol_version: u32,
	pub daemon_version: String,
	pub capabilities: Capabilities,
	pub radio_ready: bool,
}

impl WireWrite for HelloReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		self.protocol_version.put(writer)?;
		self.daemon_version.put(writer)?;
		self.capabilities.put(writer)?;
		self.radio_ready.put(writer)?;
		Ok(())
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
	pub status: u8,
	pub error_message: Option<String>,
}

impl WireWrite for StatusReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		Ok(())
	}
}

impl StatusReply {
	#[must_use]
	pub const fn ok() -> Self {
		Self {
			status: Status::None.value(),
			error_message: None,
		}
	}

	#[must_use]
	pub fn error(status: Status, message: impl Into<String>) -> Self {
		Self {
			status: status.value(),
			error_message: Some(message.into()),
		}
	}

	#[must_use]
	pub const fn status(&self) -> Option<Status> {
		Status::from_value(self.status)
	}

	#[must_use]
	pub const fn is_ok(&self) -> bool {
		self.status == Status::None.value()
	}
}

/// The body is the [`EventKind`] byte, then the variant's fields in order. An event about a
/// network or channel carries its `handle` first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
	Log {
		line: String,
	},
	LogDropped {
		lines: u32,
	},
	Radio {
		state: u8,
		message: Option<String>,
	},
	/// Emitted as the scan runs, so a UI can populate a list live; the same networks are also
	/// returned together in the scan's reply, so a simple client can ignore these entirely.
	NetworkFound(Box<NetworkInfo>),
	ScanDone {
		count: u32,
	},
	Join {
		handle: u32,
		index: u8,
		participant: Box<ParticipantInfo>,
	},
	Leave {
		handle: u32,
		index: u8,
		participant: Box<ParticipantInfo>,
	},
	Disconnect {
		handle: u32,
		reason: u8,
	},
	AppDataChanged {
		handle: u32,
		old: Vec<u8>,
		new: Vec<u8>,
	},
	/// A data channel failed. Sending is not acknowledged, so this is how a failed send surfaces.
	/// The handle is 0 when the failed `DATA` frame did not name one.
	ChannelError {
		handle: u32,
		status: u8,
		message: String,
	},
	PolicyChanged {
		handle: u32,
		old: u8,
		new: u8,
	},
}

impl Event {
	const fn kind(&self) -> EventKind {
		match self {
			Self::Log { .. } => EventKind::Log,
			Self::LogDropped { .. } => EventKind::LogDropped,
			Self::Radio { .. } => EventKind::RadioState,
			Self::NetworkFound(_) => EventKind::NetworkFound,
			Self::ScanDone { .. } => EventKind::ScanDone,
			Self::Join { .. } => EventKind::Join,
			Self::Leave { .. } => EventKind::Leave,
			Self::Disconnect { .. } => EventKind::Disconnect,
			Self::AppDataChanged { .. } => EventKind::AppDataChanged,
			Self::ChannelError { .. } => EventKind::ChannelError,
			Self::PolicyChanged { .. } => EventKind::PolicyChanged,
		}
	}

	/// # Errors
	/// [`EncodeError::FieldTooLong`] if a field is longer than a `u32` can describe.
	pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
		let mut writer = Writer::new();
		let w = &mut writer;

		w.u8(self.kind().value());

		match self {
			Self::Log { line } => line.put(w)?,
			Self::LogDropped { lines } => lines.put(w)?,
			Self::Radio { state, message } => {
				state.put(w)?;
				message.put(w)?;
			}
			Self::NetworkFound(network) => network.put(w)?,
			Self::ScanDone { count } => count.put(w)?,
			Self::Join {
				handle,
				index,
				participant,
			}
			| Self::Leave {
				handle,
				index,
				participant,
			} => {
				handle.put(w)?;
				index.put(w)?;
				participant.put(w)?;
			}
			Self::Disconnect { handle, reason } => {
				handle.put(w)?;
				reason.put(w)?;
			}
			Self::AppDataChanged { handle, old, new } => {
				handle.put(w)?;
				old.put(w)?;
				new.put(w)?;
			}
			Self::ChannelError {
				handle,
				status,
				message,
			} => {
				handle.put(w)?;
				status.put(w)?;
				message.put(w)?;
			}
			Self::PolicyChanged { handle, old, new } => {
				handle.put(w)?;
				old.put(w)?;
				new.put(w)?;
			}
		}

		Ok(writer.into_vec())
	}

	#[must_use]
	pub const fn radio(state: RadioState, message: Option<String>) -> Self {
		Self::Radio {
			state: state.value(),
			message,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
	pub network: Box<NetworkInfo>,
	pub password: Vec<u8>,
	pub name: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
	pub enable_challenge: bool,
	pub device_id: u64,
	/// Seeds the authentication key. Absent means the daemon picks one, which is the normal case.
	pub client_random: Option<[u8; 16]>,
	pub dev: bool,
	/// How long the client will wait for the join, retries included.
	pub timeout_ms: Option<u32>,
}

impl WireRead for ConnectRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			network: WireRead::get(reader)?,
			password: WireRead::get(reader)?,
			name: WireRead::get(reader)?,
			app_version: WireRead::get(reader)?,
			platform: WireRead::get(reader)?,
			enable_challenge: WireRead::get(reader)?,
			device_id: WireRead::get(reader)?,
			client_random: WireRead::get(reader)?,
			dev: WireRead::get(reader)?,
			timeout_ms: WireRead::get(reader)?,
		})
	}
}

impl ConnectRequest {
	#[must_use]
	pub fn new(network: NetworkInfo) -> Self {
		Self {
			network: Box::new(network),
			password: Vec::new(),
			name: Vec::new(),
			app_version: 0,
			platform: PLATFORM_NX,
			enable_challenge: true,
			device_id: 0,
			client_random: None,
			dev: false,
			timeout_ms: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkReply {
	pub status: Status,
	pub message: Option<String>,
	/// The network's handle. 0 when the status is non-zero.
	pub handle: u32,
	/// The LDN `AUTH_*` sub-code, when the host refused the join.
	pub auth_status: Option<u8>,
	pub network: Option<Box<NetworkInfo>>,
	pub participant_index: Option<u8>,
}

impl WireWrite for NetworkReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.message.put(writer)?;
		self.handle.put(writer)?;
		self.auth_status.put(writer)?;
		self.network.put(writer)?;
		self.participant_index.put(writer)?;
		Ok(())
	}
}

impl NetworkReply {
	#[must_use]
	pub fn joined(handle: u32, network: NetworkInfo, participant_index: u8) -> Self {
		Self {
			status: Status::None,
			message: None,
			handle,
			auth_status: None,
			network: Some(Box::new(network)),
			participant_index: Some(participant_index),
		}
	}

	#[must_use]
	pub fn error(status: Status, message: impl Into<String>) -> Self {
		Self {
			status,
			message: Some(message.into()),
			handle: 0,
			auth_status: None,
			network: None,
			participant_index: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanRequest {
	/// Channels to visit. Empty means the default.
	pub channels: Vec<u8>,
	pub dwell_ms: Option<u32>,
	/// LDN protocol versions to try. Empty means the default.
	pub protocols: Vec<u8>,
	pub timeout_ms: Option<u32>,
}

impl WireRead for ScanRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			channels: WireRead::get(reader)?,
			dwell_ms: WireRead::get(reader)?,
			protocols: WireRead::get(reader)?,
			timeout_ms: WireRead::get(reader)?,
		})
	}
}

pub const DATA_HANDLE_LEN: usize = 4;

/// Encodes a channel handle followed by its payload.
///
/// `DATA` is the one op whose body is not a message struct: the channel's handle as a
/// little-endian `u32`, then the channel's payload with no length in front of it, because the
/// frame header already says how long the body is.
#[must_use]
pub fn encode_data(handle: u32, payload: &[u8]) -> Vec<u8> {
	let mut body = Vec::with_capacity(DATA_HANDLE_LEN + payload.len());

	body.extend_from_slice(&handle.to_le_bytes());
	body.extend_from_slice(payload);

	body
}

/// Splits a `DATA` body into the channel handle and the payload.
///
/// # Errors
/// [`DecodeError::UnexpectedEof`] if the body is too short to hold a handle.
pub fn decode_data(body: &[u8]) -> Result<(u32, &[u8]), DecodeError> {
	let handle = body
		.get(..DATA_HANDLE_LEN)
		.and_then(|bytes| <[u8; DATA_HANDLE_LEN]>::try_from(bytes).ok())
		.map(u32::from_le_bytes)
		.ok_or(DecodeError::UnexpectedEof {
			wanted: DATA_HANDLE_LEN,
			got: body.len(),
		})?;

	Ok((handle, body.get(DATA_HANDLE_LEN..).unwrap_or(&[])))
}

pub const DATAGRAM_PREFIX_LEN: usize = 6;

/// A datagram channel's `DATA` payload, after the handle: four address bytes in dotted-quad order,
/// then the port as a little-endian `u16`, then the datagram.
///
/// The same shape travels both ways. Daemon to client it is who sent the datagram; client to
/// daemon it is where to send it. That symmetry is why one op serves both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramData {
	pub peer: [u8; 4],
	pub port: u16,
	pub payload: Vec<u8>,
}

impl DatagramData {
	#[must_use]
	pub fn new(peer: [u8; 4], port: u16, payload: &[u8]) -> Self {
		Self {
			peer,
			port,
			payload: payload.to_vec(),
		}
	}

	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut body = Vec::with_capacity(self.payload.len() + DATAGRAM_PREFIX_LEN);

		body.extend_from_slice(&self.peer);
		body.extend_from_slice(&self.port.to_le_bytes());
		body.extend_from_slice(&self.payload);

		body
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if the body is shorter than the prefix. A body of exactly the
	/// prefix length is valid and decodes to an empty payload; a zero-length UDP datagram is a
	/// real thing, and some protocols use it as a keepalive.
	pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
		let short = || DecodeError::UnexpectedEof {
			wanted: DATAGRAM_PREFIX_LEN,
			got: body.len(),
		};

		let peer = body
			.get(..4)
			.and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
			.ok_or_else(short)?;

		let port = body
			.get(4..DATAGRAM_PREFIX_LEN)
			.and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
			.map(u16::from_le_bytes)
			.ok_or_else(short)?;

		let payload = body.get(DATAGRAM_PREFIX_LEN..).unwrap_or(&[]).to_vec();

		Ok(Self {
			peer,
			port,
			payload,
		})
	}
}

/// The body of every request whose only argument is the network or channel it acts on:
/// `CloseNetwork`, `GetNetworkInfo`, `OpenRaw` and `CloseChannel`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HandleRequest {
	pub handle: u32,
}

impl WireRead for HandleRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
		})
	}
}

/// The reply to `OpenRaw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelReply {
	pub status: u8,
	pub error_message: Option<String>,
	/// The new channel's handle. 0 when the status is non-zero.
	pub handle: u32,
}

impl WireWrite for ChannelReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		self.handle.put(writer)?;
		Ok(())
	}
}

impl ChannelReply {
	#[must_use]
	pub const fn ok(handle: u32) -> Self {
		Self {
			status: Status::None.value(),
			error_message: None,
			handle,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HasProdKeysReply {
	pub status: u8,
	pub error_message: Option<String>,
	/// Whether `prod.keys` are loaded, from `--keys` or a `SetProdKeys`.
	pub loaded: bool,
}

impl WireWrite for HasProdKeysReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		self.loaded.put(writer)?;
		Ok(())
	}
}

impl HasProdKeysReply {
	#[must_use]
	pub const fn ok(loaded: bool) -> Self {
		Self {
			status: Status::None.value(),
			error_message: None,
			loaded,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpenDatagramRequest {
	/// The network to open the channel on.
	pub handle: u32,
	/// The port to bind. Zero lets the daemon's kernel choose one.
	pub port: u16,
}

impl WireRead for OpenDatagramRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
			port: WireRead::get(reader)?,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenDatagramReply {
	pub status: u8,
	pub error_message: Option<String>,
	/// The new channel's handle. 0 when the status is non-zero.
	pub handle: u32,
	/// The bound port. Meaningless when the status is non-zero.
	pub port: u16,
}

impl WireWrite for OpenDatagramReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		self.handle.put(writer)?;
		self.port.put(writer)?;
		Ok(())
	}
}

impl OpenDatagramReply {
	#[must_use]
	pub const fn ok(handle: u32, port: u16) -> Self {
		Self {
			status: Status::None.value(),
			error_message: None,
			handle,
			port,
		}
	}

	#[must_use]
	pub fn error(status: Status, message: impl Into<String>) -> Self {
		Self {
			status: status.value(),
			error_message: Some(message.into()),
			handle: 0,
			port: 0,
		}
	}

	#[must_use]
	pub const fn is_ok(&self) -> bool {
		self.status == Status::None.value()
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReply {
	pub status: u8,
	pub error_message: Option<String>,
	pub networks: Vec<NetworkInfo>,
}

impl WireWrite for ScanReply {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.status.put(writer)?;
		self.error_message.put(writer)?;
		self.networks.put(writer)?;
		Ok(())
	}
}

impl ScanReply {
	#[must_use]
	pub const fn ok(networks: Vec<NetworkInfo>) -> Self {
		Self {
			status: Status::None.value(),
			error_message: None,
			networks,
		}
	}

	#[must_use]
	pub fn error(status: Status, message: impl Into<String>) -> Self {
		Self {
			status: status.value(),
			error_message: Some(message.into()),
			networks: Vec::new(),
		}
	}

	#[must_use]
	pub const fn is_ok(&self) -> bool {
		self.status == Status::None.value()
	}

	#[must_use]
	pub const fn status(&self) -> Option<Status> {
		Status::from_value(self.status)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateNetworkRequest {
	pub local_communication_id: u64,
	pub scene_id: u16,
	/// How many nodes to allow, at most eight. Absent leaves the daemon's maximum.
	pub max_participants: Option<u8>,
	pub application_data: Vec<u8>,
	/// An `ACCEPT_*` value. Absent accepts everyone.
	pub accept_policy: Option<u8>,
	pub accept_filter: Vec<MacAddress>,
	/// A `SECURITY_MODE_*` value. Absent is production security.
	pub security_mode: Option<u16>,
	/// The network's hidden id. Absent means the daemon picks one, which is the normal case.
	pub ssid: Option<[u8; 16]>,
	pub name: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
	/// The channel to host on. Absent means the daemon picks one of the LDN host channels.
	pub channel: Option<u8>,
	/// Seeds the data key. Absent means the daemon picks one, which is the normal case.
	pub server_random: Option<[u8; 16]>,
	pub password: Vec<u8>,
	/// The LDN version: 2, 3 or 4. Absent is the daemon's default.
	pub version: Option<u8>,
	pub enable_challenge: bool,
	pub device_id: u64,
	/// The LDN protocol: 1 or 3. Absent is the daemon's default.
	pub protocol: Option<u8>,
	pub dev: bool,
}

impl WireRead for CreateNetworkRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			local_communication_id: WireRead::get(reader)?,
			scene_id: WireRead::get(reader)?,
			max_participants: WireRead::get(reader)?,
			application_data: WireRead::get(reader)?,
			accept_policy: WireRead::get(reader)?,
			accept_filter: WireRead::get(reader)?,
			security_mode: WireRead::get(reader)?,
			ssid: WireRead::get(reader)?,
			name: WireRead::get(reader)?,
			app_version: WireRead::get(reader)?,
			platform: WireRead::get(reader)?,
			channel: WireRead::get(reader)?,
			server_random: WireRead::get(reader)?,
			password: WireRead::get(reader)?,
			version: WireRead::get(reader)?,
			enable_challenge: WireRead::get(reader)?,
			device_id: WireRead::get(reader)?,
			protocol: WireRead::get(reader)?,
			dev: WireRead::get(reader)?,
		})
	}
}

impl Default for CreateNetworkRequest {
	fn default() -> Self {
		Self {
			local_communication_id: 0,
			scene_id: 0,
			max_participants: None,
			application_data: Vec::new(),
			accept_policy: None,
			accept_filter: Vec::new(),
			security_mode: None,
			ssid: None,
			name: Vec::new(),
			app_version: 0,
			platform: PLATFORM_NX,
			channel: None,
			server_random: None,
			password: Vec::new(),
			version: None,
			enable_challenge: true,
			device_id: 0,
			protocol: None,
			dev: false,
		}
	}
}

impl CreateNetworkRequest {
	#[must_use]
	pub fn new(local_communication_id: u64) -> Self {
		Self {
			local_communication_id,
			..Self::default()
		}
	}
}

/// Replaces the game-specific payload a hosted network advertises. Empty clears it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetApplicationDataRequest {
	pub handle: u32,
	pub application_data: Vec<u8>,
}

impl WireRead for SetApplicationDataRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
			application_data: WireRead::get(reader)?,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetAcceptPolicyRequest {
	pub handle: u32,
	pub accept_policy: u8,
}

impl WireRead for SetAcceptPolicyRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
			accept_policy: WireRead::get(reader)?,
		})
	}
}

/// An empty filter is meaningful (it is what an allow-list with nobody on it looks like), so it
/// clears the filter rather than being rejected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetAcceptFilterRequest {
	pub handle: u32,
	pub accept_filter: Vec<MacAddress>,
}

impl WireRead for SetAcceptFilterRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
			accept_filter: WireRead::get(reader)?,
		})
	}
}

/// The text of a `prod.keys` file, in the same `name = hex` format [`crate::crypto::Keys::parse`]
/// accepts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetProdKeysRequest {
	pub prod_keys: String,
}

impl WireRead for SetProdKeysRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			prod_keys: WireRead::get(reader)?,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KickRequest {
	pub handle: u32,
	pub participant_index: u8,
}

impl WireRead for KickRequest {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self {
			handle: WireRead::get(reader)?,
			participant_index: WireRead::get(reader)?,
		})
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::{Capabilities, HelloReply, LdnCapability, NwmCapability, decode_data, encode_data};
	use crate::protocol::tables::Status;
	use crate::protocol::wire::WireWrite;

	#[test]
	fn data_body_leads_with_the_handle() {
		let body = encode_data(0x0102_0304, b"hi");
		assert_eq!(body, [0x04, 0x03, 0x02, 0x01, b'h', b'i']);

		assert_eq!(decode_data(&body).unwrap(), (0x0102_0304, &b"hi"[..]));
		assert_eq!(
			decode_data(body.get(..4).unwrap()).unwrap(),
			(0x0102_0304, &[][..])
		);
		assert!(decode_data(body.get(..3).unwrap()).is_err());
	}

	#[test]
	fn hello_reply_layout() {
		let reply = HelloReply {
			status: Status::None,
			error_message: None,
			protocol_version: 5,
			daemon_version: "0.1.0".to_owned(),
			capabilities: Capabilities {
				ldn: LdnCapability::Scan | LdnCapability::Join | LdnCapability::Host,
				nwm: NwmCapability::empty(),
			},
			radio_ready: true,
		};

		let expected: &[u8] = &[
			0x00, // status
			0x00, // error_message: None
			0x05, 0x00, 0x00, 0x00, // protocol_version
			0x05, 0x00, 0x00, 0x00, b'0', b'.', b'1', b'.', b'0', // daemon_version
			0x07, // LDN capabilities
			0x00, // NWM capabilities
			0x01, // radio_ready
		];

		assert_eq!(reply.encode().unwrap(), expected);
	}
}
