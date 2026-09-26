use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::aead::{AeadInPlace, KeyInit as GcmKeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use sha2::{Digest, Sha256};

use crate::authentication::LDN_OUI;
use crate::crypto::KeyDerivation;
use crate::protocol::bytes::{DecodeError, Reader};
use crate::protocol::writer::Writer;
use crate::wlan::{MacAddress, channel_band, is_valid_channel};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

pub const ACCEPT_ALL: u8 = 0;
pub const ACCEPT_NONE: u8 = 1;
pub const ACCEPT_BLACKLIST: u8 = 2;
pub const ACCEPT_WHITELIST: u8 = 3;

pub const FORMAT_PLAIN: u8 = 1;
pub const FORMAT_AES_CTR: u8 = 2;
pub const FORMAT_AES_GCM: u8 = 3;

pub const SECURITY_MODE_PROD: u16 = 1;
/// Advertisement frames encrypted, data frames not.
pub const SECURITY_MODE_DEBUG: u16 = 2;
pub const SECURITY_MODE_SYSTEM_DEBUG: u16 = 3;

pub const PLATFORM_NX: u8 = 0;
pub const PLATFORM_OUNCE: u8 = 1;

pub const ADVERTISEMENT_MAGIC: [u8; 8] = [0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01];

/// Length of the header covered by the GCM AAD.
const HEADER_LEN: usize = 0x28;

const V1_PAYLOAD_LEN: u16 = 0x500;

pub const MAX_PARTICIPANTS: usize = 8;

pub const MAX_APPLICATION_DATA: usize = 0x180;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkId {
	pub local_communication_id: u64,
	pub scene_id: u16,
	/// 16 random bytes; the SSID is hidden.
	pub ssid: [u8; 16],
}

impl NetworkId {
	#[must_use]
	pub fn encode(&self) -> [u8; 32] {
		let mut writer = Writer::with_capacity(32);
		writer.u64_be(self.local_communication_id);
		writer.pad(2);
		writer.u16_be(self.scene_id);
		writer.pad(4);
		writer.slice(&self.ssid);

		let bytes = writer.into_vec();
		<[u8; 32]>::try_from(bytes.as_slice()).unwrap_or([0; 32])
	}

	#[must_use]
	pub fn encode_le(&self) -> [u8; 32] {
		let mut writer = Writer::with_capacity(32);
		writer.u64_le(self.local_communication_id);
		writer.pad(2);
		writer.u16_le(self.scene_id);
		writer.pad(4);
		writer.slice(&self.ssid);

		let bytes = writer.into_vec();
		<[u8; 32]>::try_from(bytes.as_slice()).unwrap_or([0; 32])
	}

	/// # Errors
	/// [`DecodeError`] if fewer than 32 bytes remain.
	pub fn decode_le(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let local_communication_id = reader.u64_le()?;
		reader.skip(2)?;
		let scene_id = reader.u16_le()?;
		reader.skip(4)?;

		let ssid = reader.array()?;

		Ok(Self {
			local_communication_id,
			scene_id,
			ssid,
		})
	}

	/// # Errors
	/// [`DecodeError`] if fewer than 32 bytes remain.
	pub fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let local_communication_id = reader.u64_be()?;
		reader.skip(2)?;
		let scene_id = reader.u16_be()?;
		reader.skip(4)?;

		let ssid = reader.array()?;

		Ok(Self {
			local_communication_id,
			scene_id,
			ssid,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantInfo {
	/// `169.254.<network>.<index + 1>`.
	pub ip_address: [u8; 4],
	/// The node's MAC, which is also its Pia connection GUID.
	pub mac_address: MacAddress,
	pub connected: bool,
	/// Nickname, trailing NULs stripped.
	pub name: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
}

impl Default for ParticipantInfo {
	fn default() -> Self {
		Self {
			ip_address: [0; 4],
			mac_address: MacAddress::ZERO,
			connected: false,
			name: Vec::new(),
			app_version: 0,
			platform: PLATFORM_NX,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisementInfo {
	/// 16 bytes seeding the data key.
	pub server_random: [u8; 16],
	pub security_mode: u16,
	pub station_accept_policy: u8,
	pub app_version: u16,
	pub band: u8,
	pub channel: u16,
	pub max_participants: u8,
	pub num_participants: u8,
	/// Always [`MAX_PARTICIPANTS`] entries.
	pub participants: Vec<ParticipantInfo>,
	pub application_data: Vec<u8>,
	pub challenge: u64,
}

impl Default for AdvertisementInfo {
	fn default() -> Self {
		Self {
			server_random: [0; 16],
			security_mode: SECURITY_MODE_PROD,
			station_accept_policy: ACCEPT_ALL,
			app_version: 0,
			band: 0,
			channel: 0,
			max_participants: 0,
			num_participants: 0,
			participants: vec![ParticipantInfo::default(); MAX_PARTICIPANTS],
			application_data: Vec::new(),
			challenge: 0,
		}
	}
}

fn encode_v1(info: &AdvertisementInfo) -> Vec<u8> {
	let mut writer = Writer::with_capacity(usize::from(V1_PAYLOAD_LEN));

	writer.slice(&info.server_random);
	writer.u16_be(info.security_mode);
	writer.u8(info.station_accept_policy);
	writer.pad(1);
	writer.u16_be(band_channel(info.band, info.channel));
	writer.u8(info.max_participants);
	writer.u8(info.num_participants);

	for index in 0..MAX_PARTICIPANTS {
		let default = ParticipantInfo::default();
		let participant = info.participants.get(index).unwrap_or(&default);

		writer.slice(&participant.ip_address);
		writer.slice(&participant.mac_address.octets());
		writer.u8(u8::from(participant.connected));
		writer.u8(participant.platform);
		write_name(&mut writer, &participant.name);
		writer.u16_be(participant.app_version);
		writer.pad(10);
	}

	writer.pad(2);
	let data_len = u16::try_from(info.application_data.len()).unwrap_or(0);
	writer.u16_be(data_len);
	writer.slice(&info.application_data);
	writer.pad(384usize.saturating_sub(info.application_data.len()));
	writer.pad(412);
	writer.u64_be(info.challenge);

	writer.into_vec()
}

fn decode_v1(data: &[u8]) -> Result<AdvertisementInfo, DecodeError> {
	let mut reader = Reader::new(data);
	let mut info = AdvertisementInfo {
		server_random: reader.array()?,
		..AdvertisementInfo::default()
	};

	info.security_mode = reader.u16_be()?;
	info.station_accept_policy = reader.u8()?;
	reader.skip(1)?;

	let value = reader.u16_be()?;
	info.band = u8::try_from(value >> 10).unwrap_or(0);
	info.channel = value & 0x3FF;

	info.max_participants = reader.u8()?;
	info.num_participants = reader.u8()?;

	info.participants = Vec::with_capacity(MAX_PARTICIPANTS);
	for _ in 0..MAX_PARTICIPANTS {
		let ip_address = reader.array()?;

		let mac_address = MacAddress::read(&mut reader)?;
		let connected = reader.u8()? != 0;
		let platform = reader.u8()?;
		let name = read_name(&mut reader)?;
		let app_version = reader.u16_be()?;
		reader.skip(10)?;

		info.participants.push(ParticipantInfo {
			ip_address,
			mac_address,
			connected,
			name,
			app_version,
			platform,
		});
	}

	// The host is slot 0, and its application version stands for the network's.
	info.app_version = info.participants.first().map_or(0, |p| p.app_version);

	reader.skip(2)?;
	let beacon_size = usize::from(reader.u16_be()?);
	let beacon = reader.take(384)?;
	info.application_data = beacon
		.get(..beacon_size.min(beacon.len()))
		.unwrap_or(&[])
		.to_vec();

	reader.skip(412)?;
	info.challenge = reader.u64_be()?;

	Ok(info)
}

fn encode_v2(info: &AdvertisementInfo) -> Vec<u8> {
	let mut writer = Writer::new();

	writer.slice(&info.server_random);
	writer.u64_be(info.challenge);
	writer.u8(u8::try_from(info.security_mode).unwrap_or(0));
	writer.u8(info.station_accept_policy);
	writer.u16_be(info.app_version);
	writer.pad(8);
	writer.u16_be(band_channel(info.band, info.channel));
	writer.u8(info.max_participants);
	writer.u8(info.num_participants);

	for (index, participant) in info.participants.iter().enumerate() {
		if !participant.connected {
			continue;
		}

		writer.slice(&participant.ip_address);
		writer.slice(&participant.mac_address.octets());
		writer.u8(u8::try_from(index).unwrap_or(0));
		writer.u8(participant.platform);
		write_name(&mut writer, &participant.name);
		writer.pad(4);
	}

	writer.u16_be(u16::try_from(info.application_data.len()).unwrap_or(0));
	writer.slice(&info.application_data);

	writer.into_vec()
}

fn decode_v2(data: &[u8]) -> Result<AdvertisementInfo, DecodeError> {
	let mut reader = Reader::new(data);
	let mut info = AdvertisementInfo {
		server_random: reader.array()?,
		..AdvertisementInfo::default()
	};

	info.challenge = reader.u64_be()?;
	info.security_mode = u16::from(reader.u8()?);
	info.station_accept_policy = reader.u8()?;
	info.app_version = reader.u16_be()?;
	reader.skip(8)?;

	let value = reader.u16_be()?;
	info.band = u8::try_from(value >> 10).unwrap_or(0);
	info.channel = value & 0x3FF;

	info.max_participants = reader.u8()?;
	info.num_participants = reader.u8()?;

	// Only connected participants are on the wire, each carrying the slot it belongs in.
	for _ in 0..info.num_participants {
		let ip_address = reader.array()?;

		let mac_address = MacAddress::read(&mut reader)?;
		let index = usize::from(reader.u8()?);
		let platform = reader.u8()?;
		let name = read_name(&mut reader)?;
		reader.skip(4)?;

		if let Some(slot) = info.participants.get_mut(index) {
			*slot = ParticipantInfo {
				ip_address,
				mac_address,
				connected: true,
				name,
				app_version: info.app_version,
				platform,
			};
		}
	}

	let data_len = usize::from(reader.u16_be()?);
	info.application_data = reader.take(data_len)?.to_vec();

	Ok(info)
}

fn band_channel(band: u8, channel: u16) -> u16 {
	(u16::from(band) << 10) | (channel & 0x3FF)
}

fn write_name(writer: &mut Writer, name: &[u8]) {
	let truncated = name.get(..name.len().min(32)).unwrap_or(&[]);
	writer.slice(truncated);
	writer.pad(32usize.saturating_sub(truncated.len()));
}

fn read_name(reader: &mut Reader<'_>) -> Result<Vec<u8>, DecodeError> {
	let raw = reader.take(32)?;
	let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
	Ok(raw.get(..end).unwrap_or(&[]).to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertisementError {
	NotAnAdvertisement,
	UnsupportedVersion { version: u8 },
	WrongFormat { format: u8 },
	WrongSize { size: u16 },
	BadHash,
	BadTag,
	Malformed(DecodeError),
}

impl core::fmt::Display for AdvertisementError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::NotAnAdvertisement => write!(f, "not an LDN advertisement frame"),
			Self::UnsupportedVersion { version } => {
				write!(f, "unsupported LDN version {version}")
			}
			Self::WrongFormat { format } => {
				write!(f, "encryption format {format} is wrong for this protocol")
			}
			Self::WrongSize { size } => write!(f, "unexpected payload size field {size:#x}"),
			Self::BadHash => write!(f, "SHA-256 mismatch (wrong key?)"),
			Self::BadTag => write!(f, "GCM tag mismatch (wrong key?)"),
			Self::Malformed(err) => write!(f, "malformed advertisement: {err}"),
		}
	}
}

impl core::error::Error for AdvertisementError {}

impl From<DecodeError> for AdvertisementError {
	fn from(err: DecodeError) -> Self {
		Self::Malformed(err)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisementFrame {
	pub network_id: NetworkId,
	pub version: u8,
	pub format: u8,
	/// Four-byte nonce, bumped whenever the host changes something.
	pub nonce: [u8; 4],
	pub payload: AdvertisementInfo,
}

impl AdvertisementFrame {
	/// `protocol` selects which encryption format is acceptable (1 expects AES-CTR, anything
	/// else expects AES-GCM) and which master key `derivation` was built from. A scan tries each
	/// configured protocol in turn and keeps the one that decrypts.
	///
	/// # Errors
	/// [`AdvertisementError`] if the frame is not an advertisement, is truncated, uses an
	/// unexpected version or format, or fails its integrity check.
	pub fn decode(
		data: &[u8],
		derivation: &KeyDerivation,
		protocol: u8,
	) -> Result<Self, AdvertisementError> {
		let mut reader = Reader::new(data);

		if reader.u8()? != 0x7F {
			return Err(AdvertisementError::NotAnAdvertisement);
		}
		if reader.u24_be()? != LDN_OUI {
			return Err(AdvertisementError::NotAnAdvertisement);
		}
		if reader.u8()? != 4 {
			return Err(AdvertisementError::NotAnAdvertisement);
		}
		reader.skip(1)?;
		if reader.u16_be()? != 0x0101 {
			return Err(AdvertisementError::NotAnAdvertisement);
		}
		reader.skip(4)?;

		let consumed = data.len().saturating_sub(reader.remaining());
		let header = data
			.get(consumed..consumed + HEADER_LEN)
			.ok_or_else(|| DecodeError::UnexpectedEof {
				wanted: HEADER_LEN,
				got: reader.remaining(),
			})?
			.to_vec();

		let network_id = NetworkId::decode(&mut reader)?;

		let version = reader.u8()?;
		if !matches!(version, 2..=4) {
			return Err(AdvertisementError::UnsupportedVersion { version });
		}

		let format = reader.u8()?;
		let expected = if protocol == 1 {
			FORMAT_AES_CTR
		} else {
			FORMAT_AES_GCM
		};
		if format != FORMAT_PLAIN && format != expected {
			return Err(AdvertisementError::WrongFormat { format });
		}

		let size = reader.u16_be()?;
		if (format == FORMAT_PLAIN || format == FORMAT_AES_CTR) && size != V1_PAYLOAD_LEN {
			return Err(AdvertisementError::WrongSize { size });
		}

		let nonce = reader.array()?;

		let key = derivation.advertise_key(&network_id.encode());
		let size = usize::from(size);

		let plaintext = match format {
			FORMAT_PLAIN => {
				let body = reader.take(size + 32)?.to_vec();
				verify_hash(&header, &body)?
			}
			FORMAT_AES_CTR => {
				let mut body = reader.take(size + 32)?.to_vec();
				apply_ctr(&key, nonce, &mut body);
				verify_hash(&header, &body)?
			}
			FORMAT_AES_GCM => {
				let body = reader.take(size + 16)?;
				decrypt_gcm(&key, nonce, &header, body)?
			}
			other => return Err(AdvertisementError::WrongFormat { format: other }),
		};

		let payload = if format == FORMAT_AES_GCM {
			decode_v2(&plaintext)?
		} else {
			decode_v1(&plaintext)?
		};

		Ok(Self {
			network_id,
			version,
			format,
			nonce,
			payload,
		})
	}

	/// # Errors
	/// [`AdvertisementError::WrongFormat`] if `format` is not one of the `FORMAT_*` values.
	pub fn encode(&self, derivation: &KeyDerivation) -> Result<Vec<u8>, AdvertisementError> {
		let plaintext = if self.format == FORMAT_AES_GCM {
			encode_v2(&self.payload)
		} else {
			encode_v1(&self.payload)
		};

		let mut header = Writer::with_capacity(HEADER_LEN);
		header.slice(&self.network_id.encode());
		header.u8(self.version);
		header.u8(self.format);
		header.u16_be(u16::try_from(plaintext.len()).unwrap_or(0));
		header.slice(&self.nonce);
		let header = header.into_vec();

		let key = derivation.advertise_key(&self.network_id.encode());

		let body = match self.format {
			FORMAT_PLAIN => with_hash(&header, &plaintext),
			FORMAT_AES_CTR => {
				let mut hashed = with_hash(&header, &plaintext);
				apply_ctr(&key, self.nonce, &mut hashed);
				hashed
			}
			FORMAT_AES_GCM => encrypt_gcm(&key, self.nonce, &header, plaintext),
			other => return Err(AdvertisementError::WrongFormat { format: other }),
		};

		let mut writer = Writer::new();
		writer.u8(0x7F);
		writer.u24_be(LDN_OUI);
		writer.u8(4);
		writer.pad(1);
		writer.u16_be(0x0101);
		writer.pad(4);
		writer.slice(&header);
		writer.slice(&body);

		Ok(writer.into_vec())
	}
}

/// The SHA-256 covers `header || 32 zero bytes || plaintext`, so it is computed over the frame as
/// it will look with the hash slot blanked.
fn hash_of(header: &[u8], plaintext: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(header);
	hasher.update([0u8; 32]);
	hasher.update(plaintext);
	hasher.finalize().into()
}

fn with_hash(header: &[u8], plaintext: &[u8]) -> Vec<u8> {
	let hash = hash_of(header, plaintext);

	let mut out = Vec::with_capacity(plaintext.len() + 32);
	out.extend_from_slice(&hash);
	out.extend_from_slice(plaintext);
	out
}

fn verify_hash(header: &[u8], body: &[u8]) -> Result<Vec<u8>, AdvertisementError> {
	let claimed = body.get(..32).ok_or(DecodeError::UnexpectedEof {
		wanted: 32,
		got: body.len(),
	})?;
	let plaintext = body.get(32..).unwrap_or(&[]);

	if hash_of(header, plaintext) != claimed {
		return Err(AdvertisementError::BadHash);
	}

	Ok(plaintext.to_vec())
}

/// AES-128-CTR with the frame's 4-byte nonce and a 12-byte big-endian counter starting at zero.
fn apply_ctr(key: &[u8; 16], nonce: [u8; 4], data: &mut [u8]) {
	let mut iv = [0u8; 16];
	if let Some(front) = iv.get_mut(..4) {
		front.copy_from_slice(&nonce);
	}

	let mut cipher = Aes128Ctr::new(key.into(), (&iv).into());
	cipher.apply_keystream(data);
}

/// The GCM nonce is the frame nonce padded to 12 bytes.
fn gcm_nonce(nonce: [u8; 4]) -> [u8; 12] {
	let mut out = [0u8; 12];
	if let Some(front) = out.get_mut(..4) {
		front.copy_from_slice(&nonce);
	}
	out
}

fn decrypt_gcm(
	key: &[u8; 16],
	nonce: [u8; 4],
	header: &[u8],
	body: &[u8],
) -> Result<Vec<u8>, AdvertisementError> {
	let tag = body.get(..16).ok_or(DecodeError::UnexpectedEof {
		wanted: 16,
		got: body.len(),
	})?;
	let mut buffer = body.get(16..).unwrap_or(&[]).to_vec();

	let cipher = Aes128Gcm::new(key.into());
	let iv = gcm_nonce(nonce);

	cipher
		.decrypt_in_place_detached(
			Nonce::from_slice(&iv),
			header,
			&mut buffer,
			Tag::from_slice(tag),
		)
		.map_err(|_| AdvertisementError::BadTag)?;

	Ok(buffer)
}

fn encrypt_gcm(key: &[u8; 16], nonce: [u8; 4], header: &[u8], plaintext: Vec<u8>) -> Vec<u8> {
	let cipher = Aes128Gcm::new(key.into());
	let iv = gcm_nonce(nonce);

	let mut buffer = plaintext;
	let tag = cipher
		.encrypt_in_place_detached(Nonce::from_slice(&iv), header, &mut buffer)
		.unwrap_or_default();

	let mut out = Vec::with_capacity(buffer.len() + 16);
	out.extend_from_slice(&tag);
	out.extend_from_slice(&buffer);
	out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
	/// Which LDN protocol decrypted this: 1 or 3.
	pub protocol: u8,
	pub address: MacAddress,
	pub band: u8,
	pub channel: u8,
	pub local_communication_id: u64,
	pub scene_id: u16,
	pub ssid: [u8; 16],
	pub version: u8,
	pub server_random: [u8; 16],
	pub security_mode: u16,
	pub app_version: u16,
	pub accept_policy: u8,
	pub max_participants: u8,
	pub num_participants: u8,
	/// Always [`MAX_PARTICIPANTS`] slots.
	pub participants: Vec<ParticipantInfo>,
	pub application_data: Vec<u8>,
	pub challenge: u64,
	/// The advertisement nonce, which changes when the host does.
	pub nonce: [u8; 4],
}

impl Default for NetworkInfo {
	fn default() -> Self {
		Self {
			protocol: 1,
			address: MacAddress::ZERO,
			band: 2,
			channel: 1,
			local_communication_id: 0,
			scene_id: 0,
			ssid: [0; 16],
			version: 0,
			server_random: [0; 16],
			security_mode: SECURITY_MODE_PROD,
			app_version: 0,
			accept_policy: ACCEPT_ALL,
			max_participants: u8::try_from(MAX_PARTICIPANTS).unwrap_or(8),
			num_participants: 0,
			participants: vec![ParticipantInfo::default(); MAX_PARTICIPANTS],
			application_data: Vec::new(),
			challenge: 0,
			nonce: [0; 4],
		}
	}
}

impl NetworkInfo {
	/// The SSID this network is actually joined by.
	///
	/// LDN's own [`NetworkInfo::ssid`] is 16 hidden bytes; what goes on the air, and what
	/// `CMD_CONNECT` must be given, is those bytes as 32 lowercase hex characters
	/// (`ldn/__init__.py:1946`, `network.ssid.hex()`). Passing the raw bytes instead produces a
	/// join that is refused with nothing useful said about why.
	#[must_use]
	pub fn wlan_ssid(&self) -> String {
		let mut ssid = String::with_capacity(32);

		for byte in self.ssid {
			ssid.push(hex_digit(byte >> 4));
			ssid.push(hex_digit(byte & 0x0F));
		}

		ssid
	}

	#[must_use]
	pub const fn is_encrypted(&self) -> bool {
		self.security_mode == SECURITY_MODE_PROD
	}

	/// The network an advertisement describes, on the channel the host says it is on.
	///
	/// `heard_on`, the channel the frame arrived on, is only the fallback for an advertisement that
	/// names no channel LDN uses. A monitor on one channel also hears strong hosts on the channels
	/// either side of it, and a join sent to the channel an advertisement was heard on rather than
	/// the host's own is refused: `mgba_LDN`, hopping 1/6/11, had two joins in three come back with
	/// WLAN status 1 that way.
	#[must_use]
	pub fn from_advertisement(
		frame: &AdvertisementFrame,
		protocol: u8,
		address: MacAddress,
		heard_on: u8,
	) -> Self {
		let channel = u8::try_from(frame.payload.channel)
			.ok()
			.filter(|channel| is_valid_channel(*channel))
			.unwrap_or(heard_on);

		Self {
			protocol,
			address,
			band: channel_band(channel),
			channel,
			local_communication_id: frame.network_id.local_communication_id,
			scene_id: frame.network_id.scene_id,
			ssid: frame.network_id.ssid,
			version: frame.version,
			server_random: frame.payload.server_random,
			security_mode: frame.payload.security_mode,
			app_version: frame.payload.app_version,
			accept_policy: frame.payload.station_accept_policy,
			max_participants: frame.payload.max_participants,
			num_participants: frame.payload.num_participants,
			participants: frame.payload.participants.clone(),
			application_data: frame.payload.application_data.clone(),
			challenge: frame.payload.challenge,
			nonce: frame.nonce,
		}
	}

	#[must_use]
	pub fn build_advertisement(&self) -> AdvertisementFrame {
		let format = if self.security_mode == SECURITY_MODE_SYSTEM_DEBUG {
			FORMAT_PLAIN
		} else if self.protocol == 1 {
			FORMAT_AES_CTR
		} else {
			FORMAT_AES_GCM
		};

		AdvertisementFrame {
			network_id: NetworkId {
				local_communication_id: self.local_communication_id,
				scene_id: self.scene_id,
				ssid: self.ssid,
			},
			version: self.version,
			format,
			nonce: self.nonce,
			payload: AdvertisementInfo {
				server_random: self.server_random,
				security_mode: self.security_mode,
				station_accept_policy: self.accept_policy,
				app_version: self.app_version,
				band: self.band,
				channel: u16::from(self.channel),
				max_participants: self.max_participants,
				num_participants: self.num_participants,
				participants: self.participants.clone(),
				application_data: self.application_data.clone(),
				challenge: self.challenge,
			},
		}
	}

	#[must_use]
	pub fn is_same_network(&self, other: &Self) -> bool {
		self.address == other.address
			&& self.band == other.band
			&& self.channel == other.channel
			&& self.local_communication_id == other.local_communication_id
			&& self.scene_id == other.scene_id
			&& self.ssid == other.ssid
			&& self.version == other.version
			&& self.server_random == other.server_random
			&& self.security_mode == other.security_mode
	}

	#[must_use]
	pub const fn is_joinable(&self) -> bool {
		self.accept_policy != ACCEPT_NONE && self.num_participants < self.max_participants
	}
}

const fn hex_digit(value: u8) -> char {
	match value & 0x0F {
		0 => '0',
		1 => '1',
		2 => '2',
		3 => '3',
		4 => '4',
		5 => '5',
		6 => '6',
		7 => '7',
		8 => '8',
		9 => '9',
		10 => 'a',
		11 => 'b',
		12 => 'c',
		13 => 'd',
		14 => 'e',
		_ => 'f',
	}
}

#[cfg(test)]
#[allow(
	clippy::unwrap_used,
	clippy::expect_used,
	clippy::panic,
	clippy::indexing_slicing
)]
mod tests {
	use super::{
		ACCEPT_ALL, AdvertisementError, AdvertisementFrame, AdvertisementInfo, FORMAT_AES_CTR,
		FORMAT_AES_GCM, FORMAT_PLAIN, MAX_PARTICIPANTS, NetworkId, NetworkInfo, ParticipantInfo,
		SECURITY_MODE_PROD, V1_PAYLOAD_LEN, decode_v1, decode_v2, encode_v1, encode_v2,
	};
	use crate::crypto::{KeyDerivation, Keys};
	use crate::wlan::MacAddress;

	const SAMPLE_KEYS: &str = "\
		master_key_00 = 000102030405060708090a0b0c0d0e0f\n\
		master_key_12 = 101112131415161718191a1b1c1d1e1f\n\
		aes_kek_generation_source = 202122232425262728292a2b2c2d2e2f\n\
		aes_key_generation_source = 303132333435363738393a3b3c3d3e3f\n\
	";

	fn derivation(protocol: u8) -> KeyDerivation {
		KeyDerivation::new(&Keys::parse(SAMPLE_KEYS).unwrap(), protocol).unwrap()
	}

	fn sample_info() -> AdvertisementInfo {
		let mut participants = vec![ParticipantInfo::default(); MAX_PARTICIPANTS];

		participants[0] = ParticipantInfo {
			ip_address: [169, 254, 21, 1],
			mac_address: MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap(),
			connected: true,
			name: b"Host".to_vec(),
			app_version: 7,
			platform: super::PLATFORM_NX,
		};
		participants[2] = ParticipantInfo {
			ip_address: [169, 254, 21, 3],
			mac_address: MacAddress::parse("aa:bb:cc:dd:ee:03").unwrap(),
			connected: true,
			name: b"Alex".to_vec(),
			app_version: 7,
			platform: super::PLATFORM_NX,
		};

		AdvertisementInfo {
			server_random: [0x5A; 16],
			security_mode: SECURITY_MODE_PROD,
			station_accept_policy: ACCEPT_ALL,
			app_version: 7,
			band: 2,
			channel: 6,
			max_participants: 8,
			num_participants: 2,
			participants,
			application_data: b"beacon-payload".to_vec(),
			challenge: 0x0123_4567_89AB_CDEF,
		}
	}

	fn sample_frame(format: u8) -> AdvertisementFrame {
		AdvertisementFrame {
			network_id: NetworkId {
				local_communication_id: 0x0100_9B90_006D_C000,
				scene_id: 1,
				ssid: [0x11; 16],
			},
			version: 4,
			format,
			nonce: [0xDE, 0xAD, 0xBE, 0xEF],
			payload: sample_info(),
		}
	}

	#[test]
	fn network_id_is_thirty_two_bytes_and_round_trips() {
		let id = NetworkId {
			local_communication_id: 0x0100_9B90_006D_C000,
			scene_id: 3,
			ssid: [0xAB; 16],
		};

		let encoded = id.encode();
		assert_eq!(encoded.len(), 32);

		let mut reader = crate::protocol::bytes::Reader::new(&encoded);
		assert_eq!(NetworkId::decode(&mut reader).unwrap(), id);
	}

	#[test]
	fn v1_payload_is_exactly_0x500_bytes() {
		assert_eq!(encode_v1(&sample_info()).len(), usize::from(V1_PAYLOAD_LEN));
	}

	#[test]
	fn v1_round_trips() {
		let info = sample_info();
		let decoded = decode_v1(&encode_v1(&info)).unwrap();

		assert_eq!(decoded.server_random, info.server_random);
		assert_eq!(decoded.security_mode, info.security_mode);
		assert_eq!(decoded.band, info.band);
		assert_eq!(decoded.channel, info.channel);
		assert_eq!(decoded.num_participants, info.num_participants);
		assert_eq!(decoded.application_data, info.application_data);
		assert_eq!(decoded.challenge, info.challenge);
		assert_eq!(decoded.participants.len(), MAX_PARTICIPANTS);
		assert_eq!(decoded.participants[0].name, b"Host");
		assert_eq!(decoded.participants[2].name, b"Alex");
		assert!(!decoded.participants[1].connected);
	}

	#[test]
	fn v2_round_trips_and_restores_slot_positions() {
		let info = sample_info();
		let decoded = decode_v2(&encode_v2(&info)).unwrap();

		assert_eq!(decoded.participants.len(), MAX_PARTICIPANTS);
		assert_eq!(decoded.participants[0].name, b"Host");
		assert!(decoded.participants[0].connected);
		assert!(!decoded.participants[1].connected, "slot 1 stays empty");
		assert_eq!(
			decoded.participants[2].name, b"Alex",
			"the index byte puts this back in slot 2, not slot 1"
		);
		assert_eq!(decoded.application_data, info.application_data);
	}

	#[test]
	fn v1_names_are_null_stripped_and_truncated() {
		let mut info = sample_info();
		info.participants[0].name = b"0123456789012345678901234567890123456789".to_vec();

		let decoded = decode_v1(&encode_v1(&info)).unwrap();
		assert_eq!(
			decoded.participants[0].name.len(),
			32,
			"clipped to the field"
		);
	}

	#[test]
	fn plain_frames_round_trip() {
		let derivation = derivation(1);
		let frame = sample_frame(FORMAT_PLAIN);

		let bytes = frame.encode(&derivation).unwrap();
		let decoded = AdvertisementFrame::decode(&bytes, &derivation, 1).unwrap();

		assert_eq!(decoded.network_id, frame.network_id);
		assert_eq!(decoded.nonce, frame.nonce);
		assert_eq!(decoded.payload.application_data, b"beacon-payload");
	}

	#[test]
	fn aes_ctr_frames_round_trip() {
		let derivation = derivation(1);
		let frame = sample_frame(FORMAT_AES_CTR);

		let bytes = frame.encode(&derivation).unwrap();
		let decoded = AdvertisementFrame::decode(&bytes, &derivation, 1).unwrap();

		assert_eq!(decoded.payload.challenge, frame.payload.challenge);
		assert_eq!(decoded.payload.participants[2].name, b"Alex");
	}

	#[test]
	fn aes_gcm_frames_round_trip() {
		let derivation = derivation(3);
		let frame = sample_frame(FORMAT_AES_GCM);

		let bytes = frame.encode(&derivation).unwrap();
		let decoded = AdvertisementFrame::decode(&bytes, &derivation, 3).unwrap();

		assert_eq!(decoded.payload.application_data, b"beacon-payload");
		assert_eq!(decoded.payload.num_participants, 2);
	}

	#[test]
	fn ciphertext_does_not_leak_the_plaintext() {
		let derivation = derivation(1);
		let bytes = sample_frame(FORMAT_AES_CTR).encode(&derivation).unwrap();

		assert!(
			!bytes.windows(14).any(|w| w == b"beacon-payload"),
			"the application data must not appear in the clear"
		);
	}

	#[test]
	fn a_gcm_frame_is_rejected_when_protocol_1_is_expected() {
		let derivation = derivation(3);
		let bytes = sample_frame(FORMAT_AES_GCM).encode(&derivation).unwrap();

		assert_eq!(
			AdvertisementFrame::decode(&bytes, &derivation, 1),
			Err(AdvertisementError::WrongFormat {
				format: FORMAT_AES_GCM
			})
		);
	}

	#[test]
	fn non_advertisement_bodies_are_rejected() {
		let derivation = derivation(1);

		assert_eq!(
			AdvertisementFrame::decode(b"\x7f\x00\x22\xaa\x05", &derivation, 1),
			Err(AdvertisementError::NotAnAdvertisement),
			"subtype 5 is not LDN"
		);
		assert!(AdvertisementFrame::decode(b"", &derivation, 1).is_err());
		assert!(
			AdvertisementFrame::decode(b"\x7f\x00\x22\xab\x04", &derivation, 1).is_err(),
			"wrong OUI"
		);
	}

	#[test]
	fn an_unsupported_version_is_reported() {
		let derivation = derivation(1);
		let mut frame = sample_frame(FORMAT_PLAIN);
		frame.version = 9;

		let bytes = frame.encode(&derivation).unwrap();
		assert_eq!(
			AdvertisementFrame::decode(&bytes, &derivation, 1),
			Err(AdvertisementError::UnsupportedVersion { version: 9 })
		);
	}

	#[test]
	fn truncated_frames_are_errors_not_panics() {
		let derivation = derivation(1);
		let bytes = sample_frame(FORMAT_AES_CTR).encode(&derivation).unwrap();

		for cut in [12, 20, 40, 60, 100, bytes.len() - 1] {
			assert!(
				AdvertisementFrame::decode(&bytes[..cut], &derivation, 1).is_err(),
				"a frame cut at {cut} bytes must fail cleanly"
			);
		}
	}

	#[test]
	fn network_info_reports_joinability() {
		let derivation = derivation(1);
		let frame = sample_frame(FORMAT_PLAIN);
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();

		let bytes = frame.encode(&derivation).unwrap();
		let decoded = AdvertisementFrame::decode(&bytes, &derivation, 1).unwrap();
		let info = NetworkInfo::from_advertisement(&decoded, 1, host, 6);

		assert_eq!(info.address, host);
		assert_eq!(info.channel, 6);
		assert_eq!(info.band, 2);
		assert_eq!(info.local_communication_id, 0x0100_9B90_006D_C000);
		assert!(info.is_joinable(), "2 of 8 with ACCEPT_ALL");

		let mut full = info.clone();
		full.num_participants = full.max_participants;
		assert!(!full.is_joinable(), "a full network is not joinable");

		let mut closed = info;
		closed.accept_policy = super::ACCEPT_NONE;
		assert!(!closed.is_joinable(), "ACCEPT_NONE is not joinable");
	}
}
