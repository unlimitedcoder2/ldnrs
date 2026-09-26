use aes_gcm::aead::{AeadInPlace, KeyInit as GcmKeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::advertisement::{NetworkId, PLATFORM_NX};
use crate::crypto::KeyDerivation;
use crate::protocol::bytes::{DecodeError, Reader};
use crate::protocol::writer::Writer;

type HmacSha256 = Hmac<Sha256>;

pub const AUTH_SUCCESS: u8 = 0;
pub const AUTH_DENIED_BY_POLICY: u8 = 1;
pub const AUTH_MALFORMED_REQUEST: u8 = 2;
pub const AUTH_TIMEOUT: u8 = 3;
pub const AUTH_INVALID_VERSION: u8 = 4;
pub const AUTH_UNEXPECTED: u8 = 5;
pub const AUTH_CHALLENGE_FAILURE: u8 = 6;

pub const AUTH_FORMAT_PLAIN: u8 = 0;
pub const AUTH_FORMAT_AES_GCM: u8 = 1;

pub(crate) const LDN_OUI: u32 = 0x0000_22AA;

const SUBTYPE_AUTHENTICATION: u16 = 0x0102;

const SUBTYPE_DISCONNECT: u16 = 0x0103;

const HEADER_LEN: usize = 0x48;

pub const CHALLENGE_REQUEST_LEN: usize = 0x300;

pub const CHALLENGE_RESPONSE_LEN: usize = 0x100;

/// Body size of a challenge request, i.e. the part the HMAC covers.
const CHALLENGE_REQUEST_BODY: usize = 0x2D0;

const CHALLENGE_RESPONSE_BODY: usize = 0xD0;

const PARAMS1_SLOTS: usize = 8;

const PARAMS2_SLOTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
	NotAuthentication,
	NotDisconnect,
	WrongFormat { format: u8 },
	WrongSize { declared: usize, actual: usize },
	WrongChallengeSize { expected: usize, got: usize },
	BadHmac,
	BadTag,
	Malformed(DecodeError),
}

impl core::fmt::Display for AuthError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::NotAuthentication => write!(f, "not an LDN authentication frame"),
			Self::NotDisconnect => write!(f, "not an LDN disconnect frame"),
			Self::WrongFormat { format } => {
				write!(f, "encryption format {format} is wrong for this protocol")
			}
			Self::WrongSize { declared, actual } => {
				write!(
					f,
					"frame declares {declared} payload bytes but carries {actual}"
				)
			}
			Self::WrongChallengeSize { expected, got } => {
				write!(f, "challenge should be {expected} bytes, is {got}")
			}
			Self::BadHmac => write!(f, "challenge HMAC mismatch (wrong challenge key?)"),
			Self::BadTag => write!(f, "GCM tag mismatch (wrong keys?)"),
			Self::Malformed(err) => write!(f, "malformed authentication frame: {err}"),
		}
	}
}

impl core::error::Error for AuthError {}

impl From<DecodeError> for AuthError {
	fn from(err: DecodeError) -> Self {
		Self::Malformed(err)
	}
}

/// Wraps a challenge body in its `u32 0 || hmac[32] || pad12 || body` envelope.
fn seal(key: &[u8; 32], body: &[u8]) -> Vec<u8> {
	let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap_or_else(|_| {
		// The key is a fixed 32 bytes, so this cannot happen; HMAC accepts any length anyway.
		<HmacSha256 as Mac>::new_from_slice(&[]).unwrap_or_else(|_| unreachable_hmac())
	});
	mac.update(body);
	let digest = mac.finalize().into_bytes();

	let mut writer = Writer::with_capacity(body.len() + 48);
	writer.u32_le(0);
	writer.slice(&digest);
	writer.pad(12);
	writer.slice(body);

	writer.into_vec()
}

fn unreachable_hmac() -> HmacSha256 {
	#[allow(
		clippy::expect_used,
		reason = "HMAC accepts any key length; cannot fail"
	)]
	<HmacSha256 as Mac>::new_from_slice(&[]).expect("HMAC accepts any key length")
}

fn unseal<'a>(key: &[u8; 32], data: &'a [u8], body_len: usize) -> Result<&'a [u8], AuthError> {
	let mut reader = Reader::new(data);
	reader.skip(4)?;
	let claimed = reader.take(32)?;
	reader.skip(12)?;
	let body = reader.take(body_len)?;

	let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable_hmac());
	mac.update(body);

	if mac.verify_slice(claimed).is_err() {
		return Err(AuthError::BadHmac);
	}

	Ok(body)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeRequest {
	pub flags: u8,
	/// Echoes the `challenge` token from the host's advertisement.
	pub token: u64,
	/// The station's nonce, echoed back in the response.
	pub nonce: u64,
	pub device_id: u64,
	/// Present on Switch 2; zero otherwise.
	pub unk: [u8; 16],
	pub params1: Vec<u64>,
	pub params2: Vec<u64>,
}

impl ChallengeRequest {
	#[must_use]
	pub fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
		let mut body = Writer::with_capacity(CHALLENGE_REQUEST_BODY);

		body.u8(0);
		body.u8(0);
		body.u8(u8::try_from(self.params1.len()).unwrap_or(0));
		body.u8(u8::try_from(self.params2.len()).unwrap_or(0));
		body.u8(self.flags);
		body.pad(3);

		body.u64_le(self.token);
		body.u64_le(self.nonce);
		body.u64_le(self.device_id);
		body.slice(&self.unk);
		body.pad(0x60);

		write_params(&mut body, &self.params1, PARAMS1_SLOTS);
		write_params(&mut body, &self.params2, PARAMS2_SLOTS);

		seal(key, &body.into_vec())
	}

	/// # Errors
	/// [`AuthError::WrongChallengeSize`] if the blob is the wrong length, [`AuthError::BadHmac`]
	/// if it does not verify.
	pub fn decode(data: &[u8], key: &[u8; 32]) -> Result<Self, AuthError> {
		if data.len() != CHALLENGE_REQUEST_LEN {
			return Err(AuthError::WrongChallengeSize {
				expected: CHALLENGE_REQUEST_LEN,
				got: data.len(),
			});
		}

		let body = unseal(key, data, CHALLENGE_REQUEST_BODY)?;
		let mut reader = Reader::new(body);

		reader.skip(2)?;
		let count1 = usize::from(reader.u8()?);
		let count2 = usize::from(reader.u8()?);
		let flags = reader.u8()?;
		reader.skip(3)?;

		let token = reader.u64_le()?;
		let nonce = reader.u64_le()?;
		let device_id = reader.u64_le()?;

		let unk = reader.array()?;

		reader.skip(0x60)?;

		// Both blocks are always fully present on the wire; only the counts say how many matter.
		let params1 = read_params(&mut reader, PARAMS1_SLOTS, count1)?;
		let params2 = read_params(&mut reader, PARAMS2_SLOTS, count2)?;

		Ok(Self {
			flags,
			token,
			nonce,
			device_id,
			unk,
			params1,
			params2,
		})
	}
}

fn write_params(writer: &mut Writer, values: &[u64], slots: usize) {
	let used = values.len().min(slots);

	for value in values.iter().take(used) {
		writer.u64_le(*value);
	}

	writer.pad(slots.saturating_sub(used) * 8);
}

fn read_params(
	reader: &mut Reader<'_>,
	slots: usize,
	count: usize,
) -> Result<Vec<u64>, DecodeError> {
	let mut values = Vec::with_capacity(count.min(slots));

	for index in 0..slots {
		let value = reader.u64_le()?;
		if index < count {
			values.push(value);
		}
	}

	Ok(values)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChallengeResponse {
	/// Flags. The host sets 2 on success.
	pub flags: u32,
	/// Echoes the station's nonce.
	pub nonce: u64,
	/// Echoes the station's device id.
	pub device_id: u64,
	pub device_id_host: u64,
	/// Echoes the station's `unk`.
	pub unk: [u8; 16],
	pub unk_host: [u8; 16],
}

impl ChallengeResponse {
	#[must_use]
	pub fn encode(&self, key: &[u8; 32]) -> Vec<u8> {
		let mut body = Writer::with_capacity(CHALLENGE_RESPONSE_BODY);

		body.u8(0);
		body.u8(0);
		body.pad(2);
		body.u32_le(self.flags);
		body.u64_le(self.nonce);
		body.u64_le(self.device_id);
		body.u64_le(self.device_id_host);
		body.slice(&self.unk);
		body.slice(&self.unk_host);
		body.pad(0x90);

		seal(key, &body.into_vec())
	}

	/// # Errors
	/// [`AuthError::WrongChallengeSize`] or [`AuthError::BadHmac`].
	pub fn decode(data: &[u8], key: &[u8; 32]) -> Result<Self, AuthError> {
		if data.len() != CHALLENGE_RESPONSE_LEN {
			return Err(AuthError::WrongChallengeSize {
				expected: CHALLENGE_RESPONSE_LEN,
				got: data.len(),
			});
		}

		let body = unseal(key, data, CHALLENGE_RESPONSE_BODY)?;
		let mut reader = Reader::new(body);

		reader.skip(4)?;
		let flags = reader.u32_le()?;
		let nonce = reader.u64_le()?;
		let device_id = reader.u64_le()?;
		let device_id_host = reader.u64_le()?;
		let unk = reader.array()?;
		let unk_host = reader.array()?;

		Ok(Self {
			flags,
			nonce,
			device_id,
			device_id_host,
			unk,
			unk_host,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthenticationRequest {
	pub username: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
	/// An encoded [`ChallengeRequest`], present from LDN version 3.
	pub challenge: Vec<u8>,
}

impl AuthenticationRequest {
	#[must_use]
	pub fn encode(&self, version: u8) -> Vec<u8> {
		let mut writer = Writer::new();

		write_name(&mut writer, &self.username);
		writer.u16_be(self.app_version);
		writer.u8(self.platform);
		writer.pad(29);

		if version >= 3 {
			writer.pad(0x24);
			writer.slice(&self.challenge);
		}

		writer.into_vec()
	}

	/// # Errors
	/// [`AuthError::Malformed`] if it is truncated.
	pub fn decode(data: &[u8], version: u8) -> Result<Self, AuthError> {
		let mut reader = Reader::new(data);

		let username = read_name(&mut reader)?;
		let app_version = reader.u16_be()?;
		let platform = reader.u8()?;
		reader.skip(29)?;

		let mut challenge = Vec::new();
		if version >= 3 {
			reader.skip(0x24)?;
			if !reader.is_empty() {
				challenge = reader.take(CHALLENGE_REQUEST_LEN)?.to_vec();
			}
		}

		Ok(Self {
			username,
			app_version,
			platform,
			challenge,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResponse {
	pub platform: u8,
	/// An encoded [`ChallengeResponse`], present from LDN version 3.
	pub challenge: Vec<u8>,
}

impl Default for AuthenticationResponse {
	fn default() -> Self {
		Self {
			platform: PLATFORM_NX,
			challenge: Vec::new(),
		}
	}
}

impl AuthenticationResponse {
	/// Encodes the payload. Empty before LDN version 3.
	#[must_use]
	pub fn encode(&self, version: u8) -> Vec<u8> {
		let mut writer = Writer::new();

		if version >= 3 {
			writer.u8(self.platform);
			writer.pad(0x83);
			writer.slice(&self.challenge);
		}

		writer.into_vec()
	}

	/// # Errors
	/// [`AuthError::Malformed`] if it is truncated.
	pub fn decode(data: &[u8], version: u8) -> Result<Self, AuthError> {
		if version < 3 {
			return Ok(Self::default());
		}

		let mut reader = Reader::new(data);
		let platform = reader.u8()?;
		reader.skip(0x83)?;

		let challenge = if reader.is_empty() {
			Vec::new()
		} else {
			reader.take(CHALLENGE_RESPONSE_LEN)?.to_vec()
		};

		Ok(Self {
			platform,
			challenge,
		})
	}
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
pub enum AuthPayload {
	Request(AuthenticationRequest),
	Response(AuthenticationResponse),
}

impl AuthPayload {
	fn encode(&self, version: u8) -> Vec<u8> {
		match self {
			Self::Request(request) => request.encode(version),
			Self::Response(response) => response.encode(version),
		}
	}

	const fn is_response(&self) -> bool {
		matches!(self, Self::Response(_))
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationFrame {
	/// LDN version: 2, 3 or 4.
	pub version: u8,
	/// An `AUTH_*` status. Non-zero on a response means the join was refused.
	pub status_code: u8,
	pub network_id: NetworkId,
	pub server_random: [u8; 16],
	/// The station's random, which also keys the frame.
	pub client_random: [u8; 16],
	pub payload: AuthPayload,
}

impl AuthenticationFrame {
	fn header(&self, payload_len: usize, format: u8) -> Vec<u8> {
		let mut writer = Writer::with_capacity(HEADER_LEN);

		writer.u8(self.version);
		writer.u8(u8::try_from(payload_len & 0xFF).unwrap_or(0));
		writer.u8(self.status_code);
		writer.u8(u8::from(self.payload.is_response()));
		writer.u8(u8::try_from((payload_len >> 8) & 0xFF).unwrap_or(0));
		writer.u8(format);
		writer.pad(2);

		writer.slice(&self.network_id.encode_le());
		writer.slice(&self.server_random);
		writer.slice(&self.client_random);

		writer.into_vec()
	}

	#[must_use]
	pub const fn format_for(protocol: u8) -> u8 {
		if protocol == 1 {
			AUTH_FORMAT_PLAIN
		} else {
			AUTH_FORMAT_AES_GCM
		}
	}

	/// # Errors
	/// [`AuthError`] if encryption fails.
	pub fn encode(&self, derivation: &KeyDerivation, protocol: u8) -> Result<Vec<u8>, AuthError> {
		let payload = self.payload.encode(self.version);
		let format = Self::format_for(protocol);
		let header = self.header(payload.len(), format);

		let mut writer = Writer::new();
		writer.u24_be(LDN_OUI);
		writer.u16_be(SUBTYPE_AUTHENTICATION);
		writer.pad(1);
		writer.slice(&header);

		if format == AUTH_FORMAT_AES_GCM {
			let key = derivation.authentication_key(&self.client_random);
			let cipher = Aes128Gcm::new(&key.into());

			// The nonce is the first twelve bytes of the header, which the whole header then
			// authenticates.
			let nonce =
				header
					.get(..12)
					.ok_or(AuthError::Malformed(DecodeError::UnexpectedEof {
						wanted: 12,
						got: header.len(),
					}))?;

			let mut buffer = payload;
			let tag = cipher
				.encrypt_in_place_detached(Nonce::from_slice(nonce), &header, &mut buffer)
				.map_err(|_| AuthError::BadTag)?;

			writer.slice(&tag);
			writer.slice(&buffer);
		} else {
			writer.slice(&payload);
		}

		Ok(writer.into_vec())
	}

	/// # Errors
	/// [`AuthError`] if the frame is not authentication, uses the wrong format, is the wrong size,
	/// or fails its tag.
	pub fn decode(
		data: &[u8],
		derivation: &KeyDerivation,
		protocol: u8,
	) -> Result<Self, AuthError> {
		let mut reader = Reader::new(data);

		if reader.u24_be()? != LDN_OUI {
			return Err(AuthError::NotAuthentication);
		}
		if reader.u16_be()? != SUBTYPE_AUTHENTICATION {
			return Err(AuthError::NotAuthentication);
		}
		reader.skip(1)?;

		let consumed = data.len().saturating_sub(reader.remaining());
		let header = data
			.get(consumed..consumed + HEADER_LEN)
			.ok_or_else(|| {
				AuthError::Malformed(DecodeError::UnexpectedEof {
					wanted: HEADER_LEN,
					got: reader.remaining(),
				})
			})?
			.to_vec();

		let version = reader.u8()?;
		let size_lo = usize::from(reader.u8()?);
		let status_code = reader.u8()?;
		let is_response = reader.u8()? != 0;
		let size_hi = usize::from(reader.u8()?);
		let format = reader.u8()?;
		reader.skip(2)?;

		if format != Self::format_for(protocol) {
			return Err(AuthError::WrongFormat { format });
		}

		let network_id = NetworkId::decode_le(&mut reader)?;
		let server_random = reader.array()?;
		let client_random = reader.array()?;

		let tag = if format == AUTH_FORMAT_AES_GCM {
			Some(reader.take(16)?.to_vec())
		} else {
			None
		};

		let size = (size_hi << 8) | size_lo;
		if reader.remaining() != size {
			return Err(AuthError::WrongSize {
				declared: size,
				actual: reader.remaining(),
			});
		}

		let mut body = reader.take(size)?.to_vec();

		if let Some(tag) = tag {
			let key = derivation.authentication_key(&client_random);
			let cipher = Aes128Gcm::new(&key.into());

			let nonce =
				header
					.get(..12)
					.ok_or(AuthError::Malformed(DecodeError::UnexpectedEof {
						wanted: 12,
						got: header.len(),
					}))?;

			cipher
				.decrypt_in_place_detached(
					Nonce::from_slice(nonce),
					&header,
					&mut body,
					Tag::from_slice(&tag),
				)
				.map_err(|_| AuthError::BadTag)?;
		}

		let payload = if is_response {
			AuthPayload::Response(AuthenticationResponse::decode(&body, version)?)
		} else {
			AuthPayload::Request(AuthenticationRequest::decode(&body, version)?)
		};

		Ok(Self {
			version,
			status_code,
			network_id,
			server_random,
			client_random,
			payload,
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DisconnectFrame {
	pub reason: u8,
}

impl DisconnectFrame {
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut writer = Writer::with_capacity(38);
		writer.u24_be(LDN_OUI);
		writer.u16_be(SUBTYPE_DISCONNECT);
		writer.pad(1);
		writer.u8(self.reason);
		writer.pad(31);

		writer.into_vec()
	}

	/// # Errors
	/// [`AuthError::NotDisconnect`] if it is something else.
	pub fn decode(data: &[u8]) -> Result<Self, AuthError> {
		let mut reader = Reader::new(data);

		if reader.u24_be()? != LDN_OUI {
			return Err(AuthError::NotDisconnect);
		}
		if reader.u16_be()? != SUBTYPE_DISCONNECT {
			return Err(AuthError::NotDisconnect);
		}
		reader.skip(1)?;

		Ok(Self {
			reason: reader.u8()?,
		})
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
		AUTH_CHALLENGE_FAILURE, AUTH_FORMAT_AES_GCM, AUTH_FORMAT_PLAIN, AuthError, AuthPayload,
		AuthenticationFrame, AuthenticationRequest, AuthenticationResponse, CHALLENGE_REQUEST_LEN,
		CHALLENGE_RESPONSE_LEN, ChallengeRequest, ChallengeResponse, DisconnectFrame,
	};
	use crate::advertisement::NetworkId;
	use crate::advertisement::PLATFORM_NX;
	use crate::crypto::{CHALLENGE_KEY, KeyDerivation, Keys};

	const SAMPLE_KEYS: &str = "\
		master_key_00 = 000102030405060708090a0b0c0d0e0f\n\
		master_key_12 = 101112131415161718191a1b1c1d1e1f\n\
		aes_kek_generation_source = 202122232425262728292a2b2c2d2e2f\n\
		aes_key_generation_source = 303132333435363738393a3b3c3d3e3f\n\
	";

	fn derivation(protocol: u8) -> KeyDerivation {
		KeyDerivation::new(&Keys::parse(SAMPLE_KEYS).unwrap(), protocol).unwrap()
	}

	fn network_id() -> NetworkId {
		NetworkId {
			local_communication_id: 0x0100_6FA0_233F_8000,
			scene_id: 22287,
			ssid: [0x7F; 16],
		}
	}

	fn challenge_request() -> ChallengeRequest {
		ChallengeRequest {
			flags: 1,
			token: 0x0123_4567_89AB_CDEF,
			nonce: 0xFEED_FACE_CAFE_BEEF,
			device_id: 0xAABB_CCDD_EEFF_0011,
			unk: [0x5A; 16],
			params1: vec![1, 2, 3],
			params2: vec![10, 20],
		}
	}

	#[test]
	fn a_challenge_request_is_always_0x300_bytes() {
		let encoded = challenge_request().encode(&CHALLENGE_KEY);
		assert_eq!(encoded.len(), CHALLENGE_REQUEST_LEN);
	}

	#[test]
	fn a_challenge_request_round_trips() {
		let request = challenge_request();
		let encoded = request.encode(&CHALLENGE_KEY);

		assert_eq!(
			ChallengeRequest::decode(&encoded, &CHALLENGE_KEY).unwrap(),
			request
		);
	}

	#[test]
	fn only_the_declared_number_of_params_is_kept() {
		let mut request = challenge_request();
		request.params1 = vec![7];
		request.params2 = Vec::new();

		let encoded = request.encode(&CHALLENGE_KEY);
		let decoded = ChallengeRequest::decode(&encoded, &CHALLENGE_KEY).unwrap();

		assert_eq!(decoded.params1, vec![7]);
		assert!(decoded.params2.is_empty());
	}

	#[test]
	fn a_challenge_response_is_always_0x100_bytes_and_round_trips() {
		let response = ChallengeResponse {
			flags: 2,
			nonce: 0xFEED_FACE_CAFE_BEEF,
			device_id: 1,
			device_id_host: 2,
			unk: [0xAA; 16],
			unk_host: [0xBB; 16],
		};

		let encoded = response.encode(&CHALLENGE_KEY);
		assert_eq!(encoded.len(), CHALLENGE_RESPONSE_LEN);
		assert_eq!(
			ChallengeResponse::decode(&encoded, &CHALLENGE_KEY).unwrap(),
			response
		);
	}

	#[test]
	fn a_tampered_challenge_fails_its_hmac() {
		let mut encoded = challenge_request().encode(&CHALLENGE_KEY);
		encoded[60] ^= 1;

		assert_eq!(
			ChallengeRequest::decode(&encoded, &CHALLENGE_KEY),
			Err(AuthError::BadHmac)
		);
	}

	#[test]
	fn the_wrong_challenge_key_fails() {
		let encoded = challenge_request().encode(&CHALLENGE_KEY);

		assert_eq!(
			ChallengeRequest::decode(&encoded, &[0xFF; 32]),
			Err(AuthError::BadHmac)
		);
	}

	#[test]
	fn a_wrong_sized_challenge_is_rejected_before_hashing() {
		assert!(matches!(
			ChallengeRequest::decode(&[0u8; 16], &CHALLENGE_KEY),
			Err(AuthError::WrongChallengeSize { .. })
		));
	}

	#[test]
	fn an_authentication_request_round_trips() {
		let request = AuthenticationRequest {
			username: b"Alex".to_vec(),
			app_version: 88,
			platform: 1,
			challenge: challenge_request().encode(&CHALLENGE_KEY),
		};

		let encoded = request.encode(4);
		assert_eq!(AuthenticationRequest::decode(&encoded, 4).unwrap(), request);
	}

	#[test]
	fn a_version_2_request_carries_no_challenge() {
		let request = AuthenticationRequest {
			username: b"Old".to_vec(),
			app_version: 1,
			platform: 0,
			challenge: challenge_request().encode(&CHALLENGE_KEY),
		};

		let encoded = request.encode(2);
		assert_eq!(encoded.len(), 64);

		let decoded = AuthenticationRequest::decode(&encoded, 2).unwrap();
		assert_eq!(decoded.username, b"Old".to_vec());
		assert!(decoded.challenge.is_empty());
	}

	#[test]
	fn a_long_username_is_clipped_to_the_field() {
		let request = AuthenticationRequest {
			username: b"0123456789012345678901234567890123456789".to_vec(),
			..AuthenticationRequest::default()
		};

		let decoded = AuthenticationRequest::decode(&request.encode(4), 4).unwrap();
		assert_eq!(decoded.username.len(), 32);
	}

	#[test]
	fn plaintext_frames_round_trip_on_protocol_1() {
		let derivation = derivation(1);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0x11; 16],
			client_random: [0x22; 16],
			payload: AuthPayload::Request(AuthenticationRequest {
				username: b"Alex".to_vec(),
				app_version: 88,
				platform: 0,
				challenge: challenge_request().encode(&CHALLENGE_KEY),
			}),
		};

		let encoded = frame.encode(&derivation, 1).unwrap();
		assert_eq!(
			AuthenticationFrame::decode(&encoded, &derivation, 1).unwrap(),
			frame
		);
	}

	#[test]
	fn gcm_frames_round_trip_on_protocol_3() {
		let derivation = derivation(3);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0x33; 16],
			client_random: [0x44; 16],
			payload: AuthPayload::Request(AuthenticationRequest {
				username: b"Leafgreen".to_vec(),
				app_version: 88,
				platform: 1,
				challenge: challenge_request().encode(&CHALLENGE_KEY),
			}),
		};

		let encoded = frame.encode(&derivation, 3).unwrap();
		assert_eq!(
			AuthenticationFrame::decode(&encoded, &derivation, 3).unwrap(),
			frame
		);
	}

	#[test]
	fn an_encrypted_frame_does_not_leak_the_username() {
		let derivation = derivation(3);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [0x44; 16],
			payload: AuthPayload::Request(AuthenticationRequest {
				username: b"Leafgreen".to_vec(),
				..AuthenticationRequest::default()
			}),
		};

		let encoded = frame.encode(&derivation, 3).unwrap();
		assert!(
			!encoded.windows(9).any(|w| w == b"Leafgreen"),
			"the nickname must not appear in the clear"
		);
	}

	#[test]
	fn a_response_round_trips_and_is_told_apart_from_a_request() {
		let derivation = derivation(3);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0x33; 16],
			client_random: [0x44; 16],
			payload: AuthPayload::Response(AuthenticationResponse {
				platform: 1,
				challenge: ChallengeResponse::default().encode(&CHALLENGE_KEY),
			}),
		};

		let encoded = frame.encode(&derivation, 3).unwrap();
		let decoded = AuthenticationFrame::decode(&encoded, &derivation, 3).unwrap();

		assert!(matches!(decoded.payload, AuthPayload::Response(_)));
		assert_eq!(decoded, frame);
	}

	#[test]
	fn a_refusal_carries_its_status_code() {
		let derivation = derivation(3);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: AUTH_CHALLENGE_FAILURE,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [1; 16],
			payload: AuthPayload::Response(AuthenticationResponse::default()),
		};

		let encoded = frame.encode(&derivation, 3).unwrap();
		let decoded = AuthenticationFrame::decode(&encoded, &derivation, 3).unwrap();

		assert_eq!(decoded.status_code, AUTH_CHALLENGE_FAILURE);
	}

	#[test]
	fn the_wrong_keys_fail_the_tag_rather_than_returning_garbage() {
		let real = derivation(3);
		let wrong = KeyDerivation::new(
			&Keys::parse(&SAMPLE_KEYS.replace(
				"101112131415161718191a1b1c1d1e1f",
				"ffffffffffffffffffffffffffffffff",
			))
			.unwrap(),
			3,
		)
		.unwrap();

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [1; 16],
			payload: AuthPayload::Request(AuthenticationRequest::default()),
		};

		let encoded = frame.encode(&real, 3).unwrap();
		assert_eq!(
			AuthenticationFrame::decode(&encoded, &wrong, 3),
			Err(AuthError::BadTag)
		);
	}

	#[test]
	fn a_gcm_frame_is_rejected_when_plaintext_is_expected() {
		let three = derivation(3);
		let one = derivation(1);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [1; 16],
			payload: AuthPayload::Request(AuthenticationRequest::default()),
		};

		let encoded = frame.encode(&three, 3).unwrap();
		assert_eq!(
			AuthenticationFrame::decode(&encoded, &one, 1),
			Err(AuthError::WrongFormat {
				format: AUTH_FORMAT_AES_GCM
			})
		);
	}

	#[test]
	fn the_network_id_is_little_endian_here_but_big_endian_in_an_advertisement() {
		let id = network_id();

		assert_ne!(id.encode_le(), id.encode());
		assert_eq!(id.encode_le().len(), 32);
	}

	#[test]
	fn non_authentication_bodies_are_rejected() {
		let derivation = derivation(1);

		assert_eq!(
			AuthenticationFrame::decode(b"\x00\x22\xab\x01\x02\x00", &derivation, 1),
			Err(AuthError::NotAuthentication),
			"wrong OUI"
		);
		assert_eq!(
			AuthenticationFrame::decode(b"\x00\x22\xaa\x01\x03\x00", &derivation, 1),
			Err(AuthError::NotAuthentication),
			"that is a disconnect frame"
		);
		assert!(AuthenticationFrame::decode(b"", &derivation, 1).is_err());
	}

	#[test]
	fn truncated_frames_are_errors_not_panics() {
		let derivation = derivation(3);

		let frame = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [1; 16],
			payload: AuthPayload::Request(AuthenticationRequest {
				username: b"Alex".to_vec(),
				challenge: challenge_request().encode(&CHALLENGE_KEY),
				..AuthenticationRequest::default()
			}),
		};

		let encoded = frame.encode(&derivation, 3).unwrap();
		for cut in 0..encoded.len() {
			assert!(
				AuthenticationFrame::decode(&encoded[..cut], &derivation, 3).is_err(),
				"a frame cut at {cut} bytes must fail cleanly"
			);
		}
	}

	#[test]
	fn a_disconnect_frame_round_trips() {
		let frame = DisconnectFrame { reason: 6 };
		let encoded = frame.encode();

		assert_eq!(encoded.len(), 38);
		assert_eq!(DisconnectFrame::decode(&encoded).unwrap(), frame);
	}

	#[test]
	fn a_disconnect_frame_is_told_apart_from_an_authentication_frame() {
		let derivation = derivation(1);

		let auth = AuthenticationFrame {
			version: 4,
			status_code: 0,
			network_id: network_id(),
			server_random: [0; 16],
			client_random: [1; 16],
			payload: AuthPayload::Request(AuthenticationRequest::default()),
		}
		.encode(&derivation, 1)
		.unwrap();

		assert_eq!(
			DisconnectFrame::decode(&auth),
			Err(AuthError::NotDisconnect)
		);
		assert_eq!(AuthenticationFrame::format_for(1), AUTH_FORMAT_PLAIN);
	}

	/// A blob generated by the reference Python implementation, which is known to be accepted by a
	/// real Switch. Both vectors below come from the same run, with fixed inputs.
	const REFERENCE_CHALLENGE: &str = concat!(
		"00000000cffda52c97f9335ab93d572acd95be947721555a72d3283a23e737549203c990000000000000000000000000",
		"00000000000000004e5892066a976ae98877665544332211efcdab896745230100000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	);

	const REFERENCE_PAYLOAD: &str = concat!(
		"6c646e727300000000000000000000000000000000000000000000000000000000580000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000cffda52c97f9335ab93d572acd95be947721555a72d3283a23e737549203c9900000000000000000",
		"0000000000000000000000004e5892066a976ae98877665544332211efcdab8967452301000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"00000000",
	);

	fn from_hex(text: &str) -> Vec<u8> {
		let bytes = text.as_bytes();
		let mut out = Vec::with_capacity(text.len() / 2);

		for pair in bytes.chunks(2) {
			let pair = std::str::from_utf8(pair).unwrap();
			out.push(u8::from_str_radix(pair, 16).unwrap());
		}

		out
	}

	#[test]
	fn a_challenge_matches_the_reference_implementation_byte_for_byte() {
		let request = ChallengeRequest {
			flags: 0,
			token: 0xE96A_976A_0692_584E,
			nonce: 0x1122_3344_5566_7788,
			device_id: 0x0123_4567_89AB_CDEF,
			..ChallengeRequest::default()
		};

		assert_eq!(
			request.encode(&CHALLENGE_KEY),
			from_hex(REFERENCE_CHALLENGE)
		);
	}

	#[test]
	fn a_request_payload_matches_the_reference_implementation_byte_for_byte() {
		let challenge = from_hex(REFERENCE_CHALLENGE);

		let request = AuthenticationRequest {
			username: b"ldnrs".to_vec(),
			app_version: 88,
			platform: PLATFORM_NX,
			challenge,
		};

		assert_eq!(request.encode(4), from_hex(REFERENCE_PAYLOAD));
	}

	#[test]
	fn the_reference_challenge_round_trips_back_through_the_decoder() {
		let decoded = ChallengeRequest::decode(&from_hex(REFERENCE_CHALLENGE), &CHALLENGE_KEY)
			.expect("the reference challenge should verify");

		assert_eq!(decoded.token, 0xE96A_976A_0692_584E);
		assert_eq!(decoded.nonce, 0x1122_3344_5566_7788);
		assert_eq!(decoded.device_id, 0x0123_4567_89AB_CDEF);
	}
}
