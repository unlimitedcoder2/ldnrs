//! All of it is little-endian, unlike the LDN payloads layered on top, which are big-endian.

#![allow(
	clippy::indexing_slicing,
	reason = "only into fixed-size arrays, where the bound is a constant"
)]

use core::fmt;

use crate::protocol::bytes::{DecodeError, Reader};
use crate::protocol::writer::Writer;

const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000F_AC04;
const WLAN_AKM_SUITE_PSK: u32 = 0x000F_AC02;

pub const FTYPE_MGMT: u8 = 0;
pub const STYPE_ACTION: u8 = 13;
pub const STYPE_ASSOC_REQ: u8 = 0;
pub const STYPE_ASSOC_RESP: u8 = 1;
pub const STYPE_PROBE_RESP: u8 = 5;
pub const STYPE_BEACON: u8 = 8;
pub const STYPE_PROBE_REQ: u8 = 4;
pub const STYPE_DISASSOC: u8 = 10;
/// Management subtype: 802.11 authentication, *not* LDN's own, which rides the control port.
pub const STYPE_AUTH: u8 = 11;
pub const STYPE_DEAUTH: u8 = 12;

pub const WLAN_AUTH_OPEN: u16 = 0;

/// Length of the 802.11 MAC header LDN uses (no `QoS`, three addresses).
pub const MAC_HEADER_LEN: usize = 24;

/// The channels LDN is allowed on, paired with their centre frequency in MHz.
pub const CHANNELS: [(u8, u16); 7] = [
	(1, 2412),
	(6, 2437),
	(11, 2462),
	(36, 5180),
	(40, 5200),
	(44, 5220),
	(48, 5240),
];

pub const DEFAULT_SCAN_CHANNELS: [u8; 3] = [1, 6, 11];

pub const DEFAULT_DWELL_MS: u32 = 300;

#[must_use]
pub fn is_valid_channel(channel: u8) -> bool {
	CHANNELS.iter().any(|(number, _)| *number == channel)
}

#[must_use]
pub fn channel_frequency(channel: u8) -> Option<u16> {
	CHANNELS
		.iter()
		.find(|(number, _)| *number == channel)
		.map(|(_, frequency)| *frequency)
}

#[must_use]
pub fn frequency_channel(frequency: u16) -> Option<u8> {
	CHANNELS
		.iter()
		.find(|(_, mhz)| *mhz == frequency)
		.map(|(number, _)| *number)
}

#[must_use]
pub const fn channel_band(channel: u8) -> u8 {
	if channel >= 36 { 5 } else { 2 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
	pub const BROADCAST: Self = Self([0xFF; 6]);

	pub const ZERO: Self = Self([0; 6]);

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than six bytes remain.
	pub fn read(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.array().map(Self)
	}

	#[must_use]
	pub fn from_slice(data: &[u8]) -> Option<Self> {
		let octets: [u8; 6] = data.try_into().ok()?;
		Some(Self(octets))
	}

	#[must_use]
	pub const fn octets(&self) -> [u8; 6] {
		self.0
	}

	#[must_use]
	pub fn is_zero(&self) -> bool {
		self.0 == [0; 6]
	}

	#[must_use]
	pub fn parse(text: &str) -> Option<Self> {
		let mut octets = [0u8; 6];
		let mut parts = text.split(':');

		for slot in &mut octets {
			*slot = u8::from_str_radix(parts.next()?, 16).ok()?;
		}

		if parts.next().is_some() {
			return None;
		}

		Some(Self(octets))
	}
}

impl fmt::Display for MacAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let o = self.0;
		write!(
			f,
			"{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
			o[0], o[1], o[2], o[3], o[4], o[5]
		)
	}
}

/// Decodes 802.11 information elements (one-byte id, one-byte length, value).
///
/// Returns the elements in the order they appeared. A truncated element ends the walk rather than
/// failing, matching how a receiver treats a damaged tail.
#[must_use]
pub fn decode_elements(data: &[u8]) -> Vec<(u8, &[u8])> {
	let mut reader = Reader::new(data);
	let mut elements = Vec::new();

	while !reader.is_empty() {
		let Ok(id) = reader.u8() else { break };
		let Ok(length) = reader.u8() else { break };
		let Ok(value) = reader.take(usize::from(length)) else {
			break;
		};

		elements.push((id, value));
	}

	elements
}

#[derive(Debug, Clone, Default)]
pub struct RadiotapFrame<'a> {
	pub mactime: Option<u64>,
	pub flags: Option<u8>,
	pub rate: Option<u8>,
	/// Centre frequency in MHz, if present. Scanning needs this to know which channel a frame
	/// arrived on.
	pub frequency: Option<u16>,
	pub channel_flags: Option<u16>,
	pub data: &'a [u8],
}

const PRESENT_TSFT: u32 = 1;
const PRESENT_FLAGS: u32 = 1 << 1;
const PRESENT_RATE: u32 = 1 << 2;
const PRESENT_CHANNEL: u32 = 1 << 3;
const PRESENT_EXT: u32 = 1 << 31;

impl<'a> RadiotapFrame<'a> {
	/// Fields are aligned to their own width within the header, and the header may carry more
	/// `present` words than this build knows; both are handled by trusting the length field and
	/// skipping to it, rather than assuming the fields end where we stopped reading.
	///
	/// # Errors
	/// [`DecodeError`] if the header is truncated, the version is not 0, or the length field is
	/// shorter than the fields actually consumed.
	pub fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);

		let version = reader.u8()?;
		if version != 0 {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: 0,
				got: usize::from(version),
			});
		}

		let _pad = reader.u8()?;
		let length = usize::from(reader.u16_le()?);

		let mut present: u64 = 0;
		let mut shift = 0u32;
		loop {
			let word = reader.u32_le()?;

			if shift == 0 {
				present = u64::from(word);
			}

			if word & PRESENT_EXT == 0 {
				break;
			}

			shift += 32;
			if shift > 96 {
				return Err(DecodeError::TruncatedTlv);
			}
		}

		// Offsets are relative to the start of the header, which is where alignment is measured
		// from. `consumed` tracks that because the reader only knows what is left.
		let mut consumed = data.len().saturating_sub(reader.remaining());
		let mut frame = Self::default();

		let present32 = u32::try_from(present).unwrap_or(u32::MAX);

		if present32 & PRESENT_TSFT != 0 {
			consumed = align_to(&mut reader, consumed, 8)?;
			frame.mactime = Some(reader.u64_le()?);
			consumed += 8;
		}

		if present32 & PRESENT_FLAGS != 0 {
			frame.flags = Some(reader.u8()?);
			consumed += 1;
		}

		if present32 & PRESENT_RATE != 0 {
			frame.rate = Some(reader.u8()?);
			consumed += 1;
		}

		if present32 & PRESENT_CHANNEL != 0 {
			consumed = align_to(&mut reader, consumed, 2)?;
			frame.frequency = Some(reader.u16_le()?);
			frame.channel_flags = Some(reader.u16_le()?);
			consumed += 4;
		}

		if consumed > length {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: length,
				got: consumed,
			});
		}

		let mut rest = Reader::new(data);
		rest.take(length)?;
		frame.data = rest.take_rest();

		Ok(frame)
	}
}

fn align_to(
	reader: &mut Reader<'_>,
	consumed: usize,
	alignment: usize,
) -> Result<usize, DecodeError> {
	let remainder = consumed.checked_rem(alignment).unwrap_or(0);
	if remainder == 0 {
		return Ok(consumed);
	}

	let padding = alignment.saturating_sub(remainder);
	reader.take(padding)?;

	Ok(consumed + padding)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacHeader {
	/// Frame type: 0 management, 1 control, 2 data.
	pub frame_type: u8,
	pub subtype: u8,
	pub flags: u8,
	pub duration: u16,
	pub address1: MacAddress,
	pub address2: MacAddress,
	pub address3: MacAddress,
	pub sequence_control: u16,
}

impl MacHeader {
	/// # Errors
	/// [`DecodeError`] if the header is short or announces a protocol version other than 0.
	pub fn decode(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let frame_control = reader.u16_le()?;

		if frame_control & 3 != 0 {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: 0,
				got: usize::from(frame_control & 3),
			});
		}

		Ok(Self {
			frame_type: u8::try_from((frame_control >> 2) & 3).unwrap_or(0),
			subtype: u8::try_from((frame_control >> 4) & 0xF).unwrap_or(0),
			flags: u8::try_from(frame_control >> 8).unwrap_or(0),
			duration: reader.u16_le()?,
			address1: MacAddress::read(reader)?,
			address2: MacAddress::read(reader)?,
			address3: MacAddress::read(reader)?,
			sequence_control: reader.u16_le()?,
		})
	}
}

#[derive(Debug, Clone)]
pub struct ActionFrame<'a> {
	pub source: MacAddress,
	pub action: &'a [u8],
}

impl<'a> ActionFrame<'a> {
	/// # Errors
	/// [`DecodeError`] if the frame is short or is not a management action frame.
	pub fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);
		let header = MacHeader::decode(&mut reader)?;

		if header.frame_type != FTYPE_MGMT || header.subtype != STYPE_ACTION {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: usize::from(STYPE_ACTION),
				got: usize::from(header.subtype),
			});
		}

		Ok(Self {
			source: header.address2,
			action: reader.take_rest(),
		})
	}

	/// Both addressed fields are the broadcast address, and deliberately so: an advertisement is
	/// not addressed to anyone. It is how a network is discovered, so every station in range has
	/// to accept it before it knows the host exists, and the BSSID is broadcast too, because a
	/// station filtering on a BSSID it has not yet learned would drop the one frame that tells it.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let header = MacHeader {
			frame_type: FTYPE_MGMT,
			subtype: STYPE_ACTION,
			flags: 0,
			duration: 0,
			address1: MacAddress::BROADCAST,
			address2: self.source,
			address3: MacAddress::BROADCAST,
			sequence_control: 0,
		};

		let mut writer = Writer::with_capacity(MAC_HEADER_LEN + self.action.len());
		writer.slice(&header.encode());
		writer.slice(self.action);

		writer.into_vec()
	}
}

/// The smallest radiotap header a monitor interface will accept for injection: version 0, no
/// fields present, 8 bytes long.
const RADIOTAP_MINIMAL: [u8; 8] = [0, 0, 8, 0, 0, 0, 0, 0];

#[must_use]
pub fn radiotap_wrap(frame: &[u8]) -> Vec<u8> {
	let mut wrapped = Vec::with_capacity(RADIOTAP_MINIMAL.len() + frame.len());
	wrapped.extend_from_slice(&RADIOTAP_MINIMAL);
	wrapped.extend_from_slice(frame);

	wrapped
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
		ActionFrame, MacAddress, RadiotapFrame, channel_band, channel_frequency, decode_elements,
		frequency_channel, is_valid_channel,
	};
	use super::{RsnElement, WLAN_EID_RSN, encode_elements, rsn_elements};

	#[test]
	fn channel_table_round_trips() {
		for (channel, frequency) in super::CHANNELS {
			assert!(is_valid_channel(channel));
			assert_eq!(channel_frequency(channel), Some(frequency));
			assert_eq!(frequency_channel(frequency), Some(channel));
		}

		assert!(!is_valid_channel(2));
		assert_eq!(frequency_channel(1234), None);
	}

	#[test]
	fn bands_split_at_channel_36() {
		assert_eq!(channel_band(1), 2);
		assert_eq!(channel_band(11), 2);
		assert_eq!(channel_band(36), 5);
		assert_eq!(channel_band(48), 5);
	}

	#[test]
	fn mac_addresses_parse_and_print() {
		let mac = MacAddress::parse("00:22:aa:04:01:ff").unwrap();
		assert_eq!(mac.octets(), [0x00, 0x22, 0xaa, 0x04, 0x01, 0xff]);
		assert_eq!(mac.to_string(), "00:22:aa:04:01:ff");

		assert!(MacAddress::ZERO.is_zero());
		assert!(!MacAddress::BROADCAST.is_zero());

		assert_eq!(MacAddress::parse("00:22:aa:04:01"), None, "too short");
		assert_eq!(MacAddress::parse("00:22:aa:04:01:ff:00"), None, "too long");
		assert_eq!(MacAddress::parse("zz:22:aa:04:01:ff"), None);
	}

	#[test]
	fn elements_decode_in_order() {
		let data = [0x00, 0x02, b'h', b'i', 0x01, 0x01, 0x82];
		let elements = decode_elements(&data);

		assert_eq!(elements.len(), 2);
		assert_eq!(elements[0], (0x00, &b"hi"[..]));
		assert_eq!(elements[1], (0x01, &[0x82][..]));
	}

	#[test]
	fn a_truncated_element_ends_the_walk_rather_than_failing() {
		let data = [0x00, 0x01, 0xAA, 0x01, 0x09, 0xBB];
		let elements = decode_elements(&data);

		assert_eq!(elements.len(), 1, "the good element is still returned");
		assert_eq!(elements[0], (0x00, &[0xAA][..]));
	}

	fn radiotap_with_channel(frequency: u16, payload: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		out.push(0);
		out.push(0);
		out.extend_from_slice(&12u16.to_le_bytes());
		out.extend_from_slice(&8u32.to_le_bytes());
		out.extend_from_slice(&frequency.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(payload);
		out
	}

	#[test]
	fn radiotap_reports_the_frequency_a_frame_arrived_on() {
		let bytes = radiotap_with_channel(2437, b"payload");
		let frame = RadiotapFrame::decode(&bytes).unwrap();

		assert_eq!(frame.frequency, Some(2437));
		assert_eq!(frequency_channel(frame.frequency.unwrap()), Some(6));
		assert_eq!(frame.data, b"payload");
	}

	#[test]
	fn radiotap_skips_fields_it_does_not_understand() {
		let mut bytes = Vec::new();
		bytes.push(0);
		bytes.push(0);
		bytes.extend_from_slice(&16u16.to_le_bytes());
		bytes.extend_from_slice(&(8u32 | (1 << 20)).to_le_bytes());
		bytes.extend_from_slice(&2412u16.to_le_bytes());
		bytes.extend_from_slice(&0u16.to_le_bytes());
		bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
		bytes.extend_from_slice(b"frame");

		let frame = RadiotapFrame::decode(&bytes).unwrap();
		assert_eq!(frame.frequency, Some(2412));
		assert_eq!(
			frame.data, b"frame",
			"payload starts after the declared length"
		);
	}

	#[test]
	fn radiotap_rejects_a_bad_version_and_a_short_header() {
		let mut bytes = radiotap_with_channel(2412, b"x");
		bytes[0] = 1;
		assert!(RadiotapFrame::decode(&bytes).is_err(), "version must be 0");

		assert!(RadiotapFrame::decode(&[0, 0]).is_err(), "truncated");
	}

	fn action_frame(source: MacAddress, action: &[u8]) -> Vec<u8> {
		let frame_control: u16 =
			(u16::from(super::FTYPE_MGMT) << 2) | (u16::from(super::STYPE_ACTION) << 4);

		let mut out = Vec::new();
		out.extend_from_slice(&frame_control.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&MacAddress::BROADCAST.octets());
		out.extend_from_slice(&source.octets());
		out.extend_from_slice(&MacAddress::BROADCAST.octets());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(action);
		out
	}

	#[test]
	fn action_frames_expose_the_transmitter_and_body() {
		let host = MacAddress::parse("aa:bb:cc:dd:ee:ff").unwrap();
		let bytes = action_frame(host, b"\x7f\x00\x22\xaa");

		let frame = ActionFrame::decode(&bytes).unwrap();
		assert_eq!(frame.source, host, "address2 is the host");
		assert_eq!(frame.action, b"\x7f\x00\x22\xaa");
	}

	#[test]
	fn non_action_frames_are_rejected() {
		let mut bytes = action_frame(MacAddress::BROADCAST, b"body");
		let frame_control: u16 = (u16::from(super::FTYPE_MGMT) << 2) | (8u16 << 4);
		bytes[0..2].copy_from_slice(&frame_control.to_le_bytes());

		assert!(ActionFrame::decode(&bytes).is_err());
	}

	#[test]
	fn a_short_frame_is_an_error_not_a_panic() {
		assert!(ActionFrame::decode(&[0, 0, 0]).is_err());
	}

	#[test]
	fn an_rsn_element_is_twenty_bytes_with_suites_big_endian() {
		let encoded = RsnElement::default().encode();

		assert_eq!(
			encoded,
			vec![
				0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
				0x00, 0x0F, 0xAC, 0x02, 0x0C, 0x00,
			]
		);
	}

	#[test]
	fn elements_are_ordered_by_id_and_carry_their_length() {
		let encoded = encode_elements(&[(48, vec![0xAA, 0xBB]), (1, vec![0xCC])]);

		assert_eq!(encoded, vec![1, 1, 0xCC, 48, 2, 0xAA, 0xBB]);
	}

	#[test]
	fn an_element_too_long_to_express_is_skipped_rather_than_truncated() {
		let encoded = encode_elements(&[(1, vec![0; 256]), (2, vec![0xFF])]);

		assert_eq!(encoded, vec![2, 1, 0xFF]);
	}

	#[test]
	fn the_rsn_elements_offered_on_a_join_round_trip_through_the_decoder() {
		let encoded = rsn_elements();
		let decoded = decode_elements(&encoded);

		assert_eq!(decoded.len(), 1);
		let (id, value) = decoded.first().copied().unwrap();

		assert_eq!(id, WLAN_EID_RSN);
		assert_eq!(value, RsnElement::default().encode().as_slice());
	}

	#[test]
	fn an_address_needs_exactly_six_bytes() {
		assert_eq!(
			MacAddress::from_slice(&[1, 2, 3, 4, 5, 6]),
			Some(MacAddress([1, 2, 3, 4, 5, 6]))
		);

		assert_eq!(MacAddress::from_slice(&[1, 2, 3, 4, 5]), None);
		assert_eq!(MacAddress::from_slice(&[1, 2, 3, 4, 5, 6, 7]), None);
		assert_eq!(MacAddress::from_slice(&[]), None);
	}
}

/// The RSN element advertising the network's cipher suites.
///
/// LDN has no key exchange (the key comes from the host's advertisement), so this element exists
/// only to tell the driver which ciphers to use. The values are fixed: CCMP for both group and
/// pairwise traffic, PSK for key management, and capabilities 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsnElement {
	pub group_cipher_suite: u32,
	pub pairwise_cipher_suite: u32,
	pub akm_suite: u32,
	pub capabilities: u16,
}

impl Default for RsnElement {
	fn default() -> Self {
		Self {
			group_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
			pairwise_cipher_suite: WLAN_CIPHER_SUITE_CCMP,
			akm_suite: WLAN_AKM_SUITE_PSK,
			capabilities: 12,
		}
	}
}

impl RsnElement {
	/// Counts and capabilities are little-endian; cipher suites are big-endian, because a suite is
	/// an OUI followed by a selector byte rather than a number.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let mut writer = Writer::with_capacity(20);

		writer.u16_le(1);
		writer.u32_be(self.group_cipher_suite);
		writer.u16_le(1);
		writer.u32_be(self.pairwise_cipher_suite);
		writer.u16_le(1);
		writer.u32_be(self.akm_suite);
		writer.u16_le(self.capabilities);

		writer.into_vec()
	}
}

pub const WLAN_EID_RSN: u8 = 48;

#[must_use]
pub fn encode_elements(elements: &[(u8, Vec<u8>)]) -> Vec<u8> {
	let mut ordered: Vec<&(u8, Vec<u8>)> = elements.iter().collect();
	ordered.sort_by_key(|(id, _)| *id);

	let mut writer = Writer::new();
	for (id, value) in ordered {
		let Ok(length) = u8::try_from(value.len()) else {
			continue;
		};

		writer.u8(*id);
		writer.u8(length);
		writer.slice(value);
	}

	writer.into_vec()
}

#[must_use]
pub fn rsn_elements() -> Vec<u8> {
	encode_elements(&[(WLAN_EID_RSN, RsnElement::default().encode())])
}

pub const WLAN_EID_SSID: u8 = 0;
pub const WLAN_EID_SUPP_RATES: u8 = 1;
pub const WLAN_EID_DS_PARAMS: u8 = 3;

/// The high bit marks a rate as *basic*, one a station must support to associate. Taken verbatim
/// from the Python rather than derived, because the point is to look like a Switch.
pub const SUPPORTED_RATES: [u8; 8] = [0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C];

/// Beacon interval, in the 1024-microsecond units 802.11 counts in.
pub const BEACON_INTERVAL: u16 = 100;

pub const DTIM_PERIOD: u8 = 3;

const CAPABILITY_BEACON: u16 = 0x511;
const CAPABILITY_PROBE_RESPONSE: u16 = 0x501;
const CAPABILITY_ASSOCIATION_RESPONSE: u16 = 0x411;
const CAPABILITY_PRIVACY: u16 = 0x10;

/// The two high bits an association id is always sent with.
const AID_MASK: u16 = 0xC000;

pub const WLAN_STATUS_SUCCESS: u16 = 0;

impl MacHeader {
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let frame_control = (u16::from(self.frame_type) << 2)
			| (u16::from(self.subtype) << 4)
			| (u16::from(self.flags) << 8);

		let mut writer = Writer::with_capacity(MAC_HEADER_LEN);

		writer.u16_le(frame_control);
		writer.u16_le(self.duration);
		writer.slice(&self.address1.octets());
		writer.slice(&self.address2.octets());
		writer.slice(&self.address3.octets());
		writer.u16_le(self.sequence_control);

		writer.into_vec()
	}

	#[must_use]
	const fn management(subtype: u8, source: MacAddress, target: MacAddress) -> Self {
		Self {
			frame_type: FTYPE_MGMT,
			subtype,
			flags: 0,
			duration: 0,
			address1: target,
			address2: source,
			address3: source,
			sequence_control: 0,
		}
	}
}

#[must_use]
pub fn beacon_head(source: MacAddress) -> Vec<u8> {
	let header = MacHeader::management(STYPE_BEACON, source, MacAddress::BROADCAST);

	let mut writer = Writer::new();
	writer.slice(&header.encode());
	// Timestamp: the driver overwrites it with the real TSF.
	writer.u64_le(0);
	writer.u16_le(BEACON_INTERVAL);
	writer.u16_le(CAPABILITY_BEACON);

	writer.into_vec()
}

/// An empty beacon tail.
///
/// An LDN network is not discoverable by ordinary means (its SSID is a
/// 16-byte hash a client can only know by having scanned for the advertisement), so there is
/// nothing a beacon element would usefully say.
#[must_use]
pub const fn beacon_tail() -> Vec<u8> {
	Vec::new()
}

/// Builds a probe response, including the RSN element when encrypted.
///
/// `encrypted` sets the privacy bit and attaches the RSN element. It is derived from whether the
/// network has a key rather than passed as a policy: a station that sees privacy advertised and
/// gets no RSN element, or the reverse, will refuse to associate.
#[must_use]
pub fn probe_response(
	source: MacAddress,
	target: MacAddress,
	ssid: &[u8],
	channel: u8,
	encrypted: bool,
) -> Vec<u8> {
	let header = MacHeader::management(STYPE_PROBE_RESP, source, target);

	let mut capability = CAPABILITY_PROBE_RESPONSE;
	let mut elements = vec![
		(WLAN_EID_SSID, ssid.to_vec()),
		(WLAN_EID_SUPP_RATES, SUPPORTED_RATES.to_vec()),
		(WLAN_EID_DS_PARAMS, vec![channel]),
	];

	if encrypted {
		capability |= CAPABILITY_PRIVACY;
		elements.push((WLAN_EID_RSN, RsnElement::default().encode()));
	}

	let mut writer = Writer::new();
	writer.slice(&header.encode());
	writer.u64_le(0);
	writer.u16_le(BEACON_INTERVAL);
	writer.u16_le(capability);
	writer.slice(&encode_elements(&elements));

	writer.into_vec()
}

#[must_use]
pub fn association_response(source: MacAddress, target: MacAddress, aid: u16) -> Vec<u8> {
	association_frame(source, target, WLAN_STATUS_SUCCESS, aid | AID_MASK, true)
}

#[must_use]
pub fn association_error(source: MacAddress, target: MacAddress, status: u16) -> Vec<u8> {
	association_frame(source, target, status, 0, false)
}

fn association_frame(
	source: MacAddress,
	target: MacAddress,
	status: u16,
	aid: u16,
	rates: bool,
) -> Vec<u8> {
	let header = MacHeader::management(STYPE_ASSOC_RESP, source, target);

	let mut writer = Writer::new();
	writer.slice(&header.encode());
	writer.u16_le(CAPABILITY_ASSOCIATION_RESPONSE);
	writer.u16_le(status);
	writer.u16_le(aid);

	if rates {
		writer.slice(&encode_elements(&[(
			WLAN_EID_SUPP_RATES,
			SUPPORTED_RATES.to_vec(),
		)]));
	}

	writer.into_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationRequest {
	pub target: MacAddress,
	pub source: MacAddress,
	pub capability_information: u16,
	pub listen_interval: u16,
	pub elements: Vec<(u8, Vec<u8>)>,
}

impl AssociationRequest {
	/// # Errors
	/// [`DecodeError`] if the frame is short or is not an association request.
	pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);
		let header = MacHeader::decode(&mut reader)?;

		if header.frame_type != FTYPE_MGMT || header.subtype != STYPE_ASSOC_REQ {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: usize::from(STYPE_ASSOC_REQ),
				got: usize::from(header.subtype),
			});
		}

		let capability_information = reader.u16_le()?;
		let listen_interval = reader.u16_le()?;

		let elements = decode_elements(reader.take_rest())
			.into_iter()
			.map(|(id, value)| (id, value.to_vec()))
			.collect();

		Ok(Self {
			target: header.address1,
			source: header.address2,
			capability_information,
			listen_interval,
			elements,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disassociation {
	pub target: MacAddress,
	pub source: MacAddress,
	pub bssid: MacAddress,
	pub reason: u16,
}

impl Disassociation {
	/// # Errors
	/// [`DecodeError`] if the frame is short or is not a disassociation.
	pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);
		let header = MacHeader::decode(&mut reader)?;

		if header.frame_type != FTYPE_MGMT || header.subtype != STYPE_DISASSOC {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: usize::from(STYPE_DISASSOC),
				got: usize::from(header.subtype),
			});
		}

		Ok(Self {
			target: header.address1,
			source: header.address2,
			bssid: header.address3,
			reason: reader.u16_le()?,
		})
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
	pub source: MacAddress,
	pub elements: Vec<(u8, Vec<u8>)>,
}

impl ProbeRequest {
	/// # Errors
	/// [`DecodeError`] if the frame is short or is not a probe request.
	pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);
		let header = MacHeader::decode(&mut reader)?;

		if header.frame_type != FTYPE_MGMT || header.subtype != STYPE_PROBE_REQ {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: usize::from(STYPE_PROBE_REQ),
				got: usize::from(header.subtype),
			});
		}

		let elements = decode_elements(reader.take_rest())
			.into_iter()
			.map(|(id, value)| (id, value.to_vec()))
			.collect();

		Ok(Self {
			source: header.address2,
			elements,
		})
	}

	/// An absent SSID is a wildcard probe: a station asking whoever is listening. An LDN host
	/// does not answer those: the network is meant to be invisible to anything that has not
	/// already decoded its advertisement.
	#[must_use]
	pub fn ssid(&self) -> Option<&[u8]> {
		self.elements
			.iter()
			.find(|(id, _)| *id == WLAN_EID_SSID)
			.map(|(_, value)| value.as_slice())
	}
}

/// An 802.11 open-system authentication exchange.
///
/// Nothing to do with [`crate::authentication`], which is LDN's own handshake over the control
/// port. This is the two-frame open-system exchange 802.11 requires before an association, and it
/// authenticates nothing: the host answers every request with success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication80211 {
	pub target: MacAddress,
	pub source: MacAddress,
	pub bssid: MacAddress,
	pub algorithm: u16,
	/// 1 from the station, 2 from the host.
	pub sequence: u16,
	pub status_code: u16,
}

impl Authentication80211 {
	/// # Errors
	/// [`DecodeError`] if the frame is short or is not an authentication frame.
	pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);
		let header = MacHeader::decode(&mut reader)?;

		if header.frame_type != FTYPE_MGMT || header.subtype != STYPE_AUTH {
			return Err(DecodeError::BadFieldLength {
				tag: 0,
				expected: usize::from(STYPE_AUTH),
				got: usize::from(header.subtype),
			});
		}

		Ok(Self {
			target: header.address1,
			source: header.address2,
			bssid: header.address3,
			algorithm: reader.u16_le()?,
			sequence: reader.u16_le()?,
			status_code: reader.u16_le()?,
		})
	}

	#[must_use]
	pub fn accept(source: MacAddress, target: MacAddress) -> Vec<u8> {
		let header = MacHeader::management(STYPE_AUTH, source, target);

		let mut writer = Writer::with_capacity(MAC_HEADER_LEN + 6);
		writer.slice(&header.encode());
		writer.u16_le(WLAN_AUTH_OPEN);
		writer.u16_le(2);
		writer.u16_le(WLAN_STATUS_SUCCESS);

		writer.into_vec()
	}

	#[must_use]
	pub const fn is_open_request(&self) -> bool {
		self.algorithm == WLAN_AUTH_OPEN && self.sequence == 1
	}
}

#[cfg(test)]
#[allow(
	clippy::unwrap_used,
	clippy::expect_used,
	clippy::panic,
	clippy::indexing_slicing
)]
mod ap_tests {
	use super::{
		AssociationRequest, Disassociation, MacAddress, association_error, association_response,
		beacon_head, beacon_tail, probe_response,
	};

	const SOURCE: MacAddress = MacAddress([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
	const TARGET: MacAddress = MacAddress([0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);

	const SSID: &str = "000102030405060708090a0b0c0d0e0f";

	fn hex(text: &str) -> Vec<u8> {
		text.as_bytes()
			.chunks(2)
			.map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
			.collect()
	}

	// Every vector below was produced by the reference implementation
	// (`../LDN/ldn/wlan.py`) rather than written by hand, so these assert agreement with the
	// thing a Switch already talks to.

	#[test]
	fn a_beacon_head_matches_the_reference_byte_for_byte() {
		let expected =
			hex("80000000ffffffffffff0211223344550211223344550000000000000000000064001105");

		assert_eq!(beacon_head(SOURCE), expected);
	}

	#[test]
	fn the_beacon_tail_is_empty() {
		assert!(beacon_tail().is_empty());
	}

	#[test]
	fn an_open_probe_response_matches_the_reference() {
		let expected = hex(concat!(
			"5000000006aabbccddee0211223344550211223344550000000000",
			"0000000000640001050020303030313032303330343035303630373",
			"0383039306130623063306430653066010882848b962430486c0301",
			"06"
		));

		assert_eq!(
			probe_response(SOURCE, TARGET, SSID.as_bytes(), 6, false),
			expected
		);
	}

	#[test]
	fn an_encrypted_probe_response_adds_privacy_and_the_rsn_element() {
		let expected = hex(concat!(
			"5000000006aabbccddee0211223344550211223344550000000000",
			"0000000000640011050020303030313032303330343035303630373",
			"0383039306130623063306430653066010882848b962430486c0301",
			"0630140100000fac040100000fac040100000fac020c00"
		));

		let response = probe_response(SOURCE, TARGET, SSID.as_bytes(), 6, true);
		assert_eq!(response, expected);

		let capability = u16::from_le_bytes([response[34], response[35]]);
		assert_eq!(capability & 0x10, 0x10);
		assert!(response.windows(4).any(|w| w == [0x30, 0x14, 0x01, 0x00]));
	}

	#[test]
	fn an_association_response_matches_the_reference_and_sets_the_aid_bits() {
		let expected = hex(concat!(
			"1000000006aabbccddee02112233445502112233445500001104",
			"000001c0010882848b962430486c"
		));

		let response = association_response(SOURCE, TARGET, 1);
		assert_eq!(response, expected);

		let aid = u16::from_le_bytes([response[28], response[29]]);
		assert_eq!(aid, 0xC001);
	}

	#[test]
	fn an_association_error_matches_the_reference() {
		let expected = hex("1000000006aabbccddee0211223344550211223344550000110411000000");

		assert_eq!(association_error(SOURCE, TARGET, 17), expected);
	}

	#[test]
	fn an_association_request_from_the_reference_decodes() {
		let frame = hex(concat!(
			"0000000002112233445506aabbccddee021122334455000031040a",
			"00010882848b962430486c"
		));

		let request = AssociationRequest::decode(&frame).unwrap();

		assert_eq!(request.target, SOURCE);
		assert_eq!(request.source, TARGET);
		assert_eq!(request.capability_information, 0x0431);
		assert_eq!(request.listen_interval, 10);
		assert_eq!(
			request.elements,
			vec![(1u8, vec![0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C])]
		);
	}

	#[test]
	fn a_disassociation_decodes() {
		// Built by hand rather than taken from the reference, because the reference's
		// `DisassociationFrame.encode` writes subtype 11 (AUTH) instead of 10 (DISASSOC), a frame
		// its own `decode` rejects. Only the decode path is ported, so the bug does not travel.
		let frame = hex("a0000000021122334455 06aabbccddee 021122334455 0000 0800"
			.replace(' ', "")
			.as_str());

		let disassociation = Disassociation::decode(&frame).unwrap();

		assert_eq!(disassociation.target, SOURCE);
		assert_eq!(disassociation.source, TARGET);
		assert_eq!(disassociation.bssid, SOURCE);
		assert_eq!(disassociation.reason, 8);
	}

	#[test]
	fn the_wrong_subtype_is_rejected_rather_than_misread() {
		let beacon = beacon_head(SOURCE);

		assert!(AssociationRequest::decode(&beacon).is_err());
		assert!(Disassociation::decode(&beacon).is_err());
	}

	#[test]
	fn truncation_is_an_error_rather_than_a_panic() {
		let frame = hex(concat!(
			"0000000002112233445506aabbccddee021122334455000031040a",
			"00010882848b962430486c"
		));

		for length in 0..frame.len() {
			let _ = AssociationRequest::decode(&frame[..length]);
			let _ = Disassociation::decode(&frame[..length]);
		}
	}
}
