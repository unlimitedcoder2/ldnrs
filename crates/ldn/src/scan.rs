use std::collections::HashSet;

use crate::advertisement::{ADVERTISEMENT_MAGIC, AdvertisementFrame, NetworkInfo};
use crate::crypto::{KeyDerivation, KeyError, Keys};
use crate::wlan::{ActionFrame, MacAddress, RadiotapFrame, frequency_channel};

pub const DEFAULT_PROTOCOLS: [u8; 2] = [1, 3];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanParams {
	pub channels: Vec<u8>,
	/// How long to listen on each, in milliseconds.
	pub dwell_ms: u32,
	pub protocols: Vec<u8>,
}

impl Default for ScanParams {
	fn default() -> Self {
		Self {
			channels: crate::wlan::DEFAULT_SCAN_CHANNELS.to_vec(),
			dwell_ms: crate::wlan::DEFAULT_DWELL_MS,
			protocols: DEFAULT_PROTOCOLS.to_vec(),
		}
	}
}

impl ScanParams {
	/// # Errors
	/// A description of the first problem found, suitable for an `InvalidParam` reply.
	pub fn check(&self) -> Result<(), String> {
		if self.channels.is_empty() {
			return Err("no channels to scan".to_owned());
		}

		for channel in &self.channels {
			if !crate::wlan::is_valid_channel(*channel) {
				return Err(format!("invalid channel: {channel}"));
			}
		}

		if self.protocols.is_empty() {
			return Err("no protocols to try".to_owned());
		}

		for protocol in &self.protocols {
			if !matches!(protocol, 1 | 3) {
				return Err(format!("unsupported LDN protocol: {protocol}"));
			}
		}

		Ok(())
	}
}

pub trait FrameSource {
	/// Tells the source that something else is about to take the radio.
	fn interrupted(&self) {}

	/// # Errors
	/// A description of why the channel could not be set, most often `EBUSY` because another
	/// interface holds the radio.
	fn set_channel(&self, channel: u8) -> Result<(), String>;

	/// Tries to read the next radiotap frame.
	/// # Errors
	/// `Empty` when no frame is ready, or `Disconnected` when the source has ended.
	fn try_next_frame(&self) -> Result<Vec<u8>, std::sync::mpsc::TryRecvError>;
}

pub struct Scanner {
	protocols: Vec<(u8, KeyDerivation)>,
	seen: HashSet<MacAddress>,
	networks: Vec<NetworkInfo>,
}

impl Scanner {
	/// # Errors
	/// [`KeyError`] if `prod.keys` cannot satisfy one of the requested protocols.
	pub fn new(keys: &Keys, protocols: &[u8]) -> Result<Self, KeyError> {
		let mut derivations = Vec::with_capacity(protocols.len());

		for protocol in protocols {
			derivations.push((*protocol, KeyDerivation::new(keys, *protocol)?));
		}

		Ok(Self {
			protocols: derivations,
			seen: HashSet::new(),
			networks: Vec::new(),
		})
	}

	pub fn feed(&mut self, radiotap: &[u8]) -> Option<NetworkInfo> {
		let frame = RadiotapFrame::decode(radiotap).ok()?;

		let heard_on = frequency_channel(frame.frequency?)?;

		let action = ActionFrame::decode(frame.data).ok()?;
		if !action.action.starts_with(&ADVERTISEMENT_MAGIC) {
			return None;
		}

		if self.seen.contains(&action.source) {
			return None;
		}

		for (protocol, derivation) in &self.protocols {
			let Ok(advertisement) =
				AdvertisementFrame::decode(action.action, derivation, *protocol)
			else {
				continue;
			};

			let info =
				NetworkInfo::from_advertisement(&advertisement, *protocol, action.source, heard_on);

			self.seen.insert(action.source);
			self.networks.push(info.clone());

			return Some(info);
		}

		None
	}

	#[must_use]
	pub fn networks(&self) -> &[NetworkInfo] {
		&self.networks
	}

	#[must_use]
	pub fn into_networks(self) -> Vec<NetworkInfo> {
		self.networks
	}

	#[must_use]
	pub const fn len(&self) -> usize {
		self.networks.len()
	}

	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.networks.is_empty()
	}
}

/// A frame source backed by a fixed list.
///
/// Once the list is exhausted it never resolves again, which is how a real monitor interface
/// behaves on a channel with no LDN traffic: the scan ends because its dwell expires, not because
/// the source ended.
pub struct ReplayFrameSource {
	frames: std::cell::RefCell<std::collections::VecDeque<(u8, Vec<u8>)>>,
	channel: std::cell::Cell<u8>,
}

impl ReplayFrameSource {
	#[must_use]
	pub fn new(frames: Vec<(u8, Vec<u8>)>) -> Self {
		Self {
			frames: std::cell::RefCell::new(frames.into()),
			channel: std::cell::Cell::new(0),
		}
	}
}

impl FrameSource for ReplayFrameSource {
	fn set_channel(&self, channel: u8) -> Result<(), String> {
		self.channel.set(channel);
		Ok(())
	}

	fn try_next_frame(&self) -> Result<Vec<u8>, std::sync::mpsc::TryRecvError> {
		let current = self.channel.get();
		let mut frames = self.frames.borrow_mut();
		frames
			.iter()
			.position(|(channel, _)| *channel == current)
			.and_then(|index| frames.remove(index))
			.map(|(_, frame)| frame)
			.ok_or(std::sync::mpsc::TryRecvError::Empty)
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
	use super::{ScanParams, Scanner};
	use crate::advertisement::{
		AdvertisementFrame, AdvertisementInfo, FORMAT_AES_CTR, FORMAT_AES_GCM, MAX_PARTICIPANTS,
		NetworkId, ParticipantInfo,
	};
	use crate::crypto::{KeyDerivation, Keys};
	use crate::wlan::{FTYPE_MGMT, MacAddress, STYPE_ACTION, channel_band, channel_frequency};

	const SAMPLE_KEYS: &str = "\
		master_key_00 = 000102030405060708090a0b0c0d0e0f\n\
		master_key_12 = 101112131415161718191a1b1c1d1e1f\n\
		aes_kek_generation_source = 202122232425262728292a2b2c2d2e2f\n\
		aes_key_generation_source = 303132333435363738393a3b3c3d3e3f\n\
	";

	fn keys() -> Keys {
		Keys::parse(SAMPLE_KEYS).unwrap()
	}

	fn advertisement(comm_id: u64, format: u8) -> AdvertisementFrame {
		let mut participants = vec![ParticipantInfo::default(); MAX_PARTICIPANTS];
		participants[0] = ParticipantInfo {
			ip_address: [169, 254, 21, 1],
			mac_address: MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap(),
			connected: true,
			name: b"Host".to_vec(),
			app_version: 7,
			platform: 0,
		};

		AdvertisementFrame {
			network_id: NetworkId {
				local_communication_id: comm_id,
				scene_id: 1,
				ssid: [0x22; 16],
			},
			version: 4,
			format,
			nonce: [1, 2, 3, 4],
			payload: AdvertisementInfo {
				max_participants: 8,
				num_participants: 1,
				participants,
				application_data: b"data".to_vec(),
				..AdvertisementInfo::default()
			},
		}
	}

	/// `frame`, naming `channel` as the host's own.
	fn on_channel(mut frame: AdvertisementFrame, channel: u8) -> AdvertisementFrame {
		frame.payload.band = channel_band(channel);
		frame.payload.channel = u16::from(channel);
		frame
	}

	fn air_frame(source: MacAddress, channel: u8, action: &[u8]) -> Vec<u8> {
		let frame_control: u16 = (u16::from(FTYPE_MGMT) << 2) | (u16::from(STYPE_ACTION) << 4);

		let mut wifi = Vec::new();
		wifi.extend_from_slice(&frame_control.to_le_bytes());
		wifi.extend_from_slice(&0u16.to_le_bytes());
		wifi.extend_from_slice(&MacAddress::BROADCAST.octets());
		wifi.extend_from_slice(&source.octets());
		wifi.extend_from_slice(&MacAddress::BROADCAST.octets());
		wifi.extend_from_slice(&0u16.to_le_bytes());
		wifi.extend_from_slice(action);

		let mut out = Vec::new();
		out.push(0);
		out.push(0);
		out.extend_from_slice(&12u16.to_le_bytes());
		out.extend_from_slice(&8u32.to_le_bytes());
		out.extend_from_slice(&channel_frequency(channel).unwrap().to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&wifi);
		out
	}

	#[test]
	fn finds_a_network_and_reports_its_channel() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();

		let action = on_channel(advertisement(0x0100_9B90_006D_C000, FORMAT_AES_CTR), 6)
			.encode(&derivation)
			.unwrap();
		let frame = air_frame(host, 6, &action);

		let mut scanner = Scanner::new(&keys(), &[1]).unwrap();
		let found = scanner
			.feed(&frame)
			.expect("the advertisement should decode");

		assert_eq!(found.address, host);
		assert_eq!(found.channel, 6);
		assert_eq!(found.band, 2);
		assert_eq!(found.protocol, 1);
		assert_eq!(found.local_communication_id, 0x0100_9B90_006D_C000);
		assert_eq!(found.application_data, b"data");
		assert_eq!(scanner.len(), 1);
	}

	#[test]
	fn a_host_heard_from_the_next_channel_is_reported_on_its_own() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();

		// (advertised, heard on): a monitor also catches strong hosts on the channels beside its own.
		for (advertised, heard_on) in [(1, 6), (11, 6), (40, 36)] {
			let action = on_channel(advertisement(1, FORMAT_AES_CTR), advertised)
				.encode(&derivation)
				.unwrap();

			let found = Scanner::new(&keys(), &[1])
				.unwrap()
				.feed(&air_frame(host, heard_on, &action))
				.expect("the advertisement should decode");

			assert_eq!(
				found.channel, advertised,
				"a join goes to the host's channel, not the one it was heard on"
			);
			assert_eq!(found.band, channel_band(advertised));
		}
	}

	#[test]
	fn an_advertisement_naming_no_ldn_channel_falls_back_to_where_it_was_heard() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();

		for advertised in [0u16, 3, 0x3FF] {
			let mut frame = advertisement(1, FORMAT_AES_CTR);
			frame.payload.channel = advertised;
			let action = frame.encode(&derivation).unwrap();

			let found = Scanner::new(&keys(), &[1])
				.unwrap()
				.feed(&air_frame(host, 11, &action))
				.expect("the advertisement should decode");

			assert_eq!(found.channel, 11, "{advertised} is not a channel LDN uses");
			assert_eq!(found.band, 2);
		}
	}

	#[test]
	fn a_host_advertising_repeatedly_is_reported_once() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();

		let action = advertisement(1, FORMAT_AES_CTR)
			.encode(&derivation)
			.unwrap();
		let frame = air_frame(host, 6, &action);

		let mut scanner = Scanner::new(&keys(), &[1]).unwrap();
		assert!(scanner.feed(&frame).is_some(), "first sighting");

		for _ in 0..10 {
			assert!(scanner.feed(&frame).is_none());
		}
		assert_eq!(scanner.len(), 1);
	}

	#[test]
	fn distinct_hosts_are_separate_networks() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();

		let mut scanner = Scanner::new(&keys(), &[1]).unwrap();

		for (index, mac) in ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]
			.iter()
			.enumerate()
		{
			let host = MacAddress::parse(mac).unwrap();
			let action = advertisement(u64::try_from(index).unwrap(), FORMAT_AES_CTR)
				.encode(&derivation)
				.unwrap();
			assert!(scanner.feed(&air_frame(host, 11, &action)).is_some());
		}

		assert_eq!(scanner.len(), 2);
	}

	#[test]
	fn tries_each_protocol_until_one_decrypts() {
		let derivation = KeyDerivation::new(&keys(), 3).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:03").unwrap();

		let action = advertisement(42, FORMAT_AES_GCM)
			.encode(&derivation)
			.unwrap();
		let frame = air_frame(host, 1, &action);

		let mut scanner = Scanner::new(&keys(), &[1, 3]).unwrap();
		let found = scanner.feed(&frame).expect("protocol 3 should decode it");

		assert_eq!(found.protocol, 3);
		assert_eq!(found.local_communication_id, 42);
	}

	#[test]
	fn ignores_traffic_that_is_not_an_ldn_advertisement() {
		let host = MacAddress::parse("aa:bb:cc:dd:ee:09").unwrap();
		let mut scanner = Scanner::new(&keys(), &[1]).unwrap();

		assert!(
			scanner
				.feed(&air_frame(host, 6, b"not an advertisement"))
				.is_none()
		);
		assert!(
			scanner
				.feed(&air_frame(host, 6, &[0x7F, 0x00, 0x22, 0xAA, 0x05]))
				.is_none()
		);
		assert!(scanner.feed(b"").is_none(), "garbage");
		assert!(scanner.feed(&[0, 0, 0, 0]).is_none(), "truncated radiotap");
		assert!(scanner.is_empty());
	}

	#[test]
	fn a_frame_without_a_frequency_is_ignored() {
		let derivation = KeyDerivation::new(&keys(), 1).unwrap();
		let action = advertisement(1, FORMAT_AES_CTR)
			.encode(&derivation)
			.unwrap();

		let mut frame = Vec::new();
		frame.push(0);
		frame.push(0);
		frame.extend_from_slice(&8u16.to_le_bytes());
		frame.extend_from_slice(&0u32.to_le_bytes());
		frame.extend_from_slice(&action);

		let mut scanner = Scanner::new(&keys(), &[1]).unwrap();
		assert!(scanner.feed(&frame).is_none());
	}

	#[test]
	fn the_wrong_keys_find_nothing_rather_than_reporting_nonsense() {
		let real = KeyDerivation::new(&keys(), 1).unwrap();
		let host = MacAddress::parse("aa:bb:cc:dd:ee:01").unwrap();
		let action = advertisement(1, FORMAT_AES_CTR).encode(&real).unwrap();

		let other_keys = Keys::parse(&SAMPLE_KEYS.replace(
			"000102030405060708090a0b0c0d0e0f",
			"ffffffffffffffffffffffffffffffff",
		))
		.unwrap();

		let mut scanner = Scanner::new(&other_keys, &[1]).unwrap();
		assert!(scanner.feed(&air_frame(host, 6, &action)).is_none());
		assert!(scanner.is_empty());
	}

	#[test]
	fn scan_params_validate_channels_and_protocols() {
		assert!(ScanParams::default().check().is_ok());

		let bad_channel = ScanParams {
			channels: vec![3],
			..ScanParams::default()
		};
		assert!(bad_channel.check().unwrap_err().contains("invalid channel"));

		let no_channels = ScanParams {
			channels: vec![],
			..ScanParams::default()
		};
		assert!(no_channels.check().is_err());

		let bad_protocol = ScanParams {
			protocols: vec![2],
			..ScanParams::default()
		};
		assert!(bad_protocol.check().unwrap_err().contains("protocol"));
	}
}
