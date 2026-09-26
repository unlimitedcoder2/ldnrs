use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::accesspoint::{AccessPoint, AccessPointError, ApEvent};
use crate::advertisement::{
	ACCEPT_ALL, ACCEPT_BLACKLIST, ACCEPT_WHITELIST, ADVERTISEMENT_MAGIC, AdvertisementError,
	AdvertisementFrame, MAX_APPLICATION_DATA, MAX_PARTICIPANTS, NetworkId, NetworkInfo,
	PLATFORM_NX, ParticipantInfo, SECURITY_MODE_PROD,
};
use crate::authentication::{
	AUTH_CHALLENGE_FAILURE, AUTH_DENIED_BY_POLICY, AUTH_INVALID_VERSION, AUTH_MALFORMED_REQUEST,
	AUTH_SUCCESS, AUTH_UNEXPECTED, AuthError, AuthPayload, AuthenticationFrame,
	AuthenticationRequest, AuthenticationResponse, ChallengeRequest, ChallengeResponse,
	DisconnectFrame,
};
use crate::crypto::{KeyDerivation, KeyError, Keys};
use crate::monitor::{MonitorError, MonitorSource};
use crate::radio::{RadioError, Tuned, VifNames, add_neighbors, free_radio, tune_iface};
use crate::station::{Station, StationError};
use crate::sys::KernelContext;
use crate::wireless::Notification;
use crate::wlan::{ActionFrame, MacAddress, channel_band, frequency_channel, is_valid_channel};

pub const DISCONNECT_NETWORK_DESTROYED: u8 = 3;
pub const DISCONNECT_NETWORK_DESTROYED_FORCEFULLY: u8 = 4;
pub const DISCONNECT_STATION_REJECTED_BY_HOST: u8 = 5;
pub const DISCONNECT_CONNECTION_LOST: u8 = 6;

const AUTH_ATTEMPTS: u32 = 3;

const AUTH_RETRY_MS: u32 = 700;

const POLL_MS: u32 = 100;

const LISTED_TIMEOUT_MS: u32 = 1_000;

const JOIN_ATTEMPTS: u32 = 3;

const JOIN_SETTLE_MS: u64 = 1_500;

#[derive(Debug, Clone)]
pub struct ConnectParam {
	pub phyname: String,
	pub ifname: String,
	/// Left up through the join, where the sweep would otherwise take it down. While a monitor is
	/// up mac80211 never marks the radio idle, and idle is what makes rtw88 power the chip off:
	/// without one, the join powers it back on, firmware and all, for `if_up`, again for the scan
	/// and again for the association. Over `WinUSB` each power-on is ~6 s.
	pub ifname_monitor: String,
	pub password: Vec<u8>,
	pub name: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
	pub enable_challenge: bool,
	pub device_id: u64,
	/// Seeds the authentication key; must differ per join.
	pub client_random: [u8; 16],
	pub dev: bool,
	/// How long the caller will wait for the whole join, retries included.
	pub timeout_ms: Option<u32>,
}

impl Default for ConnectParam {
	fn default() -> Self {
		Self {
			phyname: "phy0".to_owned(),
			ifname: "ldn".to_owned(),
			ifname_monitor: "ldn-mon".to_owned(),
			password: Vec::new(),
			name: Vec::new(),
			app_version: 0,
			platform: PLATFORM_NX,
			enable_challenge: true,
			device_id: 0,
			client_random: [0; 16],
			dev: false,
			timeout_ms: None,
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkEvent {
	Join {
		index: usize,
		participant: Box<ParticipantInfo>,
	},
	Leave {
		index: usize,
		participant: Box<ParticipantInfo>,
	},
	Disconnect {
		reason: u8,
	},
	ApplicationDataChanged {
		old: Vec<u8>,
		new: Vec<u8>,
	},
	AcceptPolicyChanged {
		old: u8,
		new: u8,
	},
}

/// Metadata from the final LDN authentication attempt; contains no keys or frame payloads.
#[derive(Debug, Default)]
pub struct AuthDiagnostics {
	sent: u32,
	acknowledged: u32,
	not_acknowledged: u32,
	received: u32,
	last_received_len: usize,
	last_ignored: Option<String>,
}

#[derive(Debug)]
pub enum ConnectError {
	Radio(RadioError),
	Station(StationError),
	Auth(AuthError),
	Key(KeyError),
	Rejected { status: u8 },
	AuthTimeout(AuthDiagnostics),
	Disassociated,
	NotListed,
	NoAddress,
}

impl core::fmt::Display for ConnectError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Radio(err) => write!(f, "{err}"),
			Self::Station(err) => write!(f, "{err}"),
			Self::Auth(err) => write!(f, "{err}"),
			Self::Key(err) => write!(f, "{err}"),
			Self::Rejected { status } => write!(f, "the host refused the join (status {status})"),
			Self::AuthTimeout(trace) => write!(
				f,
				"LDN authentication timed out without a valid response; final attempt: sent={}, TX status ACK={}, no-ACK={}, control RX={}, last RX bytes={}, last ignored={}",
				trace.sent,
				trace.acknowledged,
				trace.not_acknowledged,
				trace.received,
				trace.last_received_len,
				trace.last_ignored.as_deref().unwrap_or("none"),
			),
			Self::Disassociated => write!(f, "the host dropped us during the join"),
			Self::NotListed => {
				write!(
					f,
					"authenticated, but the host never listed us as a participant"
				)
			}
			Self::NoAddress => write!(f, "the interface has no hardware address"),
		}
	}
}

impl core::error::Error for ConnectError {}

impl From<RadioError> for ConnectError {
	fn from(err: RadioError) -> Self {
		Self::Radio(err)
	}
}

impl From<StationError> for ConnectError {
	fn from(err: StationError) -> Self {
		Self::Station(err)
	}
}

impl From<AuthError> for ConnectError {
	fn from(err: AuthError) -> Self {
		Self::Auth(err)
	}
}

impl From<KeyError> for ConnectError {
	fn from(err: KeyError) -> Self {
		Self::Key(err)
	}
}

pub struct Network {
	station: Station,
	derivation: KeyDerivation,
	protocol: u8,
	info: NetworkInfo,
	client_random: [u8; 16],
	address: MacAddress,
	participant_id: usize,
	ctx: KernelContext,
	tuned: Tuned,
	events: VecDeque<NetworkEvent>,
	disconnected: bool,
}

impl Network {
	/// [`ConnectParam::timeout_ms`] bounds the whole thing, but loosely, and on purpose. It stops
	/// a *new* attempt being started once the caller has stopped waiting, and it shortens the waits
	/// that can be shortened safely. It does not cut an association short (see
	/// [`Station::set_deadline`]), so a join can overrun its budget by up to one
	/// association timeout. Overrunning is the lesser evil: the alternative orphans an association
	/// that then wedges the radio for everything that follows.
	///
	/// # Errors
	/// [`ConnectError`] describing the last attempt's failure.
	pub fn connect(
		ctx: KernelContext,
		keys: &Keys,
		network: &NetworkInfo,
		param: &ConnectParam,
	) -> Result<Self, ConnectError> {
		let deadline = param
			.timeout_ms
			.and_then(|ms| Instant::now().checked_add(Duration::from_millis(u64::from(ms))));

		let mut last = None;

		for attempt in 0..JOIN_ATTEMPTS {
			if attempt > 0 {
				if expired(deadline) {
					break;
				}

				std::thread::sleep(Duration::from_millis(JOIN_SETTLE_MS));

				if expired(deadline) {
					break;
				}
			}

			match Self::attempt(ctx, keys, network, param, deadline) {
				Ok(joined) => return Ok(joined),
				Err(err) => last = Some(err),
			}
		}

		Err(last.unwrap_or_else(|| ConnectError::AuthTimeout(AuthDiagnostics::default())))
	}

	fn attempt(
		ctx: KernelContext,
		keys: &Keys,
		network: &NetworkInfo,
		param: &ConnectParam,
		deadline: Option<Instant>,
	) -> Result<Self, ConnectError> {
		let names = VifNames::with(&[param.ifname.as_str()]);
		free_radio(ctx, &param.phyname, &names, Some(&param.ifname_monitor))?;

		let derivation = KeyDerivation::new(keys, network.protocol)?;

		// LDN has no key exchange: the link key comes from the host's advertisement and the game's
		// passphrase, and nothing on the wire says whether it was right.
		let link_key = network
			.is_encrypted()
			.then(|| derivation.data_key(&network.server_random, &param.password));

		let mut station = Station::create(ctx, &param.phyname, &param.ifname)?;
		station.set_deadline(deadline);
		let address = station.address().ok_or(ConnectError::NoAddress)?;

		let ssid = network.wlan_ssid();
		station.connect(
			ssid.as_bytes(),
			network.channel,
			link_key.as_ref().map(<[u8; 16]>::as_slice),
		)?;

		let protocol = network.protocol;

		let mut joined = Self {
			station,
			derivation,
			protocol,
			info: network.clone(),
			client_random: param.client_random,
			address,
			participant_id: 0,
			ctx,
			tuned: Tuned::default(),
			events: VecDeque::new(),
			disconnected: false,
		};

		joined.authenticate(param, deadline)?;
		joined.initialize(deadline)?;

		Ok(joined)
	}

	fn authenticate(
		&self,
		param: &ConnectParam,
		deadline: Option<Instant>,
	) -> Result<(), ConnectError> {
		let encoded = self.build_request(param)?;
		let host = self.info.address;
		let mut trace = AuthDiagnostics::default();

		for _ in 0..AUTH_ATTEMPTS {
			if expired(deadline) {
				break;
			}

			self.station.send_control_frame(host, &encoded)?;
			trace.sent += 1;

			let limit = remaining(deadline, AUTH_RETRY_MS);
			let started = Instant::now();
			while started.elapsed() < limit {
				match self.station.next_event(POLL_MS)? {
					Some(Notification::ControlPort { address, frame }) => {
						trace.received = trace.received.saturating_add(1);
						trace.last_received_len = frame.len();
						if self.check_response(address, &frame, &mut trace)? {
							return Ok(());
						}
					}
					Some(Notification::ControlPortTxStatus { acknowledged }) => {
						if acknowledged {
							trace.acknowledged = trace.acknowledged.saturating_add(1);
						} else {
							trace.not_acknowledged = trace.not_acknowledged.saturating_add(1);
						}
					}
					Some(Notification::DelStation { address }) if address == host => {
						return Err(ConnectError::Disassociated);
					}
					_ => {}
				}
			}
		}

		Err(ConnectError::AuthTimeout(trace))
	}

	fn build_request(&self, param: &ConnectParam) -> Result<Vec<u8>, ConnectError> {
		let challenge = if param.enable_challenge {
			let request = ChallengeRequest {
				flags: 0,
				token: self.info.challenge,
				nonce: u64::from_le_bytes(nonce_seed(&param.client_random)),
				device_id: param.device_id,
				..ChallengeRequest::default()
			};

			request.encode(&self.derivation.challenge_key(param.dev))
		} else {
			Vec::new()
		};

		let request = AuthenticationRequest {
			username: param.name.clone(),
			app_version: param.app_version,
			platform: param.platform,
			challenge,
		};

		let frame = AuthenticationFrame {
			version: self.info.version,
			status_code: 0,
			network_id: NetworkId {
				local_communication_id: self.info.local_communication_id,
				scene_id: self.info.scene_id,
				ssid: self.info.ssid,
			},
			server_random: self.info.server_random,
			client_random: self.client_random,
			payload: AuthPayload::Request(request),
		};

		Ok(frame.encode(&self.derivation, self.protocol)?)
	}

	fn check_response(
		&self,
		address: MacAddress,
		data: &[u8],
		trace: &mut AuthDiagnostics,
	) -> Result<bool, ConnectError> {
		if address != self.info.address {
			trace.last_ignored = Some("sender is not the selected host".to_owned());
			return Ok(false);
		}

		let frame = match AuthenticationFrame::decode(data, &self.derivation, self.protocol) {
			Ok(frame) => frame,
			Err(err) => {
				trace.last_ignored = Some(format!("decode: {err}"));
				return Ok(false);
			}
		};

		if !matches!(frame.payload, AuthPayload::Response(_)) {
			trace.last_ignored = Some("authentication request instead of response".to_owned());
			return Ok(false);
		}

		if frame.network_id.local_communication_id != self.info.local_communication_id
			|| frame.network_id.scene_id != self.info.scene_id
			|| frame.network_id.ssid != self.info.ssid
			|| frame.server_random != self.info.server_random
			|| frame.client_random != self.client_random
		{
			trace.last_ignored = Some("network or session identifiers do not match".to_owned());
			return Ok(false);
		}

		if frame.status_code != 0 {
			return Err(ConnectError::Rejected {
				status: frame.status_code,
			});
		}

		Ok(true)
	}

	fn initialize(&mut self, deadline: Option<Instant>) -> Result<(), ConnectError> {
		self.station.set_authorized()?;

		let limit = remaining(deadline, LISTED_TIMEOUT_MS);
		let started = Instant::now();

		while started.elapsed() < limit {
			let Some(notification) = self.station.next_event(POLL_MS)? else {
				continue;
			};

			let Some(info) = self.decode_advertisement(&notification) else {
				continue;
			};

			let Some(index) = find_participant(&info, self.address) else {
				continue;
			};

			self.participant_id = index;
			self.info = info;

			self.configure();

			return Ok(());
		}

		Err(ConnectError::NotListed)
	}

	fn configure(&mut self) {
		let Some(address) = self.local_address() else {
			return;
		};

		let ifindex = self.station.ifindex();

		match tune_iface(self.ctx, self.station.name(), ifindex, address) {
			Ok(tuned) => self.tuned = tuned,
			Err(_) => return,
		}

		// LDN peers never answer ARP, so every participant needs an entry of its own.
		let peers = self
			.info
			.participants
			.iter()
			.filter(|participant| participant.connected)
			.map(|participant| (participant.ip_address, participant.mac_address))
			.collect::<Vec<_>>();

		add_neighbors(self.ctx, ifindex, peers);
	}

	#[must_use]
	pub const fn tuned(&self) -> &Tuned {
		&self.tuned
	}

	/// **Join and leave are quantised to the advertisement interval**, because that is all a
	/// station has: the host publishes its participant table roughly every 100 ms and this diffs
	/// successive copies by MAC. Two changes to one slot inside a single interval are reported as
	/// one leave plus one join, and a slot whose occupant changes without its MAC changing is not
	/// reported at all. A host knows its own membership synchronously; a station cannot, and
	/// pretending otherwise would promise more than the radio can deliver.
	///
	/// # Errors
	/// [`ConnectError::Station`] if the socket fails.
	pub fn poll(&mut self, timeout_ms: u32) -> Result<Option<NetworkEvent>, ConnectError> {
		if let Some(event) = self.events.pop_front() {
			return Ok(Some(event));
		}

		let Some(notification) = self.station.next_event(timeout_ms)? else {
			return Ok(None);
		};

		match &notification {
			Notification::Frame { .. } => {
				if let Some(info) = self.decode_advertisement(&notification) {
					self.absorb(info);
				}
			}
			Notification::ControlPort { address, frame } => {
				if *address == self.info.address
					&& let Ok(disconnect) = DisconnectFrame::decode(frame)
				{
					self.disconnected = true;
					self.events.push_back(NetworkEvent::Disconnect {
						reason: disconnect.reason,
					});
				}
			}
			Notification::DelStation { address } if *address == self.info.address => {
				self.disconnected = true;
				self.events.push_back(NetworkEvent::Disconnect {
					reason: DISCONNECT_CONNECTION_LOST,
				});
			}
			_ => {}
		}

		Ok(self.events.pop_front())
	}

	fn decode_advertisement(&self, notification: &Notification) -> Option<NetworkInfo> {
		let Notification::Frame { frame, frequency } = notification else {
			return None;
		};

		// Frames arrive here through nl80211, so there is no radiotap header to strip; the
		// channel comes from the notification instead.
		let channel = frequency_channel((*frequency)?)?;

		let action = ActionFrame::decode(frame).ok()?;
		if action.source != self.info.address {
			return None;
		}
		if !action.action.starts_with(&ADVERTISEMENT_MAGIC) {
			return None;
		}

		let advertisement =
			AdvertisementFrame::decode(action.action, &self.derivation, self.protocol).ok()?;

		let info =
			NetworkInfo::from_advertisement(&advertisement, self.protocol, action.source, channel);

		self.info.is_same_network(&info).then_some(info)
	}

	fn absorb(&mut self, info: NetworkInfo) {
		if info.accept_policy != self.info.accept_policy {
			self.events.push_back(NetworkEvent::AcceptPolicyChanged {
				old: self.info.accept_policy,
				new: info.accept_policy,
			});
		}

		if info.application_data != self.info.application_data {
			self.events.push_back(NetworkEvent::ApplicationDataChanged {
				old: self.info.application_data.clone(),
				new: info.application_data.clone(),
			});
		}

		for index in 0..MAX_PARTICIPANTS {
			let (Some(old), Some(new)) = (
				self.info.participants.get(index),
				info.participants.get(index),
			) else {
				continue;
			};

			if old.connected && old.mac_address != new.mac_address {
				self.events.push_back(NetworkEvent::Leave {
					index,
					participant: Box::new(old.clone()),
				});
			}
		}

		for index in 0..MAX_PARTICIPANTS {
			let (Some(old), Some(new)) = (
				self.info.participants.get(index),
				info.participants.get(index),
			) else {
				continue;
			};

			if new.connected && old.mac_address != new.mac_address {
				self.events.push_back(NetworkEvent::Join {
					index,
					participant: Box::new(new.clone()),
				});
			}
		}

		self.info = info;
	}

	#[must_use]
	pub const fn info(&self) -> &NetworkInfo {
		&self.info
	}

	#[must_use]
	pub fn participant(&self) -> Option<&ParticipantInfo> {
		self.info.participants.get(self.participant_id)
	}

	#[must_use]
	pub const fn participant_index(&self) -> usize {
		self.participant_id
	}

	#[must_use]
	pub fn local_address(&self) -> Option<[u8; 4]> {
		self.participant().map(|participant| participant.ip_address)
	}

	#[must_use]
	pub const fn station(&self) -> &Station {
		&self.station
	}

	/// # Errors
	/// [`ConnectError::Station`] if the kernel refuses.
	pub fn disconnect(&mut self) -> Result<(), ConnectError> {
		self.disconnected = true;
		self.station.disconnect()?;

		Ok(())
	}
}

const ADVERTISEMENT_INTERVAL_MS: u64 = 100;

const HOST_CHANNELS: [u8; 3] = [1, 6, 11];

#[derive(Debug, Clone)]
pub struct CreateParam {
	pub phyname: String,
	pub ifname: String,
	pub phyname_monitor: String,
	pub ifname_monitor: String,
	pub local_communication_id: u64,
	pub scene_id: u16,
	pub max_participants: u8,
	/// Game-specific payload, at most [`MAX_APPLICATION_DATA`] bytes.
	pub application_data: Vec<u8>,
	pub accept_policy: u8,
	pub accept_filter: Vec<MacAddress>,
	pub security_mode: u16,
	/// The network's hidden id. Random when absent.
	pub ssid: Option<[u8; 16]>,
	pub name: Vec<u8>,
	pub app_version: u16,
	pub platform: u8,
	/// The channel to host on. Randomly chooses 1, 6, or 11 when absent.
	pub channel: Option<u8>,
	/// Seeds the data key. Random when absent.
	pub server_random: Option<[u8; 16]>,
	pub password: Vec<u8>,
	/// LDN version: 2, 3 or 4.
	pub version: u8,
	pub enable_challenge: bool,
	pub device_id: u64,
	/// LDN protocol: 1 or 3.
	pub protocol: u8,
	pub dev: bool,
}

impl Default for CreateParam {
	fn default() -> Self {
		Self {
			phyname: "phy0".to_owned(),
			ifname: "ldn".to_owned(),
			phyname_monitor: "phy0".to_owned(),
			ifname_monitor: "ldn-mon".to_owned(),
			local_communication_id: 0,
			scene_id: 0,
			max_participants: u8::try_from(MAX_PARTICIPANTS).unwrap_or(8),
			application_data: Vec::new(),
			accept_policy: ACCEPT_ALL,
			accept_filter: Vec::new(),
			security_mode: SECURITY_MODE_PROD,
			ssid: None,
			name: Vec::new(),
			app_version: 0,
			platform: PLATFORM_NX,
			channel: None,
			server_random: None,
			password: Vec::new(),
			version: 4,
			enable_challenge: true,
			device_id: 0,
			protocol: 1,
			dev: false,
		}
	}
}

impl CreateParam {
	/// # Errors
	/// [`CreateError::InvalidParam`] naming the field.
	pub fn check(&self) -> Result<(), CreateError> {
		if usize::from(self.max_participants) > MAX_PARTICIPANTS {
			return Err(CreateError::InvalidParam {
				reason: "max_participants is above 8",
			});
		}

		if self.application_data.len() > MAX_APPLICATION_DATA {
			return Err(CreateError::InvalidParam {
				reason: "application_data is larger than 0x180 bytes",
			});
		}

		if let Some(channel) = self.channel
			&& !is_valid_channel(channel)
		{
			return Err(CreateError::InvalidParam {
				reason: "channel is not a WLAN channel",
			});
		}

		if !matches!(self.version, 2..=4) {
			return Err(CreateError::InvalidParam {
				reason: "version must be 2, 3 or 4",
			});
		}

		if !matches!(self.protocol, 1 | 3) {
			return Err(CreateError::InvalidParam {
				reason: "protocol must be 1 or 3",
			});
		}

		Ok(())
	}
}

#[derive(Debug)]
pub enum CreateError {
	Radio(RadioError),
	AccessPoint(AccessPointError),
	Monitor(MonitorError),
	Auth(AuthError),
	Advertisement(AdvertisementError),
	Key(KeyError),
	Random,
	InvalidParam { reason: &'static str },
	NoParticipant { index: usize },
}

impl core::fmt::Display for CreateError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Radio(err) => write!(f, "{err}"),
			Self::AccessPoint(err) => write!(f, "{err}"),
			Self::Monitor(err) => write!(f, "{err}"),
			Self::Auth(err) => write!(f, "{err}"),
			Self::Advertisement(err) => write!(f, "{err}"),
			Self::Key(err) => write!(f, "{err}"),
			Self::Random => write!(f, "the operating system would not supply randomness"),
			Self::InvalidParam { reason } => write!(f, "{reason}"),
			Self::NoParticipant { index } => write!(f, "nobody is in slot {index}"),
		}
	}
}

impl core::error::Error for CreateError {}

impl From<RadioError> for CreateError {
	fn from(err: RadioError) -> Self {
		Self::Radio(err)
	}
}

impl From<AccessPointError> for CreateError {
	fn from(err: AccessPointError) -> Self {
		Self::AccessPoint(err)
	}
}

impl From<MonitorError> for CreateError {
	fn from(err: MonitorError) -> Self {
		Self::Monitor(err)
	}
}

impl From<AuthError> for CreateError {
	fn from(err: AuthError) -> Self {
		Self::Auth(err)
	}
}

impl From<AdvertisementError> for CreateError {
	fn from(err: AdvertisementError) -> Self {
		Self::Advertisement(err)
	}
}

impl From<KeyError> for CreateError {
	fn from(err: KeyError) -> Self {
		Self::Key(err)
	}
}

/// Hosts a network using an AP and a monitor interface.
///
/// The AP carries the network and its control port; the
/// monitor carries the advertisement, because an advertisement is a broadcast action frame from a
/// network nobody has joined yet and mac80211 will not transmit one from an AP vif. That is a real
/// constraint on the radio rather than an implementation detail: a phy whose interface
/// combinations do not allow AP plus monitor cannot host.
pub struct ApNetwork {
	access_point: AccessPoint,
	monitor: MonitorSource,
	derivation: KeyDerivation,
	protocol: u8,
	network: NetworkInfo,
	network_id: u8,
	advertisement_nonce: u32,
	accept_filter: Vec<MacAddress>,
	enable_challenge: bool,
	device_id: u64,
	platform: u8,
	dev: bool,
	ctx: KernelContext,
	tuned: Tuned,
	events: VecDeque<NetworkEvent>,
	last_advertisement: Instant,
	stopped: bool,
}

impl ApNetwork {
	/// # Errors
	/// [`CreateError`] describing which step failed.
	pub fn create(
		ctx: KernelContext,
		keys: &Keys,
		param: &CreateParam,
	) -> Result<Self, CreateError> {
		param.check()?;

		let ssid = match param.ssid {
			Some(ssid) => ssid,
			None => random_bytes()?,
		};
		let server_random = match param.server_random {
			Some(server_random) => server_random,
			None => random_bytes()?,
		};
		let channel = match param.channel {
			Some(channel) => channel,
			None => pick_channel()?,
		};

		let derivation = KeyDerivation::new(keys, param.protocol)?;

		let key = (param.security_mode == SECURITY_MODE_PROD)
			.then(|| derivation.data_key(&server_random, &param.password));

		let names = VifNames::with(&[param.ifname.as_str(), param.ifname_monitor.as_str()]);
		free_radio(ctx, &param.phyname, &names, None)?;

		let mut access_point = AccessPoint::create(ctx, &param.phyname, &param.ifname)?;
		let address = access_point.address();

		let network_id = random_network_id()?;
		let advertisement_nonce = random_u32()?;
		let challenge = if param.enable_challenge {
			random_u64()?
		} else {
			0
		};

		let network = build_network(
			param,
			address,
			channel,
			ssid,
			server_random,
			network_id,
			challenge,
			advertisement_nonce,
		);

		let wlan_ssid = network.wlan_ssid();

		access_point.start(
			wlan_ssid.as_bytes(),
			channel,
			key.as_ref().map(<[u8; 16]>::as_slice),
			usize::from(param.max_participants),
		)?;

		let monitor = MonitorSource::create(ctx, &param.phyname_monitor, &param.ifname_monitor)?;

		let mut hosted = Self {
			access_point,
			monitor,
			derivation,
			protocol: param.protocol,
			network,
			network_id,
			advertisement_nonce,
			accept_filter: param.accept_filter.clone(),
			enable_challenge: param.enable_challenge,
			device_id: param.device_id,
			platform: param.platform,
			dev: param.dev,
			ctx,
			tuned: Tuned::default(),
			events: VecDeque::new(),
			last_advertisement: Instant::now(),
			stopped: false,
		};

		hosted.configure();
		hosted.advertise()?;

		Ok(hosted)
	}

	fn configure(&mut self) {
		let Some(host) = self.network.participants.first() else {
			return;
		};

		let address = host.ip_address;
		let ifindex = self.access_point.ifindex();

		if let Ok(tuned) = tune_iface(self.ctx, self.access_point.name(), ifindex, address) {
			self.tuned = tuned;
		}
	}

	#[must_use]
	pub const fn tuned(&self) -> &Tuned {
		&self.tuned
	}

	/// # Errors
	/// [`CreateError`] if the frame cannot be encrypted or the monitor will not take it.
	pub fn advertise(&mut self) -> Result<(), CreateError> {
		let action = self
			.network
			.build_advertisement()
			.encode(&self.derivation)?;
		let frame = ActionFrame {
			source: self.network.address,
			action: &action,
		};

		self.monitor.send_frame(&frame.encode())?;
		self.last_advertisement = Instant::now();

		Ok(())
	}

	/// Waits up to `timeout_ms` for the next event, advertising as it goes.
	///
	/// The advertisement clock runs inside this call, so a host that stops polling stops
	/// advertising and its network disappears; there is no background thread keeping it alive. A
	/// caller with nothing else to do should poll continuously.
	///
	/// # Errors
	/// [`CreateError`] if the radio fails or a frame cannot be built.
	pub fn poll(&mut self, timeout_ms: u32) -> Result<Option<NetworkEvent>, CreateError> {
		if let Some(event) = self.events.pop_front() {
			return Ok(Some(event));
		}

		let timeout = Duration::from_millis(u64::from(timeout_ms));
		let interval = Duration::from_millis(ADVERTISEMENT_INTERVAL_MS);
		let started = Instant::now();

		loop {
			if self.last_advertisement.elapsed() >= interval {
				self.advertise()?;
			}

			let left = timeout.saturating_sub(started.elapsed());
			if left.is_zero() {
				return Ok(self.events.pop_front());
			}

			let until_advertisement = interval.saturating_sub(self.last_advertisement.elapsed());
			let slice = left.min(until_advertisement);
			let slice_ms = u32::try_from(slice.as_millis()).unwrap_or(u32::MAX).max(1);

			if let Some(event) = self.access_point.poll(slice_ms)? {
				self.handle(event)?;
			}

			if let Some(event) = self.events.pop_front() {
				return Ok(Some(event));
			}
		}
	}

	fn handle(&mut self, event: ApEvent) -> Result<(), CreateError> {
		match event {
			ApEvent::Associated { .. } => Ok(()),
			ApEvent::Left { address } => {
				self.remove_participant(address);
				Ok(())
			}
			ApEvent::ControlPort { address, frame } => self.handle_control_port(address, &frame),
		}
	}

	fn handle_control_port(&mut self, address: MacAddress, data: &[u8]) -> Result<(), CreateError> {
		if DisconnectFrame::decode(data).is_ok() {
			self.remove_participant(address);
			let _ = self.access_point.remove_station(address);

			return Ok(());
		}

		let Ok(frame) = AuthenticationFrame::decode(data, &self.derivation, self.protocol) else {
			return self.refuse(address, AUTH_MALFORMED_REQUEST, [0; 16]);
		};

		let status =
			check_authentication_request(&self.network, &self.accept_filter, address, &frame);

		let request = match &frame.payload {
			AuthPayload::Request(request) if status == AUTH_SUCCESS => request.clone(),
			_ => {
				let status = if status == AUTH_SUCCESS {
					AUTH_MALFORMED_REQUEST
				} else {
					status
				};

				return self.refuse(address, status, frame.client_random);
			}
		};

		let Some(challenge) = self.answer_challenge(&request.challenge) else {
			return self.refuse(address, AUTH_CHALLENGE_FAILURE, frame.client_random);
		};

		let Some(index) = allocate_slot(&self.network.participants, self.network.max_participants)
		else {
			return self.refuse(address, AUTH_UNEXPECTED, frame.client_random);
		};

		self.register(index, address, &request);
		self.reply(address, AUTH_SUCCESS, frame.client_random, challenge)?;

		// Only now. Authorizing opens the control port for ordinary data, and doing it before the
		// handshake completes would let a station that is about to be refused carry traffic.
		let _ = self.access_point.set_authorized(address);

		Ok(())
	}

	/// `Some(empty)` when the network does not use one, which is not the same as a failure.
	fn answer_challenge(&self, challenge: &[u8]) -> Option<Vec<u8>> {
		if !self.enable_challenge {
			return Some(Vec::new());
		}

		let key = self.derivation.challenge_key(self.dev);
		let request = ChallengeRequest::decode(challenge, &key).ok()?;

		if request.token != self.network.challenge {
			return None;
		}

		let response = ChallengeResponse {
			flags: 2,
			nonce: request.nonce,
			device_id: request.device_id,
			device_id_host: self.device_id,
			unk: request.unk,
			unk_host: [0; 16],
		};

		Some(response.encode(&key))
	}

	fn refuse(
		&self,
		address: MacAddress,
		status: u8,
		client_random: [u8; 16],
	) -> Result<(), CreateError> {
		self.reply(address, status, client_random, Vec::new())
	}

	fn reply(
		&self,
		address: MacAddress,
		status: u8,
		client_random: [u8; 16],
		challenge: Vec<u8>,
	) -> Result<(), CreateError> {
		let frame = AuthenticationFrame {
			version: self.network.version,
			status_code: status,
			network_id: NetworkId {
				local_communication_id: self.network.local_communication_id,
				scene_id: self.network.scene_id,
				ssid: self.network.ssid,
			},
			server_random: self.network.server_random,
			client_random,
			payload: AuthPayload::Response(AuthenticationResponse {
				platform: self.platform,
				challenge,
			}),
		};

		let encoded = frame.encode(&self.derivation, self.protocol)?;
		self.access_point.send_control_frame(address, &encoded)?;

		Ok(())
	}

	fn register(&mut self, index: usize, address: MacAddress, request: &AuthenticationRequest) {
		let octet = u8::try_from(index + 1).unwrap_or(1);

		let participant = ParticipantInfo {
			ip_address: [169, 254, self.network_id, octet],
			mac_address: address,
			connected: true,
			name: request.username.clone(),
			app_version: request.app_version,
			platform: request.platform,
		};

		let Some(slot) = self.network.participants.get_mut(index) else {
			return;
		};

		*slot = participant.clone();
		self.network.num_participants += 1;
		self.bump_nonce();

		add_neighbors(
			self.ctx,
			self.access_point.ifindex(),
			[(participant.ip_address, address)],
		);

		self.events.push_back(NetworkEvent::Join {
			index,
			participant: Box::new(participant),
		});
	}

	fn remove_participant(&mut self, address: MacAddress) {
		let Some(index) = find_connected(&self.network.participants, address) else {
			return;
		};

		let Some(slot) = self.network.participants.get_mut(index) else {
			return;
		};

		slot.connected = false;
		let participant = slot.clone();

		self.network.num_participants = self.network.num_participants.saturating_sub(1);
		self.bump_nonce();

		self.events.push_back(NetworkEvent::Leave {
			index,
			participant: Box::new(participant),
		});
	}

	/// Every change a host makes has to move this, because it is the only thing that tells a
	/// station a re-read advertisement is new rather than the same one heard twice.
	const fn bump_nonce(&mut self) {
		self.advertisement_nonce = self.advertisement_nonce.wrapping_add(1);
		self.network.nonce = self.advertisement_nonce.to_be_bytes();
	}

	/// # Errors
	/// [`CreateError::InvalidParam`] if it does not fit the advertisement.
	pub fn set_application_data(&mut self, data: &[u8]) -> Result<(), CreateError> {
		if data.len() > MAX_APPLICATION_DATA {
			return Err(CreateError::InvalidParam {
				reason: "application_data is larger than 0x180 bytes",
			});
		}

		self.network.application_data = data.to_vec();
		self.bump_nonce();

		Ok(())
	}

	pub const fn set_accept_policy(&mut self, policy: u8) {
		self.network.accept_policy = policy;
		self.bump_nonce();
	}

	/// No nonce bump, deliberately: the filter is the host's own business and is not advertised,
	/// so nothing a station can see has changed.
	pub fn set_accept_filter(&mut self, filter: Vec<MacAddress>) {
		self.accept_filter = filter;
	}

	#[must_use]
	pub fn accept_filter(&self) -> &[MacAddress] {
		&self.accept_filter
	}

	/// Told, then removed: the frame goes out while the station is still associated, because once
	/// the association is gone there is no way left to say why.
	///
	/// # Errors
	/// [`CreateError::InvalidParam`] for slot zero, [`CreateError::NoParticipant`] if the slot is
	/// empty, or [`CreateError::AccessPoint`] if the kernel refuses.
	pub fn kick(&mut self, index: usize) -> Result<(), CreateError> {
		check_kick(&self.network.participants, index)?;

		let Some(participant) = self.network.participants.get(index) else {
			return Err(CreateError::NoParticipant { index });
		};

		let address = participant.mac_address;
		let frame = DisconnectFrame {
			reason: DISCONNECT_STATION_REJECTED_BY_HOST,
		};

		let _ = self
			.access_point
			.send_control_frame(address, &frame.encode());
		self.access_point.remove_station(address)?;
		self.remove_participant(address);

		Ok(())
	}

	#[must_use]
	pub const fn info(&self) -> &NetworkInfo {
		&self.network
	}

	#[must_use]
	pub fn participant(&self) -> Option<&ParticipantInfo> {
		self.network.participants.first()
	}

	#[must_use]
	pub const fn is_stopped(&self) -> bool {
		self.stopped
	}

	#[must_use]
	pub const fn access_point(&self) -> &AccessPoint {
		&self.access_point
	}

	/// # Errors
	/// [`CreateError::AccessPoint`] if the kernel refuses to stop the AP. The notifications are
	/// best-effort: a station that cannot be told still finds out, one advertisement interval
	/// later, by not hearing one.
	pub fn close(&mut self) -> Result<(), CreateError> {
		if self.stopped {
			return Ok(());
		}

		self.stopped = true;

		let frame = DisconnectFrame {
			reason: DISCONNECT_NETWORK_DESTROYED,
		}
		.encode();

		let peers: Vec<MacAddress> = self
			.network
			.participants
			.iter()
			.skip(1)
			.filter(|participant| participant.connected)
			.map(|participant| participant.mac_address)
			.collect();

		for peer in peers {
			let _ = self.access_point.send_control_frame(peer, &frame);
		}

		self.access_point.stop()?;

		Ok(())
	}
}

impl Drop for ApNetwork {
	fn drop(&mut self) {
		let _ = self.close();
	}
}

#[allow(clippy::too_many_arguments)]
fn build_network(
	param: &CreateParam,
	address: MacAddress,
	channel: u8,
	ssid: [u8; 16],
	server_random: [u8; 16],
	network_id: u8,
	challenge: u64,
	nonce: u32,
) -> NetworkInfo {
	let host = ParticipantInfo {
		ip_address: [169, 254, network_id, 1],
		mac_address: address,
		connected: true,
		name: param.name.clone(),
		app_version: param.app_version,
		platform: param.platform,
	};

	let mut participants = vec![ParticipantInfo::default(); MAX_PARTICIPANTS];
	if let Some(slot) = participants.first_mut() {
		*slot = host;
	}

	NetworkInfo {
		protocol: param.protocol,
		address,
		band: channel_band(channel),
		channel,
		local_communication_id: param.local_communication_id,
		scene_id: param.scene_id,
		ssid,
		version: param.version,
		server_random,
		security_mode: param.security_mode,
		app_version: param.app_version,
		accept_policy: param.accept_policy,
		max_participants: param.max_participants,
		num_participants: 1,
		participants,
		application_data: param.application_data.clone(),
		challenge,
		nonce: nonce.to_be_bytes(),
	}
}

#[must_use]
pub fn check_accept_policy(policy: u8, filter: &[MacAddress], address: MacAddress) -> bool {
	match policy {
		ACCEPT_ALL => true,
		ACCEPT_BLACKLIST => !filter.contains(&address),
		ACCEPT_WHITELIST => filter.contains(&address),
		_ => false,
	}
}

#[must_use]
pub fn check_authentication_request(
	network: &NetworkInfo,
	filter: &[MacAddress],
	address: MacAddress,
	frame: &AuthenticationFrame,
) -> u8 {
	if !matches!(frame.version, 2..=4) {
		return AUTH_INVALID_VERSION;
	}

	if frame.status_code != 0
		|| frame.network_id.local_communication_id != network.local_communication_id
		|| frame.network_id.scene_id != network.scene_id
		|| frame.network_id.ssid != network.ssid
		|| frame.server_random != network.server_random
		|| !matches!(frame.payload, AuthPayload::Request(_))
	{
		return AUTH_MALFORMED_REQUEST;
	}

	if !check_accept_policy(network.accept_policy, filter, address) {
		return AUTH_DENIED_BY_POLICY;
	}

	AUTH_SUCCESS
}

#[must_use]
pub fn allocate_slot(participants: &[ParticipantInfo], max_participants: u8) -> Option<usize> {
	let limit = usize::from(max_participants).min(MAX_PARTICIPANTS);

	participants
		.iter()
		.take(limit)
		.position(|participant| !participant.connected)
}

/// # Errors
/// [`CreateError::InvalidParam`] for slot zero, or [`CreateError::NoParticipant`] for a slot that
/// is out of range or empty.
pub fn check_kick(participants: &[ParticipantInfo], index: usize) -> Result<(), CreateError> {
	if index == 0 {
		return Err(CreateError::InvalidParam {
			reason: "slot 0 is the host and cannot be kicked",
		});
	}

	let Some(participant) = participants.get(index) else {
		return Err(CreateError::NoParticipant { index });
	};

	if !participant.connected {
		return Err(CreateError::NoParticipant { index });
	}

	Ok(())
}

#[must_use]
pub fn find_connected(participants: &[ParticipantInfo], address: MacAddress) -> Option<usize> {
	participants
		.iter()
		.position(|participant| participant.connected && participant.mac_address == address)
}

fn random_bytes() -> Result<[u8; 16], CreateError> {
	let mut bytes = [0u8; 16];
	getrandom::fill(&mut bytes).map_err(|_| CreateError::Random)?;

	Ok(bytes)
}

fn random_u32() -> Result<u32, CreateError> {
	getrandom::u32().map_err(|_| CreateError::Random)
}

fn random_u64() -> Result<u64, CreateError> {
	getrandom::u64().map_err(|_| CreateError::Random)
}

/// A network id in 1..=127, which is the third octet of every address on the network.
fn random_network_id() -> Result<u8, CreateError> {
	let mut byte = [0u8; 1];
	getrandom::fill(&mut byte).map_err(|_| CreateError::Random)?;

	Ok(network_id_from(byte.first().copied().unwrap_or(0)))
}

const fn network_id_from(byte: u8) -> u8 {
	(byte % 127) + 1
}

fn pick_channel() -> Result<u8, CreateError> {
	let mut byte = [0u8; 1];
	getrandom::fill(&mut byte).map_err(|_| CreateError::Random)?;

	let index = usize::from(byte.first().copied().unwrap_or(0))
		.checked_rem(HOST_CHANNELS.len())
		.unwrap_or(0);

	Ok(HOST_CHANNELS.get(index).copied().unwrap_or(1))
}

fn expired(deadline: Option<Instant>) -> bool {
	deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn remaining(deadline: Option<Instant>, own_ms: u32) -> Duration {
	let own = Duration::from_millis(u64::from(own_ms));

	deadline.map_or(own, |deadline| {
		own.min(deadline.saturating_duration_since(Instant::now()))
	})
}

fn find_participant(info: &NetworkInfo, address: MacAddress) -> Option<usize> {
	info.participants
		.iter()
		.position(|participant| participant.mac_address == address)
}

fn nonce_seed(client_random: &[u8; 16]) -> [u8; 8] {
	let mut seed = [0u8; 8];
	if let Some(front) = client_random.get(..8) {
		seed.copy_from_slice(front);
	}

	seed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
	use super::{
		ConnectParam, CreateError, MAX_PARTICIPANTS, check_kick, find_participant, nonce_seed,
	};
	use crate::advertisement::{NetworkInfo, ParticipantInfo};
	use crate::wlan::MacAddress;

	fn network_with(macs: &[[u8; 6]]) -> NetworkInfo {
		let participants = (0..MAX_PARTICIPANTS)
			.map(|index| {
				macs.get(index)
					.map_or_else(ParticipantInfo::default, |mac| ParticipantInfo {
						mac_address: MacAddress(*mac),
						connected: true,
						ip_address: [169, 254, 7, u8::try_from(index).unwrap_or(0) + 1],
						..ParticipantInfo::default()
					})
			})
			.collect();

		NetworkInfo {
			participants,
			..NetworkInfo::default()
		}
	}

	#[test]
	fn a_station_finds_itself_by_mac() {
		let info = network_with(&[[1; 6], [2; 6], [3; 6]]);

		assert_eq!(find_participant(&info, MacAddress([2; 6])), Some(1));
		assert_eq!(find_participant(&info, MacAddress([9; 6])), None);
	}

	#[test]
	fn the_default_parameters_ask_for_the_challenge() {
		let param = ConnectParam::default();

		assert!(param.enable_challenge);
		assert_eq!(param.phyname, "phy0");
		assert!(
			param.password.is_empty(),
			"a password is the caller's to supply"
		);
	}

	#[test]
	fn the_nonce_seed_takes_the_first_eight_bytes_of_the_client_random() {
		let client_random: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap_or(0));

		assert_eq!(nonce_seed(&client_random), [0, 1, 2, 3, 4, 5, 6, 7]);
	}

	#[test]
	fn a_kick_refuses_the_host_its_own_slot() {
		let info = network_with(&[[1; 6], [2; 6], [3; 6]]);

		assert!(matches!(
			check_kick(&info.participants, 0),
			Err(CreateError::InvalidParam { .. })
		));

		assert!(check_kick(&info.participants, 1).is_ok());
		assert!(check_kick(&info.participants, 2).is_ok());
	}

	#[test]
	fn a_kick_refuses_an_empty_or_absent_slot() {
		let info = network_with(&[[1; 6], [2; 6]]);

		assert!(matches!(
			check_kick(&info.participants, 5),
			Err(CreateError::NoParticipant { index: 5 })
		));
		assert!(matches!(
			check_kick(&info.participants, MAX_PARTICIPANTS),
			Err(CreateError::NoParticipant { .. })
		));
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
		ACCEPT_ALL, ACCEPT_BLACKLIST, ACCEPT_WHITELIST, AUTH_DENIED_BY_POLICY,
		AUTH_INVALID_VERSION, AUTH_MALFORMED_REQUEST, AUTH_SUCCESS, AuthPayload,
		AuthenticationFrame, AuthenticationRequest, AuthenticationResponse, CreateParam,
		MAX_APPLICATION_DATA, MAX_PARTICIPANTS, NetworkId, NetworkInfo, ParticipantInfo,
		allocate_slot, build_network, check_accept_policy, check_authentication_request,
		find_connected, network_id_from,
	};
	use crate::advertisement::ACCEPT_NONE;
	use crate::wlan::MacAddress;

	const ACCEPT_UNKNOWN: u8 = 200;

	fn station(last: u8) -> MacAddress {
		MacAddress([6, 0, 0, 0, 0, last])
	}

	fn hosted() -> NetworkInfo {
		let param = CreateParam {
			local_communication_id: 0x0100_0000_0000_1234,
			scene_id: 7,
			name: b"host".to_vec(),
			..CreateParam::default()
		};

		build_network(&param, station(1), 6, [0xAA; 16], [0xBB; 16], 42, 0x1234, 9)
	}

	fn request_for(network: &NetworkInfo) -> AuthenticationFrame {
		AuthenticationFrame {
			version: network.version,
			status_code: 0,
			network_id: NetworkId {
				local_communication_id: network.local_communication_id,
				scene_id: network.scene_id,
				ssid: network.ssid,
			},
			server_random: network.server_random,
			client_random: [0x11; 16],
			payload: AuthPayload::Request(AuthenticationRequest {
				username: b"player".to_vec(),
				app_version: 1,
				platform: 0,
				challenge: Vec::new(),
			}),
		}
	}

	fn occupy(network: &mut NetworkInfo, index: usize, address: MacAddress) {
		network.participants[index] = ParticipantInfo {
			ip_address: [169, 254, 42, u8::try_from(index).unwrap() + 1],
			mac_address: address,
			connected: true,
			..ParticipantInfo::default()
		};
	}

	#[test]
	fn a_new_network_lists_only_its_host() {
		let network = hosted();

		assert_eq!(network.num_participants, 1);
		assert_eq!(
			network.participants.len(),
			MAX_PARTICIPANTS,
			"every slot goes on the wire, occupied or not"
		);
		assert_eq!(network.participants[0].ip_address, [169, 254, 42, 1]);
		assert!(network.participants[0].connected);
		assert!(!network.participants[1].connected);

		assert_eq!(network.nonce, [0, 0, 0, 9]);
	}

	#[test]
	fn the_advertised_ssid_is_the_hex_form_of_the_hidden_one() {
		let network = hosted();

		assert_eq!(network.wlan_ssid().len(), 32);
		assert_eq!(network.wlan_ssid(), "a".repeat(32));
	}

	#[test]
	fn an_advertisement_round_trips_through_the_network_it_describes() {
		let network = hosted();
		let frame = network.build_advertisement();

		assert_eq!(
			frame.network_id.local_communication_id,
			network.local_communication_id
		);
		assert_eq!(frame.network_id.ssid, network.ssid);
		assert_eq!(frame.nonce, network.nonce);
		assert_eq!(frame.payload.server_random, network.server_random);
		assert_eq!(frame.payload.num_participants, 1);
		assert_eq!(frame.payload.challenge, 0x1234);
		assert_eq!(frame.payload.channel, 6);
	}

	#[test]
	fn every_policy_answers_the_same_way_it_reads() {
		let filter = [station(1), station(2)];

		assert!(check_accept_policy(ACCEPT_ALL, &filter, station(9)));
		assert!(!check_accept_policy(ACCEPT_NONE, &filter, station(9)));

		assert!(!check_accept_policy(ACCEPT_BLACKLIST, &filter, station(1)));
		assert!(check_accept_policy(ACCEPT_BLACKLIST, &filter, station(9)));

		assert!(check_accept_policy(ACCEPT_WHITELIST, &filter, station(1)));
		assert!(!check_accept_policy(ACCEPT_WHITELIST, &filter, station(9)));
	}

	#[test]
	fn a_policy_this_build_does_not_know_admits_nobody() {
		assert!(!check_accept_policy(ACCEPT_UNKNOWN, &[], station(1)));
	}

	#[test]
	fn a_matching_request_is_accepted() {
		let network = hosted();

		assert_eq!(
			check_authentication_request(&network, &[], station(9), &request_for(&network)),
			AUTH_SUCCESS
		);
	}

	#[test]
	fn a_request_for_another_network_is_malformed_rather_than_ignored() {
		let network = hosted();

		let mut wrong_game = request_for(&network);
		wrong_game.network_id.local_communication_id = 1;
		assert_eq!(
			check_authentication_request(&network, &[], station(9), &wrong_game),
			AUTH_MALFORMED_REQUEST
		);

		let mut wrong_scene = request_for(&network);
		wrong_scene.network_id.scene_id = 99;
		assert_eq!(
			check_authentication_request(&network, &[], station(9), &wrong_scene),
			AUTH_MALFORMED_REQUEST
		);

		let mut wrong_session = request_for(&network);
		wrong_session.server_random = [0xCC; 16];
		assert_eq!(
			check_authentication_request(&network, &[], station(9), &wrong_session),
			AUTH_MALFORMED_REQUEST
		);
	}

	#[test]
	fn a_response_arriving_where_a_request_belongs_is_refused() {
		let network = hosted();

		let mut frame = request_for(&network);
		frame.payload = AuthPayload::Response(AuthenticationResponse::default());

		assert_eq!(
			check_authentication_request(&network, &[], station(9), &frame),
			AUTH_MALFORMED_REQUEST
		);
	}

	#[test]
	fn the_version_is_checked_before_anything_else() {
		let network = hosted();

		let mut frame = request_for(&network);
		frame.version = 1;
		frame.network_id.scene_id = 99;

		assert_eq!(
			check_authentication_request(&network, &[], station(9), &frame),
			AUTH_INVALID_VERSION
		);
	}

	#[test]
	fn the_policy_is_checked_last() {
		let mut network = hosted();
		network.accept_policy = ACCEPT_WHITELIST;

		assert_eq!(
			check_authentication_request(&network, &[], station(9), &request_for(&network)),
			AUTH_DENIED_BY_POLICY
		);

		assert_eq!(
			check_authentication_request(
				&network,
				&[station(9)],
				station(9),
				&request_for(&network)
			),
			AUTH_SUCCESS
		);
	}

	#[test]
	fn slots_are_allocated_lowest_first_and_reused() {
		let mut network = hosted();
		occupy(&mut network, 1, station(2));
		occupy(&mut network, 3, station(4));

		assert_eq!(allocate_slot(&network.participants, 8), Some(2));

		network.participants[1].connected = false;
		assert_eq!(allocate_slot(&network.participants, 8), Some(1));
	}

	#[test]
	fn a_full_network_has_no_slot_to_give() {
		let mut network = hosted();
		for index in 1..MAX_PARTICIPANTS {
			occupy(&mut network, index, station(u8::try_from(index).unwrap()));
		}

		assert_eq!(allocate_slot(&network.participants, 8), None);
	}

	#[test]
	fn max_participants_caps_the_search_short_of_the_table() {
		let mut network = hosted();
		occupy(&mut network, 1, station(2));

		assert_eq!(allocate_slot(&network.participants, 2), None);
		assert_eq!(allocate_slot(&network.participants, 3), Some(2));
	}

	#[test]
	fn a_station_is_found_only_while_it_is_connected() {
		let mut network = hosted();
		occupy(&mut network, 2, station(5));

		assert_eq!(find_connected(&network.participants, station(5)), Some(2));

		network.participants[2].connected = false;
		assert_eq!(
			find_connected(&network.participants, station(5)),
			None,
			"a slot that has been left still holds the old address"
		);
	}

	#[test]
	fn a_network_id_is_always_in_the_range_an_address_can_hold() {
		for byte in 0..=u8::MAX {
			let id = network_id_from(byte);

			assert!(id >= 1 && id <= 127, "byte {byte} produced network id {id}");
		}
	}

	#[test]
	fn the_parameters_that_would_produce_an_unjoinable_network_are_refused() {
		assert!(CreateParam::default().check().is_ok());

		let too_many = CreateParam {
			max_participants: 9,
			..CreateParam::default()
		};
		assert!(too_many.check().is_err());

		let too_much_data = CreateParam {
			application_data: vec![0; MAX_APPLICATION_DATA + 1],
			..CreateParam::default()
		};
		assert!(too_much_data.check().is_err());

		let bad_channel = CreateParam {
			channel: Some(2),
			..CreateParam::default()
		};
		assert!(bad_channel.check().is_err());

		let bad_version = CreateParam {
			version: 5,
			..CreateParam::default()
		};
		assert!(bad_version.check().is_err());

		let bad_protocol = CreateParam {
			protocol: 2,
			..CreateParam::default()
		};
		assert!(bad_protocol.check().is_err());
	}
}
