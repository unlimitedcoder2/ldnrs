use std::collections::BTreeMap;

use crate::iface::{IfaceError, checked_ifindex, disable_ipv6, ensure_interface, wiphy_index};
use crate::sys::{KernelContext, if_down, if_up};
use crate::wireless::Wireless;
use crate::wireless::{KEY_INDEX_UNICAST, NL80211_IFTYPE_AP, Notification};
use crate::wlan::{
	AssociationRequest, Authentication80211, Disassociation, MacAddress, ProbeRequest,
	STYPE_ASSOC_REQ, STYPE_AUTH, STYPE_DEAUTH, STYPE_DISASSOC, STYPE_PROBE_REQ,
	WLAN_EID_SUPP_RATES, association_error, association_response, beacon_head, beacon_tail,
	channel_frequency, probe_response,
};

pub const WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA: u16 = 17;

pub const WLAN_STATUS_ASSOC_DENIED_UNSPEC: u16 = 1;

const REGISTERED_SUBTYPES: [u8; 5] = [
	STYPE_ASSOC_REQ,
	STYPE_PROBE_REQ,
	STYPE_DISASSOC,
	STYPE_AUTH,
	STYPE_DEAUTH,
];

#[derive(Debug)]
pub enum AccessPointError {
	Iface(IfaceError),
	Sys(crate::sys::SysError),
	BadChannel { channel: u8 },
	NoAddress,
	NotStarted,
}

impl core::fmt::Display for AccessPointError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Iface(err) => write!(f, "{err}"),
			Self::Sys(err) => write!(f, "{err}"),
			Self::BadChannel { channel } => write!(f, "channel {channel} is not an LDN channel"),
			Self::NoAddress => write!(f, "the interface has no address to use as a BSSID"),
			Self::NotStarted => write!(f, "no network is being hosted"),
		}
	}
}

impl core::error::Error for AccessPointError {}

impl From<IfaceError> for AccessPointError {
	fn from(err: IfaceError) -> Self {
		Self::Iface(err)
	}
}

impl From<crate::sys::SysError> for AccessPointError {
	fn from(err: crate::sys::SysError) -> Self {
		Self::Sys(err)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApEvent {
	Associated { address: MacAddress, aid: u16 },
	Left { address: MacAddress },
	ControlPort { address: MacAddress, frame: Vec<u8> },
}

/// Dropping this explicitly stops the AP held by cfg80211.
pub struct AccessPoint {
	ctx: KernelContext,
	wireless: Wireless,
	ifindex: i32,
	address: MacAddress,
	name: String,
	ssid: Vec<u8>,
	channel: u8,
	key: Option<Vec<u8>>,
	max_stations: usize,
	started: bool,
	stations: BTreeMap<u16, MacAddress>,
}

impl AccessPoint {
	/// # Errors
	/// [`AccessPointError`] if the phy is missing or the kernel refuses a step.
	pub fn create(
		ctx: KernelContext,
		phyname: &str,
		ifname: &str,
	) -> Result<Self, AccessPointError> {
		let wireless = Wireless::lkl(ctx);

		let wiphy = wiphy_index(&wireless, phyname)?;
		let interface = ensure_interface(&wireless, wiphy, ifname, NL80211_IFTYPE_AP, false)?;

		let ifindex = checked_ifindex(interface.index)?;
		let address = interface.mac.ok_or(AccessPointError::NoAddress)?;

		disable_ipv6(ctx, ifname);
		if_up(ctx, ifindex)?;

		Ok(Self {
			ctx,
			wireless,
			ifindex,
			address,
			name: ifname.to_owned(),
			ssid: Vec::new(),
			channel: 0,
			key: None,
			max_stations: 0,
			started: false,
			stations: BTreeMap::new(),
		})
	}

	#[must_use]
	pub const fn ifindex(&self) -> i32 {
		self.ifindex
	}

	#[must_use]
	pub fn name(&self) -> &str {
		&self.name
	}

	#[must_use]
	pub const fn address(&self) -> MacAddress {
		self.address
	}

	/// `ssid` is the **hex form** of the network's 16-byte id (32 ASCII characters) because that
	/// is what goes on the air. See [`crate::wireless::Wireless::start_ap`].
	///
	/// `key` is the network's CCMP key. When it is `Some`, it is installed as the group key *and*
	/// defaulted for multicast, because a key that is installed and not defaulted is never used and
	/// every broadcast then goes out in the clear.
	///
	/// # Errors
	/// [`AccessPointError`] if the channel is not an LDN one or the kernel refuses a step.
	pub fn start(
		&mut self,
		ssid: &[u8],
		channel: u8,
		key: Option<&[u8]>,
		max_stations: usize,
	) -> Result<(), AccessPointError> {
		let frequency =
			channel_frequency(channel).ok_or(AccessPointError::BadChannel { channel })?;

		let ifindex = self.ifindex_u32();
		let head = beacon_head(self.address);
		let tail = beacon_tail();

		self.wireless
			.start_ap(ifindex, ssid, self.address, frequency, &head, &tail)?;

		if let Some(key) = key {
			self.wireless.new_group_key(ifindex, key)?;
			self.wireless.set_default_group_key(ifindex)?;
		}

		for subtype in REGISTERED_SUBTYPES {
			self.wireless.register_frame(ifindex, subtype)?;
		}

		self.ssid = ssid.to_vec();
		self.channel = channel;
		self.key = key.map(<[u8]>::to_vec);
		self.max_stations = max_stations;
		self.started = true;

		Ok(())
	}

	/// # Errors
	/// [`AccessPointError`] if the socket fails or a notification is malformed.
	pub fn poll(&mut self, timeout_ms: u32) -> Result<Option<ApEvent>, AccessPointError> {
		let Some(notification) = self.wireless.next_notification(timeout_ms)? else {
			return Ok(None);
		};

		match notification {
			Notification::Frame { frame, .. } => self.handle_management(&frame),
			Notification::ControlPort { address, frame } => {
				Ok(Some(ApEvent::ControlPort { address, frame }))
			}
			Notification::DelStation { address } => {
				self.forget(address);
				Ok(Some(ApEvent::Left { address }))
			}
			_ => Ok(None),
		}
	}

	fn handle_management(&mut self, frame: &[u8]) -> Result<Option<ApEvent>, AccessPointError> {
		if let Ok(probe) = ProbeRequest::decode(frame) {
			if probe.ssid() == Some(self.ssid.as_slice()) {
				let response = probe_response(
					self.address,
					probe.source,
					&self.ssid,
					self.channel,
					self.key.is_some(),
				);

				self.send_frame(&response)?;
			}

			return Ok(None);
		}

		if let Ok(auth) = Authentication80211::decode(frame) {
			// Open-system authentication authenticates nothing; the real check is LDN's own
			// handshake over the control port, which happens after the association.
			if auth.bssid == self.address && auth.is_open_request() {
				let response = Authentication80211::accept(self.address, auth.source);
				self.send_frame(&response)?;
			}

			return Ok(None);
		}

		if let Ok(request) = AssociationRequest::decode(frame) {
			return self.handle_association(&request);
		}

		if let Ok(disassociation) = Disassociation::decode(frame) {
			return Ok(self.handle_disassociation(disassociation.source));
		}

		Ok(None)
	}

	fn handle_association(
		&mut self,
		request: &AssociationRequest,
	) -> Result<Option<ApEvent>, AccessPointError> {
		let (aid, rates) = match decide_association(&self.stations, self.max_stations, request) {
			AssociationDecision::Repeat { aid } => {
				let response = association_response(self.address, request.source, aid);
				self.send_frame(&response)?;

				return Ok(None);
			}
			AssociationDecision::Refuse { status } => {
				let response = association_error(self.address, request.source, status);
				self.send_frame(&response)?;

				return Ok(None);
			}
			AssociationDecision::Admit { aid } => {
				let rates = element(&request.elements, WLAN_EID_SUPP_RATES).unwrap_or(&[]);
				(aid, rates.to_vec())
			}
		};

		self.wireless.new_station(
			self.ifindex_u32(),
			request.source,
			aid,
			request.listen_interval,
			request.capability_information,
			&rates,
		)?;

		if let Some(key) = self.key.clone() {
			self.wireless.new_key(
				self.ifindex_u32(),
				KEY_INDEX_UNICAST,
				&key,
				Some(request.source),
			)?;
		}

		self.stations.insert(aid, request.source);

		let response = association_response(self.address, request.source, aid);
		self.send_frame(&response)?;

		Ok(Some(ApEvent::Associated {
			address: request.source,
			aid,
		}))
	}

	fn handle_disassociation(&mut self, address: MacAddress) -> Option<ApEvent> {
		self.aid_of(address)?;

		self.forget(address);
		let _ = self.remove_station(address);

		Some(ApEvent::Left { address })
	}

	/// # Errors
	/// [`AccessPointError::Sys`] if the kernel refuses.
	pub fn remove_station(&mut self, address: MacAddress) -> Result<(), AccessPointError> {
		self.forget(address);

		self.wireless.del_station(self.ifindex_u32(), address)?;

		Ok(())
	}

	/// # Errors
	/// [`AccessPointError::NotStarted`] if nothing is being hosted, or
	/// [`AccessPointError::Sys`] if the kernel refuses.
	pub fn send_control_frame(
		&self,
		address: MacAddress,
		frame: &[u8],
	) -> Result<(), AccessPointError> {
		if !self.started {
			return Err(AccessPointError::NotStarted);
		}

		self.wireless
			.control_port_frame(self.ifindex_u32(), address, frame)?;

		Ok(())
	}

	/// # Errors
	/// [`AccessPointError::Sys`] if the kernel refuses.
	pub fn set_authorized(&self, address: MacAddress) -> Result<(), AccessPointError> {
		self.wireless
			.set_station_authorized(self.ifindex_u32(), address)?;

		Ok(())
	}

	fn send_frame(&self, frame: &[u8]) -> Result<(), AccessPointError> {
		self.wireless.frame(self.ifindex_u32(), frame)?;

		Ok(())
	}

	fn aid_of(&self, address: MacAddress) -> Option<u16> {
		aid_of(&self.stations, address)
	}

	fn forget(&mut self, address: MacAddress) {
		self.stations.retain(|_, station| *station != address);
	}

	/// # Errors
	/// [`AccessPointError::Sys`] if the kernel refuses.
	pub fn stop(&mut self) -> Result<(), AccessPointError> {
		if !self.started {
			return Ok(());
		}

		self.wireless.stop_ap(self.ifindex_u32())?;

		self.started = false;
		self.stations.clear();

		// As with a station: stopping is not enough to free the radio. An interface that is merely
		// stopped is still up and still owns a channel, so the next `SET_CHANNEL` on this phy fails
		// with `EBUSY`. The vif is kept deliberately, so the next network reuses it.
		let _ = if_down(self.ctx, self.ifindex);

		Ok(())
	}

	fn ifindex_u32(&self) -> u32 {
		u32::try_from(self.ifindex).unwrap_or(0)
	}
}

impl Drop for AccessPoint {
	fn drop(&mut self) {
		// On the netlink backend this is a formality: the socket closing is what stops the network,
		// because `START_AP` was sent with `SOCKET_OWNER`. On the direct backend nothing closes, so
		// a failure here leaves a phantom AP beaconing. Worth saying out loud.
		if let Err(err) = self.stop() {
			println!("accesspoint: could not stop the network on drop: {err}");
		}
	}
}

fn element(elements: &[(u8, Vec<u8>)], id: u8) -> Option<&[u8]> {
	elements
		.iter()
		.find(|(element_id, _)| *element_id == id)
		.map(|(_, value)| value.as_slice())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssociationDecision {
	Admit { aid: u16 },
	Repeat { aid: u16 },
	Refuse { status: u16 },
}

#[must_use]
pub fn decide_association(
	stations: &BTreeMap<u16, MacAddress>,
	max_stations: usize,
	request: &AssociationRequest,
) -> AssociationDecision {
	if let Some(aid) = aid_of(stations, request.source) {
		return AssociationDecision::Repeat { aid };
	}

	if stations.len() >= max_stations {
		return AssociationDecision::Refuse {
			status: WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA,
		};
	}

	// The driver refuses a station whose rates it was not told about, so a request that omits them
	// cannot be admitted at all; better to say so than to admit it and have its traffic dropped.
	if element(&request.elements, WLAN_EID_SUPP_RATES).is_none() {
		return AssociationDecision::Refuse {
			status: WLAN_STATUS_ASSOC_DENIED_UNSPEC,
		};
	}

	AssociationDecision::Admit {
		aid: next_aid(stations),
	}
}

fn aid_of(stations: &BTreeMap<u16, MacAddress>, address: MacAddress) -> Option<u16> {
	stations
		.iter()
		.find(|(_, station)| **station == address)
		.map(|(aid, _)| *aid)
}

fn next_aid(stations: &BTreeMap<u16, MacAddress>) -> u16 {
	let mut aid = 1u16;
	while stations.contains_key(&aid) {
		aid += 1;
	}

	aid
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
	use super::{
		AssociationDecision, MacAddress, WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA,
		WLAN_STATUS_ASSOC_DENIED_UNSPEC, decide_association, next_aid,
	};
	use crate::wlan::{AssociationRequest, WLAN_EID_SUPP_RATES};
	use std::collections::BTreeMap;

	const RATES: [u8; 4] = [0x82, 0x84, 0x8B, 0x96];

	fn station(last: u8) -> MacAddress {
		MacAddress([6, 0, 0, 0, 0, last])
	}

	fn request(from: MacAddress, rates: bool) -> AssociationRequest {
		AssociationRequest {
			target: MacAddress::ZERO,
			source: from,
			capability_information: 0x0431,
			listen_interval: 10,
			elements: if rates {
				vec![(WLAN_EID_SUPP_RATES, RATES.to_vec())]
			} else {
				Vec::new()
			},
		}
	}

	#[test]
	fn an_empty_network_admits_the_first_station_as_aid_one() {
		let stations = BTreeMap::new();

		assert_eq!(
			decide_association(&stations, 8, &request(station(1), true)),
			AssociationDecision::Admit { aid: 1 }
		);
	}

	#[test]
	fn a_repeat_request_gets_the_id_it_already_has() {
		let mut stations = BTreeMap::new();
		stations.insert(3u16, station(1));

		assert_eq!(
			decide_association(&stations, 8, &request(station(1), true)),
			AssociationDecision::Repeat { aid: 3 }
		);
	}

	#[test]
	fn a_full_network_refuses_rather_than_ignoring() {
		let mut stations = BTreeMap::new();
		for index in 1..=8u16 {
			stations.insert(index, station(u8::try_from(index).unwrap()));
		}

		assert_eq!(
			decide_association(&stations, 8, &request(station(9), true)),
			AssociationDecision::Refuse {
				status: WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA
			}
		);
	}

	#[test]
	fn a_request_without_rates_is_refused() {
		let stations = BTreeMap::new();

		assert_eq!(
			decide_association(&stations, 8, &request(station(1), false)),
			AssociationDecision::Refuse {
				status: WLAN_STATUS_ASSOC_DENIED_UNSPEC
			}
		);
	}

	#[test]
	fn a_full_network_still_answers_a_station_it_already_has() {
		let mut stations = BTreeMap::new();
		for index in 1..=8u16 {
			stations.insert(index, station(u8::try_from(index).unwrap()));
		}

		assert_eq!(
			decide_association(&stations, 8, &request(station(4), true)),
			AssociationDecision::Repeat { aid: 4 }
		);
	}

	#[test]
	fn association_ids_fill_gaps_rather_than_growing() {
		let mut stations = BTreeMap::new();
		stations.insert(1u16, station(1));
		stations.insert(3u16, station(3));

		assert_eq!(next_aid(&stations), 2);

		stations.insert(2u16, station(2));
		assert_eq!(next_aid(&stations), 4);
	}

	#[test]
	fn a_network_with_no_room_configured_admits_nobody() {
		let stations = BTreeMap::new();

		assert_eq!(
			decide_association(&stations, 0, &request(station(1), true)),
			AssociationDecision::Refuse {
				status: WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA
			}
		);
	}
}
