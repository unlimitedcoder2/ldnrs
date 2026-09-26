use std::time::{Duration, Instant};

use crate::iface::{IfaceError, checked_ifindex, disable_ipv6, ensure_interface, wiphy_index};
use crate::sys::{KernelContext, if_down, if_up};
use crate::wireless::Wireless;
use crate::wireless::{
	KEY_INDEX_BROADCAST, KEY_INDEX_UNICAST, NL80211_IFTYPE_STATION, Notification,
};
use crate::wlan::{MacAddress, STYPE_ACTION, WLAN_STATUS_SUCCESS, channel_frequency};

const CONNECT_TIMEOUT_MS: u32 = 10_000;

const NOTIFICATION_POLL_MS: u32 = 250;

const SCAN_TIMEOUT_MS: u32 = 8_000;

const SCAN_POLL_MS: u32 = 300;

const SCAN_ATTEMPTS: u32 = 3;

/// How long a peer must stay listed with no connect event before it is taken as associated. The
/// AP is listed from the moment authentication starts, and associating takes about 0.5 s more.
const PEER_GRACE_MS: u64 = 2_000;

#[derive(Debug)]
pub enum StationError {
	Iface(IfaceError),
	Sys(crate::sys::SysError),
	BadChannel {
		channel: u8,
	},
	Refused {
		/// The 802.11 status code. 1 is the unhelpful catch-all, and usually means a leaked vif
		/// from an earlier attempt is still associated.
		status: u16,
	},
	ConnectTimeout {
		notifications: usize,
	},
	NoHostAddress,
	NotConnected,
}

impl core::fmt::Display for StationError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Iface(err) => write!(f, "{err}"),
			Self::Sys(err) => write!(f, "{err}"),
			Self::BadChannel { channel } => write!(f, "channel {channel} is not an LDN channel"),
			Self::Refused { status } => {
				write!(f, "the network refused the join (802.11 status {status})")
			}
			Self::ConnectTimeout { notifications: 0 } => {
				write!(f, "the kernel reported no wireless events while joining")
			}
			Self::ConnectTimeout { notifications } => write!(
				f,
				"the kernel never reported the result of the join ({notifications} unrelated \
				 wireless event(s) did arrive)"
			),
			Self::NoHostAddress => write!(f, "joined, but the kernel named no host"),
			Self::NotConnected => write!(f, "not connected to a network"),
		}
	}
}

impl core::error::Error for StationError {}

impl From<IfaceError> for StationError {
	fn from(err: IfaceError) -> Self {
		Self::Iface(err)
	}
}

impl From<crate::sys::SysError> for StationError {
	fn from(err: crate::sys::SysError) -> Self {
		Self::Sys(err)
	}
}

/// Dropping this explicitly disconnects the association held by cfg80211.
pub struct Station {
	ctx: KernelContext,
	wireless: Wireless,
	ifindex: i32,
	address: Option<MacAddress>,
	name: String,
	host: Option<MacAddress>,
	connected: bool,
	deadline: Option<Instant>,
}

impl Station {
	/// # Errors
	/// [`StationError`] if the phy is missing or the kernel refuses a step.
	pub fn create(ctx: KernelContext, phyname: &str, ifname: &str) -> Result<Self, StationError> {
		let wireless = Wireless::lkl(ctx);

		let wiphy = wiphy_index(&wireless, phyname)?;
		let interface = ensure_interface(&wireless, wiphy, ifname, NL80211_IFTYPE_STATION, false)?;

		let ifindex = checked_ifindex(interface.index)?;

		disable_ipv6(ctx, ifname);
		if_up(ctx, ifindex)?;

		Ok(Self {
			ctx,
			wireless,
			ifindex,
			address: interface.mac,
			name: ifname.to_owned(),
			host: None,
			connected: false,
			deadline: None,
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
	pub const fn address(&self) -> Option<MacAddress> {
		self.address
	}

	/// **It does not apply to the association wait in [`Station::connect`].** Cutting a wait short only
	/// stops us listening; it does not stop the kernel. Everything else here is a wait whose
	/// abandonment costs nothing, but `CMD_CONNECT` has been *sent* by then; walking away from it
	/// leaves an association that completes seconds later with nobody owning it, and a station vif
	/// holding the radio, so the next `SET_CHANNEL` on this phy fails `EBUSY` and every subsequent
	/// scan reports nothing. Measured: a join abandoned at its deadline associated 300 ms later and
	/// wedged the phy until the daemon was restarted.
	pub const fn set_deadline(&mut self, deadline: Option<Instant>) {
		self.deadline = deadline;
	}

	fn allowance(&self, own_ms: u32) -> Duration {
		let own = Duration::from_millis(u64::from(own_ms));

		self.deadline.map_or(own, |deadline| {
			own.min(deadline.saturating_duration_since(Instant::now()))
		})
	}

	/// # Errors
	/// [`StationError::Refused`] if the network turned the join down,
	/// [`StationError::ConnectTimeout`] if the kernel never answered, or [`StationError`] for any
	/// other failure.
	pub fn connect(
		&mut self,
		ssid: &[u8],
		channel: u8,
		key: Option<&[u8]>,
	) -> Result<(), StationError> {
		let frequency = channel_frequency(channel).ok_or(StationError::BadChannel { channel })?;

		let ifindex = self.ifindex_u32();

		// cfg80211 only completes a connection to a BSS it already knows, so the network has to be
		// scanned for on *this* interface first; knowing it is there from a monitor scan is not
		// enough. Skipping this is how a join half-succeeds: the driver associates, cfg80211 never
		// registers the link, no connect event is sent, and the first key install is refused with
		// `ENOLINK` ("key not allowed").
		self.scan_for(ssid, frequency)?;

		self.wireless.connect(ifindex, ssid, frequency, key)?;

		let host = self.await_connect()?;
		self.host = Some(host);
		self.connected = true;

		if let Some(key) = key {
			self.register_key(key, host)?;
		}

		self.wireless.register_frame(ifindex, STYPE_ACTION)?;

		Ok(())
	}

	/// A scan that finds nothing is not fatal here: the association is attempted anyway, and its
	/// own error is more informative than one invented at this point.
	///
	/// The network's beacons hide its SSID, so it enters the cache only through the answer to the
	/// one directed probe each scan sends, and that answer is sometimes missed. Once a scan has
	/// finished nothing else will add it, so a miss is scanned again rather than waited on.
	fn scan_for(&self, ssid: &[u8], frequency: u16) -> Result<(), StationError> {
		if self.cached_bss(ssid)? {
			return Ok(());
		}

		let limit = self.allowance(SCAN_TIMEOUT_MS);
		let started = Instant::now();

		for _ in 0..SCAN_ATTEMPTS {
			if started.elapsed() >= limit {
				break;
			}

			// A busy or already-scanning driver answers `EBUSY`. The wait covers that too: the scan
			// it is already running fills the same cache, and ends with the same notification.
			let _ = self
				.wireless
				.trigger_scan(self.ifindex_u32(), ssid, frequency);

			while started.elapsed() < limit {
				let notification = self.wireless.next_notification(SCAN_POLL_MS)?;

				if self.cached_bss(ssid)? {
					return Ok(());
				}

				if notification == Some(Notification::ScanDone) {
					break;
				}
			}
		}

		Ok(())
	}

	fn cached_bss(&self, ssid: &[u8]) -> Result<bool, StationError> {
		Ok(self
			.wireless
			.scan_results(self.ifindex_u32())?
			.iter()
			.any(|bss| bss.ssid.as_deref() == Some(ssid)))
	}

	/// Two ways of learning the same thing, because one of them cannot be relied on. The
	/// `CMD_CONNECT` notification is the direct answer and carries a status code, so it is
	/// preferred. But an event that is never emitted is indistinguishable from a failed join, and
	/// that has been seen in practice: the station associates, the peer is there in a `GET_STATION`
	/// dump, and no notification ever arrives. So the association is also *asked* about.
	///
	/// A listed peer is not yet an associated one, though. mac80211 lists the AP as soon as it
	/// starts authenticating, and the key install that follows is refused with `ENOENT` until the
	/// association completes. So a peer only stands in for the event once it has been listed for
	/// [`PEER_GRACE_MS`] without the event arriving.
	fn await_connect(&self) -> Result<MacAddress, StationError> {
		let limit = Duration::from_millis(u64::from(CONNECT_TIMEOUT_MS));
		let grace = Duration::from_millis(PEER_GRACE_MS);
		let started = Instant::now();
		let mut notifications = 0usize;
		let mut listed: Option<(MacAddress, Instant)> = None;

		while started.elapsed() < limit {
			if let Some(notification) = self.wireless.next_notification(NOTIFICATION_POLL_MS)? {
				notifications += 1;

				if let Notification::Connect { status, address } = notification {
					if status != WLAN_STATUS_SUCCESS {
						return Err(StationError::Refused { status });
					}

					return address.ok_or(StationError::NoHostAddress);
				}

				continue;
			}

			match (self.listed_peer()?, listed) {
				(Some(host), Some((seen, since))) if host == seen => {
					if since.elapsed() >= grace {
						return Ok(host);
					}
				}
				(peer, _) => listed = peer.map(|host| (host, Instant::now())),
			}
		}

		Err(StationError::ConnectTimeout { notifications })
	}

	fn listed_peer(&self) -> Result<Option<MacAddress>, StationError> {
		Ok(self.wireless.first_station(self.ifindex_u32())?)
	}

	fn register_key(&self, key: &[u8], host: MacAddress) -> Result<(), StationError> {
		let ifindex = self.ifindex_u32();

		self.wireless
			.new_key(ifindex, KEY_INDEX_UNICAST, key, Some(host))?;
		self.wireless
			.new_key(ifindex, KEY_INDEX_BROADCAST, key, None)?;

		Ok(())
	}

	/// # Errors
	/// [`StationError::NotConnected`] if no network has been joined, or [`StationError::Sys`]
	/// if the kernel refuses.
	pub fn send_control_frame(
		&self,
		address: MacAddress,
		frame: &[u8],
	) -> Result<(), StationError> {
		if !self.connected {
			return Err(StationError::NotConnected);
		}

		self.wireless
			.control_port_frame(self.ifindex_u32(), address, frame)?;

		Ok(())
	}

	/// Called once the LDN handshake has succeeded; until then the link carries only control-port
	/// frames.
	///
	/// # Errors
	/// [`StationError::NotConnected`] if no network has been joined.
	pub fn set_authorized(&self) -> Result<(), StationError> {
		let host = self.host.ok_or(StationError::NotConnected)?;

		self.wireless
			.set_station_authorized(self.ifindex_u32(), host)?;

		Ok(())
	}

	/// # Errors
	/// [`StationError`] if the socket fails or a notification is malformed.
	pub fn next_event(&self, timeout_ms: u32) -> Result<Option<Notification>, StationError> {
		Ok(self.wireless.next_notification(timeout_ms)?)
	}

	/// # Errors
	/// [`StationError::Sys`] if the kernel refuses.
	pub fn disconnect(&mut self) -> Result<(), StationError> {
		if !self.connected {
			return Ok(());
		}

		self.wireless.disconnect(self.ifindex_u32())?;

		self.connected = false;
		self.host = None;

		// Leaving the network is not enough to free the radio: an interface that is merely
		// disconnected is still up, still owns a channel, and makes the next `SET_CHANNEL` on this
		// phy fail with `EBUSY`, which is how a scan after a join starts failing. Bringing it down
		// is what actually releases the phy, and the vif itself is deliberately kept so the next
		// join reuses it rather than thrashing the device.
		let _ = if_down(self.ctx, self.ifindex);

		Ok(())
	}

	fn ifindex_u32(&self) -> u32 {
		u32::try_from(self.ifindex).unwrap_or(0)
	}
}

impl Drop for Station {
	fn drop(&mut self) {
		if let Err(err) = self.disconnect() {
			println!("station: could not leave the network on drop: {err}");
		}
	}
}
