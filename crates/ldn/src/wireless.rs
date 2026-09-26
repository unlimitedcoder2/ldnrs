use core::ffi::c_void;
use std::ffi::CString;

use crate::generated::{
	LDN_LKL_WL_ANY_WIPHY, LDN_LKL_WL_EV_CONNECT, LDN_LKL_WL_EV_CONTROL_PORT,
	LDN_LKL_WL_EV_CONTROL_PORT_TX_STATUS, LDN_LKL_WL_EV_DEL_STATION, LDN_LKL_WL_EV_FRAME,
	LDN_LKL_WL_EV_SCAN_DONE, LdnLklWlBss, LdnLklWlEvent, LdnLklWlIface, ldn_lkl_wl_add_key,
	ldn_lkl_wl_add_station, ldn_lkl_wl_connect, ldn_lkl_wl_del_iface, ldn_lkl_wl_del_station,
	ldn_lkl_wl_disconnect, ldn_lkl_wl_find_wiphy, ldn_lkl_wl_get_station, ldn_lkl_wl_list_bss,
	ldn_lkl_wl_list_ifaces, ldn_lkl_wl_new_iface, ldn_lkl_wl_next_event, ldn_lkl_wl_register_frame,
	ldn_lkl_wl_release, ldn_lkl_wl_set_channel, ldn_lkl_wl_set_default_key,
	ldn_lkl_wl_set_station_authorized, ldn_lkl_wl_start_ap, ldn_lkl_wl_stop_ap,
	ldn_lkl_wl_trigger_scan, ldn_lkl_wl_tx_control_port, ldn_lkl_wl_tx_frame,
};
use crate::sys::{KernelContext, SysError};
use crate::wlan::{BEACON_INTERVAL, DTIM_PERIOD, MacAddress};

pub const NL80211_IFTYPE_STATION: u32 = 2;
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_MONITOR: u32 = 6;

pub const KEY_INDEX_UNICAST: u8 = 0;
pub const KEY_INDEX_BROADCAST: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
	pub index: u32,
	pub wiphy: Option<u32>,
	pub name: Option<String>,
	pub iftype: Option<u32>,
	pub mac: Option<MacAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
	Connect {
		/// The 802.11 status code; zero is success.
		status: u16,
		/// The host's address, absent on failure.
		address: Option<MacAddress>,
	},
	ControlPort {
		address: MacAddress,
		frame: Vec<u8>,
	},
	Frame {
		/// The frame, starting at the 802.11 header.
		frame: Vec<u8>,
		/// The frequency it arrived on, in MHz, if the driver said.
		frequency: Option<u16>,
	},
	DelStation {
		address: MacAddress,
	},
	/// `acknowledged` is the 802.11 acknowledgement, which is below encryption: a peer that cannot
	/// decrypt a frame still acknowledges receiving it. So an acknowledged frame that gets no
	/// answer was delivered and ignored, while an unacknowledged one never landed at all; the two
	/// point at completely different faults.
	ControlPortTxStatus {
		acknowledged: bool,
	},
	ScanDone,
	Other {
		kind: u32,
	},
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bss {
	pub bssid: MacAddress,
	pub frequency: Option<u16>,
	pub ssid: Option<Vec<u8>>,
}

/// The biggest payload an event can carry, matching `LKL_WL_FRAME_MAX` on the kernel side.
const EVENT_BUFFER: usize = 2304;

const fn check(value: i32) -> Result<i32, SysError> {
	if value < 0 {
		Err(SysError::from_raw(value))
	} else {
		Ok(value)
	}
}

pub struct Wireless {
	ctx: KernelContext,
}

impl Wireless {
	#[must_use]
	pub const fn lkl(ctx: KernelContext) -> Self {
		Self { ctx }
	}

	/// # Errors
	/// [`SysError`] if the kernel cannot be asked.
	pub fn find_wiphy(&self, name: &str) -> Result<Option<u32>, SysError> {
		let ctx = &self.ctx;

		let name = CString::new(name).map_err(|_| SysError::from_raw(-22))?;
		let mut wiphy = 0u32;

		// SAFETY: `name` is NUL-terminated and outlives the call; `wiphy` is a live u32.
		let ret =
			unsafe { ldn_lkl_wl_find_wiphy(ctx.raw_for_ffi(), name.as_ptr(), &raw mut wiphy) };

		if SysError::from_raw(ret).errno() == ENODEV && ret < 0 {
			return Ok(None);
		}

		check(ret)?;

		Ok(Some(wiphy))
	}

	/// # Errors
	/// [`SysError`] if the kernel cannot be asked.
	pub fn interfaces(&self, wiphy: Option<u32>) -> Result<Vec<Interface>, SysError> {
		let ctx = &self.ctx;

		let want = wiphy.unwrap_or(LDN_LKL_WL_ANY_WIPHY);

		// SAFETY: a null buffer is allowed when the capacity is zero.
		let count = check(unsafe {
			ldn_lkl_wl_list_ifaces(ctx.raw_for_ffi(), want, core::ptr::null_mut(), 0)
		})?;

		let mut out = vec![blank_iface(); usize::try_from(count).unwrap_or(0)];
		if out.is_empty() {
			return Ok(Vec::new());
		}

		let capacity = i32::try_from(out.len()).unwrap_or(0);

		// SAFETY: `out` has `capacity` entries and the shim is told so.
		let filled = check(unsafe {
			ldn_lkl_wl_list_ifaces(ctx.raw_for_ffi(), want, out.as_mut_ptr(), capacity)
		})?;

		// A device that appeared between the two calls is reported but was not written.
		let filled = usize::try_from(filled).unwrap_or(0).min(out.len());

		Ok(out
			.get(..filled)
			.unwrap_or(&[])
			.iter()
			.map(interface_of)
			.collect())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses, or if it creates the interface without saying which.
	pub fn new_interface(
		&self,
		wiphy: u32,
		ifname: &str,
		iftype: u32,
		monitor_other_bss: bool,
	) -> Result<Interface, SysError> {
		let ctx = &self.ctx;

		let name = CString::new(ifname).map_err(|_| SysError::from_raw(-22))?;
		let mut out = blank_iface();

		// SAFETY: `name` is NUL-terminated and outlives the call; `out` is a live struct.
		check(unsafe {
			ldn_lkl_wl_new_iface(
				ctx.raw_for_ffi(),
				wiphy,
				name.as_ptr(),
				iftype,
				i32::from(monitor_other_bss),
				&raw mut out,
			)
		})?;

		Ok(interface_of(&out))
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn del_interface(&self, ifindex: u32) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe { ldn_lkl_wl_del_iface(ctx.raw_for_ffi(), signed(ifindex)) })?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses: `EBUSY` if something else on the phy holds the radio.
	pub fn set_channel(&self, ifindex: u32, frequency: u16) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe {
			ldn_lkl_wl_set_channel(ctx.raw_for_ffi(), signed(ifindex), u32::from(frequency))
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses. `EBUSY` means a scan is already running, which populates the
	/// same cache and so is usually not worth treating as a failure.
	pub fn trigger_scan(&self, ifindex: u32, ssid: &[u8], frequency: u16) -> Result<(), SysError> {
		let ctx = &self.ctx;

		// SAFETY: `ssid` is `ssid.len()` bytes and the shim is told so.
		check(unsafe {
			ldn_lkl_wl_trigger_scan(
				ctx.raw_for_ffi(),
				signed(ifindex),
				ssid.as_ptr(),
				length(ssid.len()),
				u32::from(frequency),
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel cannot be asked.
	pub fn scan_results(&self, ifindex: u32) -> Result<Vec<Bss>, SysError> {
		let ctx = &self.ctx;

		// SAFETY: a null buffer is allowed when the capacity is zero.
		let count = check(unsafe {
			ldn_lkl_wl_list_bss(ctx.raw_for_ffi(), signed(ifindex), core::ptr::null_mut(), 0)
		})?;

		let mut out = vec![blank_bss(); usize::try_from(count).unwrap_or(0)];
		if out.is_empty() {
			return Ok(Vec::new());
		}

		let capacity = i32::try_from(out.len()).unwrap_or(0);

		// SAFETY: `out` has `capacity` entries and the shim is told so.
		let filled = check(unsafe {
			ldn_lkl_wl_list_bss(
				ctx.raw_for_ffi(),
				signed(ifindex),
				out.as_mut_ptr(),
				capacity,
			)
		})?;

		let filled = usize::try_from(filled).unwrap_or(0).min(out.len());

		Ok(out
			.get(..filled)
			.unwrap_or(&[])
			.iter()
			.map(bss_of)
			.collect())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses to start the join. Success here only means the attempt began;
	/// the outcome arrives as a [`Notification::Connect`].
	pub fn connect(
		&self,
		ifindex: u32,
		ssid: &[u8],
		frequency: u16,
		key: Option<&[u8]>,
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let (key_ptr, key_len) = optional(key);

		// SAFETY: both slices are described by their lengths, and a `None` key crosses as a
		// null pointer with a zero length, which the shim expects.
		check(unsafe {
			ldn_lkl_wl_connect(
				ctx.raw_for_ffi(),
				signed(ifindex),
				ssid.as_ptr(),
				length(ssid.len()),
				u32::from(frequency),
				key_ptr,
				key_len,
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn disconnect(&self, ifindex: u32) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe { ldn_lkl_wl_disconnect(ctx.raw_for_ffi(), signed(ifindex)) })?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn start_ap(
		&self,
		ifindex: u32,
		ssid: &[u8],
		address: MacAddress,
		frequency: u16,
		beacon_head: &[u8],
		beacon_tail: &[u8],
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		// The address is the interface's own, which the kernel already knows; nl80211
		// ignores the attribute too.
		let _ = address;

		// SAFETY: every buffer is described by its length.
		check(unsafe {
			ldn_lkl_wl_start_ap(
				ctx.raw_for_ffi(),
				signed(ifindex),
				ssid.as_ptr(),
				length(ssid.len()),
				u32::from(frequency),
				beacon_head.as_ptr().cast::<c_void>(),
				length(beacon_head.len()),
				beacon_tail.as_ptr().cast::<c_void>(),
				length(beacon_tail.len()),
				u32::from(BEACON_INTERVAL),
				u32::from(DTIM_PERIOD),
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn stop_ap(&self, ifindex: u32) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe { ldn_lkl_wl_stop_ap(ctx.raw_for_ffi(), signed(ifindex)) })?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses: `ENOLINK` if the link is not up yet.
	pub fn new_key(
		&self,
		ifindex: u32,
		index: u8,
		key: &[u8],
		address: Option<MacAddress>,
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let octets = address.map(|address| address.octets());
		let mac = octets
			.as_ref()
			.map_or(core::ptr::null(), |octets| octets.as_ptr());

		// SAFETY: `key` is described by its length, and `mac` is either null or six bytes
		// that outlive the call.
		check(unsafe {
			ldn_lkl_wl_add_key(
				ctx.raw_for_ffi(),
				signed(ifindex),
				i32::from(index),
				key.as_ptr().cast::<c_void>(),
				length(key.len()),
				mac,
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn new_group_key(&self, ifindex: u32, key: &[u8]) -> Result<(), SysError> {
		self.new_key(ifindex, KEY_INDEX_BROADCAST, key, None)
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn set_default_group_key(&self, ifindex: u32) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe {
			ldn_lkl_wl_set_default_key(
				ctx.raw_for_ffi(),
				signed(ifindex),
				i32::from(KEY_INDEX_BROADCAST),
				1,
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn new_station(
		&self,
		ifindex: u32,
		address: MacAddress,
		aid: u16,
		listen_interval: u16,
		capability: u16,
		supported_rates: &[u8],
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let mac = address.octets();

		// SAFETY: `mac` is six bytes and `supported_rates` is described by its length; both
		// outlive the call.
		check(unsafe {
			ldn_lkl_wl_add_station(
				ctx.raw_for_ffi(),
				signed(ifindex),
				mac.as_ptr(),
				u32::from(aid),
				u32::from(listen_interval),
				u32::from(capability),
				supported_rates.as_ptr().cast::<c_void>(),
				length(supported_rates.len()),
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn set_station_authorized(
		&self,
		ifindex: u32,
		address: MacAddress,
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let mac = address.octets();

		// SAFETY: `mac` is six bytes that outlive the call.
		check(unsafe {
			ldn_lkl_wl_set_station_authorized(ctx.raw_for_ffi(), signed(ifindex), mac.as_ptr())
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn del_station(&self, ifindex: u32, address: MacAddress) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let mac = address.octets();

		// SAFETY: `mac` is six bytes that outlive the call.
		check(unsafe { ldn_lkl_wl_del_station(ctx.raw_for_ffi(), signed(ifindex), mac.as_ptr()) })?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel cannot be asked.
	pub fn first_station(&self, ifindex: u32) -> Result<Option<MacAddress>, SysError> {
		let ctx = &self.ctx;

		let mut mac = [0u8; 6];

		// SAFETY: `mac` is six writable bytes.
		let ret =
			unsafe { ldn_lkl_wl_get_station(ctx.raw_for_ffi(), signed(ifindex), mac.as_mut_ptr()) };

		if ret < 0 {
			let errno = SysError::from_raw(ret).errno();
			if errno == ENOENT || errno == ENODEV {
				return Ok(None);
			}
		}

		check(ret)?;

		Ok(Some(MacAddress(mac)))
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn register_frame(&self, ifindex: u32, subtype: u8) -> Result<(), SysError> {
		let ctx = &self.ctx;

		check(unsafe {
			ldn_lkl_wl_register_frame(ctx.raw_for_ffi(), signed(ifindex), u32::from(subtype) << 4)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn frame(&self, ifindex: u32, frame: &[u8]) -> Result<(), SysError> {
		let ctx = &self.ctx;

		// SAFETY: `frame` is described by its length.
		check(unsafe {
			ldn_lkl_wl_tx_frame(
				ctx.raw_for_ffi(),
				signed(ifindex),
				frame.as_ptr().cast::<c_void>(),
				length(frame.len()),
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel refuses.
	pub fn control_port_frame(
		&self,
		ifindex: u32,
		address: MacAddress,
		frame: &[u8],
	) -> Result<(), SysError> {
		let ctx = &self.ctx;

		let mac = address.octets();

		// SAFETY: `mac` is six bytes and `frame` is described by its length.
		check(unsafe {
			ldn_lkl_wl_tx_control_port(
				ctx.raw_for_ffi(),
				signed(ifindex),
				mac.as_ptr(),
				frame.as_ptr().cast::<c_void>(),
				length(frame.len()),
			)
		})?;
		Ok(())
	}

	/// # Errors
	/// [`SysError`] if the kernel cannot supply the next wireless event.
	pub fn next_notification(&self, timeout_ms: u32) -> Result<Option<Notification>, SysError> {
		let ctx = &self.ctx;

		let mut event = blank_event();
		let mut buffer = vec![0u8; EVENT_BUFFER];

		let capacity = i32::try_from(buffer.len()).unwrap_or(0);

		// SAFETY: `event` is a live struct and `buffer` has `capacity` writable bytes.
		let ret = unsafe {
			ldn_lkl_wl_next_event(
				ctx.raw_for_ffi(),
				&raw mut event,
				buffer.as_mut_ptr().cast::<c_void>(),
				capacity,
				timeout_ms,
			)
		};

		if ret < 0 {
			let err = SysError::from_raw(ret);

			if err.is_would_block() || err.is_interrupted() {
				return Ok(None);
			}

			return Err(err);
		}

		// The ring drops the oldest event when it fills rather than stalling the driver, so
		// a loss is reported rather than swallowed. On a station this means a missed
		// advertisement; on a host, a missed frame it should have answered.
		if event.lost > 0 {
			println!(
				"wireless: dropped {} kernel event(s); the reader is not keeping up",
				event.lost
			);
		}

		let payload = buffer
			.get(..usize::try_from(event.len).unwrap_or(0).min(buffer.len()))
			.unwrap_or(&[])
			.to_vec();

		Ok(Some(notification_of(&event, payload)))
	}

	pub fn release(&self) {
		let ctx = &self.ctx;

		unsafe { ldn_lkl_wl_release(ctx.raw_for_ffi()) }
	}
}

const ENODEV: i32 = 19;

const ENOENT: i32 = 2;

fn signed(ifindex: u32) -> i32 {
	i32::try_from(ifindex).unwrap_or(0)
}

fn length(len: usize) -> i32 {
	i32::try_from(len).unwrap_or(0)
}

fn optional(data: Option<&[u8]>) -> (*const u8, i32) {
	data.map_or((core::ptr::null(), 0), |data| {
		(data.as_ptr(), length(data.len()))
	})
}

const fn blank_iface() -> LdnLklWlIface {
	LdnLklWlIface {
		index: 0,
		wiphy: 0,
		iftype: 0,
		mac: [0; 6],
		name: [0; 16],
	}
}

const fn blank_bss() -> LdnLklWlBss {
	LdnLklWlBss {
		bssid: [0; 6],
		freq: 0,
		ssid_len: 0,
		ssid: [0; 32],
	}
}

const fn blank_event() -> LdnLklWlEvent {
	LdnLklWlEvent {
		type_: 0,
		ifindex: 0,
		mac: [0; 6],
		status: 0,
		freq: 0,
		acked: 0,
		len: 0,
		lost: 0,
	}
}

/// Where a netlink dump leaves a field out, the direct path reports a zero, so the fields that
/// cannot legitimately be zero are the ones turned back into `None`, and the rest are always known.
fn interface_of(iface: &LdnLklWlIface) -> Interface {
	let name: Vec<u8> = iface
		.name
		.iter()
		.map(|byte| byte.cast_unsigned())
		.take_while(|byte| *byte != 0)
		.collect();

	let name = String::from_utf8(name).ok();

	Interface {
		index: u32::try_from(iface.index).unwrap_or(0),
		wiphy: Some(iface.wiphy),
		name,
		iftype: Some(iface.iftype),
		mac: Some(MacAddress(iface.mac)),
	}
}

fn bss_of(bss: &LdnLklWlBss) -> Bss {
	let len = usize::try_from(bss.ssid_len)
		.unwrap_or(0)
		.min(bss.ssid.len());

	Bss {
		bssid: MacAddress(bss.bssid),
		frequency: u16::try_from(bss.freq).ok().filter(|freq| *freq != 0),
		ssid: Some(bss.ssid.get(..len).unwrap_or(&[]).to_vec()),
	}
}

fn notification_of(event: &LdnLklWlEvent, payload: Vec<u8>) -> Notification {
	let address = MacAddress(event.mac);

	match event.type_ {
		LDN_LKL_WL_EV_CONNECT => Notification::Connect {
			status: event.status,
			// All zeroes is how the kernel reports a join that named nobody.
			address: (event.mac != [0u8; 6]).then_some(address),
		},
		LDN_LKL_WL_EV_CONTROL_PORT => Notification::ControlPort {
			address,
			frame: payload,
		},
		LDN_LKL_WL_EV_FRAME => Notification::Frame {
			frame: payload,
			frequency: u16::try_from(event.freq).ok().filter(|freq| *freq != 0),
		},
		LDN_LKL_WL_EV_DEL_STATION => Notification::DelStation { address },
		LDN_LKL_WL_EV_CONTROL_PORT_TX_STATUS => Notification::ControlPortTxStatus {
			acknowledged: event.acked != 0,
		},
		LDN_LKL_WL_EV_SCAN_DONE => Notification::ScanDone,
		kind => Notification::Other { kind },
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
	use super::Notification;
	use super::{
		LdnLklWlBss, LdnLklWlEvent, LdnLklWlIface, blank_bss, blank_event, blank_iface, bss_of,
		interface_of, notification_of,
	};
	use crate::wlan::MacAddress;

	fn named(name: &str) -> LdnLklWlIface {
		let mut iface = blank_iface();
		iface.index = 7;
		iface.wiphy = 3;
		iface.iftype = 6;
		iface.mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

		for (slot, byte) in iface.name.iter_mut().zip(name.bytes()) {
			*slot = byte.cast_signed();
		}

		iface
	}

	#[test]
	fn an_interface_crosses_the_boundary_intact() {
		let interface = interface_of(&named("ldn-mon"));

		assert_eq!(interface.index, 7);
		assert_eq!(interface.wiphy, Some(3));
		assert_eq!(interface.name.as_deref(), Some("ldn-mon"));
		assert_eq!(interface.iftype, Some(super::NL80211_IFTYPE_MONITOR));
		assert_eq!(
			interface.mac,
			Some(MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
		);
	}

	#[test]
	fn an_interface_name_stops_at_the_nul() {
		let interface = interface_of(&named("mon"));
		assert_eq!(interface.name.as_deref(), Some("mon"));
	}

	#[test]
	fn a_hidden_ssid_is_kept_rather_than_dropped() {
		let mut bss = blank_bss();
		bss.bssid = [1, 2, 3, 4, 5, 6];
		bss.freq = 2412;

		let parsed = bss_of(&bss);
		assert_eq!(parsed.frequency, Some(2412));
		assert_eq!(parsed.ssid.as_deref(), Some(&[][..]));
	}

	#[test]
	fn a_bss_ssid_is_bounded_by_its_length() {
		let mut bss = LdnLklWlBss {
			ssid_len: 4,
			..blank_bss()
		};
		bss.ssid[..4].copy_from_slice(b"ldn!");

		assert_eq!(bss_of(&bss).ssid.as_deref(), Some(&b"ldn!"[..]));
	}

	#[test]
	fn a_refused_join_keeps_its_status() {
		let event = LdnLklWlEvent {
			type_: super::LDN_LKL_WL_EV_CONNECT,
			status: 1,
			..blank_event()
		};

		assert_eq!(
			notification_of(&event, Vec::new()),
			Notification::Connect {
				status: 1,
				address: None,
			}
		);
	}

	#[test]
	fn scan_completion_is_distinct_from_unknown_event_kinds() {
		let event = LdnLklWlEvent {
			type_: super::LDN_LKL_WL_EV_SCAN_DONE,
			..blank_event()
		};
		assert_eq!(notification_of(&event, Vec::new()), Notification::ScanDone);

		// 34 was the old netlink scan-completion command. An unknown direct event
		// with that number must not masquerade as a completed scan.
		for kind in [34, 0x100, u32::MAX] {
			let unknown = LdnLklWlEvent {
				type_: kind,
				..blank_event()
			};
			assert_eq!(
				notification_of(&unknown, Vec::new()),
				Notification::Other { kind }
			);
		}
	}

	#[test]
	fn a_successful_join_names_the_host() {
		let event = LdnLklWlEvent {
			type_: super::LDN_LKL_WL_EV_CONNECT,
			mac: [1, 2, 3, 4, 5, 6],
			..blank_event()
		};

		assert_eq!(
			notification_of(&event, Vec::new()),
			Notification::Connect {
				status: 0,
				address: Some(MacAddress([1, 2, 3, 4, 5, 6])),
			}
		);
	}

	#[test]
	fn a_control_port_frame_carries_its_sender_and_body() {
		let event = LdnLklWlEvent {
			type_: super::LDN_LKL_WL_EV_CONTROL_PORT,
			mac: [1, 2, 3, 4, 5, 6],
			..blank_event()
		};

		assert_eq!(
			notification_of(&event, b"auth".to_vec()),
			Notification::ControlPort {
				address: MacAddress([1, 2, 3, 4, 5, 6]),
				frame: b"auth".to_vec(),
			}
		);
	}

	#[test]
	fn an_unacknowledged_transmit_is_told_from_an_acknowledged_one() {
		for (acked, expected) in [(0, false), (1, true)] {
			let event = LdnLklWlEvent {
				type_: super::LDN_LKL_WL_EV_CONTROL_PORT_TX_STATUS,
				acked,
				..blank_event()
			};

			assert_eq!(
				notification_of(&event, Vec::new()),
				Notification::ControlPortTxStatus {
					acknowledged: expected,
				}
			);
		}
	}
}
