use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};

use crate::generated::LDN_LKL_ETH_P_ALL;
use crate::iface::{IfaceError, checked_ifindex, ensure_interface, wiphy_index};
use crate::scan::FrameSource;
use crate::sys::{KernelContext, Socket, if_up};
use crate::wireless::NL80211_IFTYPE_MONITOR;
use crate::wireless::Wireless;
use crate::wlan::{MacAddress, channel_frequency, is_valid_channel, radiotap_wrap};

const FRAME_QUEUE: usize = 256;
const FRAME_BUFFER: usize = 8192;
const READ_TIMEOUT_MS: u32 = 200;
const SETTLE_MS: u64 = 1_000;

#[derive(Debug)]
pub enum MonitorError {
	Sys(crate::sys::SysError),
	Iface(IfaceError),
	Spawn(std::io::Error),
}

impl core::fmt::Display for MonitorError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Sys(err) => write!(f, "{err}"),
			Self::Iface(err) => write!(f, "{err}"),
			Self::Spawn(err) => write!(f, "could not start the frame reader: {err}"),
		}
	}
}

impl core::error::Error for MonitorError {}

impl From<crate::sys::SysError> for MonitorError {
	fn from(err: crate::sys::SysError) -> Self {
		Self::Sys(err)
	}
}

impl From<IfaceError> for MonitorError {
	fn from(err: IfaceError) -> Self {
		Self::Iface(err)
	}
}

pub struct MonitorSource {
	wireless: Wireless,
	ctx: KernelContext,
	ifindex: i32,
	address: Option<MacAddress>,
	name: String,
	frames: Receiver<Vec<u8>>,
	socket: Arc<Socket>,
	stop: Arc<AtomicBool>,
	tuned: Cell<Option<u8>>,
	/// Whether the interface may have been brought down behind our back.
	down: Cell<bool>,
}

impl MonitorSource {
	/// # Errors
	/// [`MonitorError`] if the phy is missing or any step is refused.
	pub fn create(ctx: KernelContext, phyname: &str, ifname: &str) -> Result<Self, MonitorError> {
		let wireless = Wireless::lkl(ctx);

		let wiphy = wiphy_index(&wireless, phyname)?;

		let interface = ensure_interface(&wireless, wiphy, ifname, NL80211_IFTYPE_MONITOR, true)?;

		let ifindex = checked_ifindex(interface.index)?;

		if_up(ctx, ifindex)?;

		std::thread::sleep(std::time::Duration::from_millis(SETTLE_MS));

		let eth_protocol = u16::try_from(LDN_LKL_ETH_P_ALL).unwrap_or(3);
		let socket = Arc::new(Socket::open_packet(ctx, eth_protocol)?);
		socket.bind_packet(eth_protocol, ifindex)?;
		socket.set_recv_timeout_ms(READ_TIMEOUT_MS)?;

		let (sender, frames) = sync_channel(FRAME_QUEUE);
		let stop = Arc::new(AtomicBool::new(false));

		let reader_stop = Arc::clone(&stop);
		let reader_socket = Arc::clone(&socket);
		std::thread::Builder::new()
			.name("ldn-monitor-reader".to_owned())
			.spawn(move || read_frames(&reader_socket, &sender, &reader_stop))
			.map_err(MonitorError::Spawn)?;

		Ok(Self {
			wireless,
			ctx,
			ifindex,
			address: interface.mac,
			name: ifname.to_owned(),
			frames,
			socket,
			stop,
			tuned: Cell::new(None),
			down: Cell::new(false),
		})
	}

	/// Records that something else took the radio, so the next tune brings the interface back up.
	pub fn mark_down(&self) {
		self.down.set(true);
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

	/// `frame` is the bare 802.11 frame; the radiotap header injection requires is added here.
	///
	/// This is how an LDN host advertises. Advertisements are action frames and go out on a
	/// monitor interface rather than the AP one, because they are not the AP's traffic: mac80211
	/// will not transmit a management frame from an AP vif that its own state machine did not
	/// produce, and an advertisement is addressed to the broadcast address from a network nobody
	/// has joined yet.
	///
	/// # Errors
	/// [`MonitorError::Sys`] if the write fails.
	pub fn send_frame(&self, frame: &[u8]) -> Result<(), MonitorError> {
		self.socket.send(&radiotap_wrap(frame))?;

		Ok(())
	}

	fn tune(&self, channel: u8) -> Result<(), String> {
		let frequency = channel_frequency(channel)
			.ok_or_else(|| format!("no frequency for channel {channel}"))?;
		let ifindex = u32::try_from(self.ifindex).map_err(|_| "bad interface index".to_owned())?;

		self.wireless
			.set_channel(ifindex, frequency)
			.map_err(|err| format!("{err}"))
	}

	fn drain(&self) {
		while self.frames.try_recv().is_ok() {}
	}

	#[must_use]
	pub fn into_source(self) -> std::rc::Rc<dyn FrameSource> {
		std::rc::Rc::new(self)
	}
}

impl Drop for MonitorSource {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);

		let _ = &self.ctx;
	}
}

fn read_frames(socket: &Socket, sender: &SyncSender<Vec<u8>>, stop: &AtomicBool) {
	let mut buffer = vec![0u8; FRAME_BUFFER];

	while !stop.load(Ordering::Acquire) {
		match socket.recv(&mut buffer) {
			Ok(0) => {}
			Ok(read) => {
				let frame = buffer.get(..read).unwrap_or(&[]).to_vec();

				if let Err(TrySendError::Disconnected(_)) = sender.try_send(frame) {
					return;
				}
			}
			Err(err) if err.is_would_block() || err.is_interrupted() => {}
			Err(err) if err.is_network_down() => {
				std::thread::sleep(std::time::Duration::from_millis(u64::from(READ_TIMEOUT_MS)));
			}
			Err(_) => return,
		}
	}
}

impl FrameSource for MonitorSource {
	fn interrupted(&self) {
		self.mark_down();
	}

	fn set_channel(&self, channel: u8) -> Result<(), String> {
		if !is_valid_channel(channel) {
			return Err(format!("invalid channel: {channel}"));
		}

		if self.down.replace(false) {
			if_up(self.ctx, self.ifindex).map_err(|err| format!("{err}"))?;

			self.tuned.set(None);
			std::thread::sleep(std::time::Duration::from_millis(SETTLE_MS));
		}

		/* let needs_nudge = self.tuned.get().is_none_or(|last| last == channel);
		if needs_nudge {
			let nudge = if channel == 11 { 6 } else { 11 };
			let _ = self.tune(nudge);
		} */

		self.tune(channel)?;
		self.tuned.set(Some(channel));

		// Frames captured before the tune are still queued, and they belong to the old channel.
		// Discarding them stops them eating the new channel's dwell.
		self.drain();

		Ok(())
	}

	fn try_next_frame(&self) -> Result<Vec<u8>, TryRecvError> {
		self.frames.try_recv()
	}
}
