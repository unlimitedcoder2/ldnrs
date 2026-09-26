use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};

use crate::generated::LDN_LKL_ETH_P_ALL;
use std::sync::atomic::AtomicUsize;

use crate::sys::{KernelContext, Socket, SysError};

const FRAME_BUFFER: usize = 4096;
const READ_TIMEOUT_MS: u32 = 200;
const FRAME_QUEUE: usize = 256;

#[derive(Debug)]
pub enum ChannelError {
	Sys(SysError),
	Spawn(std::io::Error),
}

impl core::fmt::Display for ChannelError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Sys(err) => write!(f, "{err}"),
			Self::Spawn(err) => write!(f, "could not start the channel reader: {err}"),
		}
	}
}

impl core::error::Error for ChannelError {}

impl From<SysError> for ChannelError {
	fn from(err: SysError) -> Self {
		Self::Sys(err)
	}
}

pub struct RawChannel {
	tx: Socket,
	frames: Receiver<Vec<u8>>,
	stop: Arc<AtomicBool>,
	dropped: Arc<AtomicUsize>,
}

impl RawChannel {
	/// # Errors
	/// [`ChannelError::Sys`] if a socket cannot be set up, [`ChannelError::Spawn`] if the reader
	/// thread cannot be started.
	pub fn open(ctx: KernelContext, ifindex: i32) -> Result<Self, ChannelError> {
		let eth_protocol = u16::try_from(LDN_LKL_ETH_P_ALL).unwrap_or(3);

		let tx = Socket::open_packet(ctx, eth_protocol)?;
		tx.bind_packet(eth_protocol, ifindex)?;

		let rx = Socket::open_packet(ctx, eth_protocol)?;
		rx.bind_packet(eth_protocol, ifindex)?;
		rx.set_recv_timeout_ms(READ_TIMEOUT_MS)?;

		let (sender, frames) = sync_channel(FRAME_QUEUE);
		let stop = Arc::new(AtomicBool::new(false));

		let dropped = Arc::new(AtomicUsize::new(0));

		let reader_stop = Arc::clone(&stop);
		let reader_dropped = Arc::clone(&dropped);
		std::thread::Builder::new()
			.name("ldn-channel-reader".to_owned())
			.spawn(move || read_frames(&rx, &sender, &reader_stop, &reader_dropped))
			.map_err(ChannelError::Spawn)?;

		Ok(Self {
			tx,
			frames,
			stop,
			dropped,
		})
	}

	/// # Errors
	/// [`ChannelError::Sys`] if the kernel refuses it.
	pub fn send(&self, frame: &[u8]) -> Result<(), ChannelError> {
		self.tx.send(frame)?;

		Ok(())
	}

	/// # Errors
	/// `Empty` when no frame is ready, or `Disconnected` when the reader stops.
	pub fn try_next_frame(&self) -> Result<Vec<u8>, TryRecvError> {
		self.frames.try_recv()
	}

	#[must_use]
	pub fn dropped(&self) -> usize {
		self.dropped.load(Ordering::Acquire)
	}
}

impl Drop for RawChannel {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);
	}
}

fn read_frames(
	socket: &Socket,
	sender: &SyncSender<Vec<u8>>,
	stop: &AtomicBool,
	dropped: &AtomicUsize,
) {
	let mut buffer = vec![0u8; FRAME_BUFFER];

	while !stop.load(Ordering::Acquire) {
		match socket.recv(&mut buffer) {
			Ok(0) => {}
			Ok(read) => {
				let frame = buffer.get(..read).unwrap_or(&[]).to_vec();

				match sender.try_send(frame) {
					Ok(()) => {}
					Err(TrySendError::Full(_)) => {
						dropped.fetch_add(1, Ordering::AcqRel);
					}
					Err(TrySendError::Disconnected(_)) => return,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
	pub peer: [u8; 4],
	pub port: u16,
	pub payload: Vec<u8>,
}

pub struct DatagramChannel {
	socket: Arc<Socket>,
	datagrams: Receiver<Datagram>,
	stop: Arc<AtomicBool>,
	port: u16,
}

impl DatagramChannel {
	/// **Binds the wildcard address, not the station's own.** This is load-bearing rather than
	/// lazy: LDN's interesting traffic is the host broadcasting to `169.254.<net>.255`, which is
	/// not addressed to us, so a socket bound to our own address alone would receive none of it.
	///
	/// A `port` of 0 lets the kernel choose; [`DatagramChannel::port`] reports what it picked.
	///
	/// # Errors
	/// [`ChannelError`] if the socket cannot be opened or bound, or the reader cannot start.
	pub fn open(ctx: KernelContext, port: u16) -> Result<Self, ChannelError> {
		let socket = Socket::open_udp(ctx)?;
		socket.bind_in([0, 0, 0, 0], port)?;
		socket.set_recv_timeout_ms(READ_TIMEOUT_MS)?;

		let port = socket.local_port()?;

		let socket = Arc::new(socket);
		let (sender, datagrams) = sync_channel(FRAME_QUEUE);
		let stop = Arc::new(AtomicBool::new(false));

		let reader = Arc::clone(&socket);
		let reader_stop = Arc::clone(&stop);
		std::thread::Builder::new()
			.name("ldn-datagram-reader".to_owned())
			.spawn(move || read_datagrams(&reader, &sender, &reader_stop))
			.map_err(ChannelError::Spawn)?;

		Ok(Self {
			socket,
			datagrams,
			stop,
			port,
		})
	}

	#[must_use]
	pub const fn port(&self) -> u16 {
		self.port
	}

	/// # Errors
	/// [`ChannelError::Sys`] if the kernel refuses it.
	pub fn send_to(&self, payload: &[u8], peer: [u8; 4], port: u16) -> Result<(), ChannelError> {
		self.socket.send_to(payload, peer, port)?;

		Ok(())
	}

	/// # Errors
	/// `Empty` when no datagram is ready, or `Disconnected` when the reader stops.
	pub fn try_next_datagram(&self) -> Result<Datagram, TryRecvError> {
		self.datagrams.try_recv()
	}
}

impl Drop for DatagramChannel {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);
	}
}

fn read_datagrams(socket: &Socket, sender: &SyncSender<Datagram>, stop: &AtomicBool) {
	let mut buffer = vec![0u8; FRAME_BUFFER];

	while !stop.load(Ordering::Acquire) {
		match socket.recv_from(&mut buffer) {
			// A zero-length UDP datagram is legal and carries meaning in some protocols, so it is
			// forwarded rather than skipped the way a zero-length frame read is.
			Ok((read, peer, port)) => {
				let payload = buffer.get(..read).unwrap_or(&[]).to_vec();

				let datagram = Datagram {
					peer,
					port,
					payload,
				};

				if let Err(TrySendError::Disconnected(_)) = sender.try_send(datagram) {
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
