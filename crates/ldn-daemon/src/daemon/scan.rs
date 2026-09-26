use super::Daemon;
use super::session::{Outbound, queue_event};
use ldn::protocol::{Event, Op, ScanReply, ScanRequest, Status, WireWrite, encode_frame};
use ldn::radio::{VifNames, free_radio};
use ldn::scan::{FrameSource, ScanParams, Scanner};
use std::rc::Rc;
use std::time::{Duration, Instant};

const TUNE_SETTLE_MS: u64 = 100;

pub(super) struct Scan {
	source: Rc<dyn FrameSource>,
	scanner: Scanner,
	params: ScanParams,
	channel: usize,
	phase: Phase,
	request_id: u32,
}

enum Phase {
	Tune,
	Settle(Instant),
	Dwell(Instant),
}

impl Scan {
	pub(super) fn start(
		daemon: &Rc<Daemon>,
		request: &ScanRequest,
		out: &Outbound,
		request_id: u32,
	) -> Option<Self> {
		match Self::new(daemon, request, request_id) {
			Ok(scan) => Some(scan),
			Err((status, message)) => {
				reply(out, request_id, &ScanReply::error(status, message));
				None
			}
		}
	}

	fn new(
		daemon: &Rc<Daemon>,
		request: &ScanRequest,
		request_id: u32,
	) -> Result<Self, (Status, String)> {
		let Some(source) = daemon.frame_source() else {
			return Err((
				Status::NoRadio,
				"no monitor interface is available to scan with".to_owned(),
			));
		};

		let defaults = ScanParams::default();
		let params = ScanParams {
			channels: if request.channels.is_empty() {
				defaults.channels
			} else {
				request.channels.clone()
			},
			dwell_ms: request.dwell_ms.unwrap_or(defaults.dwell_ms),
			protocols: if request.protocols.is_empty() {
				defaults.protocols
			} else {
				request.protocols.clone()
			},
		};

		params
			.check()
			.map_err(|message| (Status::InvalidParam, message))?;

		let Some(keys) = daemon.keys() else {
			return Err((
				Status::NoKeys,
				format!("{}", ldn::crypto::KeyError::NotLoaded),
			));
		};

		let scanner = Scanner::new(&keys, &params.protocols)
			.map_err(|err| (Status::NoKeys, format!("{err}")))?;
		Ok(Self {
			source,
			scanner,
			params,
			channel: 0,
			phase: Phase::Tune,
			request_id,
		})
	}

	/// Returns true after sending the final reply.
	pub(super) fn poll(&mut self, daemon: &Rc<Daemon>, out: &Outbound) -> bool {
		let Some(channel) = self.params.channels.get(self.channel).copied() else {
			self.finish(out);
			return true;
		};
		match self.phase {
			Phase::Tune => {
				if let Err(message) = self.source.set_channel(channel) {
					sweep(daemon, self.source.as_ref());
					if let Err(second) = self.source.set_channel(channel) {
						reply(
							out,
							self.request_id,
							&ScanReply::error(
								Status::Io,
								format!(
									"could not tune to channel {channel}: {message} (still busy after sweeping {}: {second})",
									daemon.phyname()
								),
							),
						);
						return true;
					}
				}
				self.phase = Phase::Settle(Instant::now());
			}
			Phase::Settle(started) => {
				if started.elapsed() >= Duration::from_millis(TUNE_SETTLE_MS) {
					self.phase = Phase::Dwell(Instant::now());
				}
			}
			Phase::Dwell(started) => {
				let dwell = Duration::from_millis(u64::from(self.params.dwell_ms));
				for _ in 0..64 {
					if started.elapsed() >= dwell {
						self.channel += 1;
						self.phase = Phase::Tune;
						break;
					}
					match self.source.try_next_frame() {
						Ok(frame) => {
							if let Some(network) = self.scanner.feed(&frame) {
								queue_event(out, &Event::NetworkFound(Box::new(network)));
							}
						}
						Err(std::sync::mpsc::TryRecvError::Empty) => break,
						Err(std::sync::mpsc::TryRecvError::Disconnected) => {
							self.channel += 1;
							self.phase = Phase::Tune;
							break;
						}
					}
				}
			}
		}
		false
	}

	pub(super) fn finish(&self, out: &Outbound) {
		let count = u32::try_from(self.scanner.len()).unwrap_or(u32::MAX);
		queue_event(out, &Event::ScanDone { count });
		reply(
			out,
			self.request_id,
			&ScanReply::ok(self.scanner.networks().to_vec()),
		);
	}
}

fn sweep(daemon: &Rc<Daemon>, source: &dyn FrameSource) {
	let Some(ctx) = daemon.lkl().context() else {
		return;
	};
	let _ = free_radio(ctx, &daemon.phyname(), &VifNames::default(), None);
	source.interrupted();
}

fn reply(out: &Outbound, request_id: u32, reply: &ScanReply) {
	let body = reply.encode().unwrap_or_default();
	let _ = out.send(encode_frame(Op::Reply, request_id, &body));
}
