use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

const TUNE_SETTLE_MS: u64 = 100;

use futures_channel::mpsc::UnboundedSender;

use ldn::protocol::{Event, Op, ScanReply, ScanRequest, Status, WireWrite, encode_frame};
use ldn::radio::{VifNames, free_radio};
use ldn::scan::{FrameSource, ScanParams, Scanner};

use super::Daemon;

type Outbound = UnboundedSender<Vec<u8>>;

pub(super) async fn run(
	daemon: Rc<Daemon>,
	request: ScanRequest,
	out: Outbound,
	request_id: u32,
	cancel: Rc<Cell<bool>>,
) {
	let reply = match scan(&daemon, &request, &out, &cancel).await {
		Ok(networks) => {
			let count = u32::try_from(networks.len()).unwrap_or(u32::MAX);
			queue_event(&out, &Event::ScanDone { count });
			ScanReply::ok(networks)
		}
		Err((status, message)) => ScanReply::error(status, message),
	};

	let body = reply.encode().unwrap_or_default();
	let _ = out.unbounded_send(encode_frame(Op::Reply, request_id, &body));
}

async fn scan(
	daemon: &Rc<Daemon>,
	request: &ScanRequest,
	out: &Outbound,
	cancel: &Rc<Cell<bool>>,
) -> Result<Vec<ldn::advertisement::NetworkInfo>, (Status, String)> {
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

	let mut scanner =
		Scanner::new(&keys, &params.protocols).map_err(|err| (Status::NoKeys, format!("{err}")))?;

	let dwell = Duration::from_millis(u64::from(params.dwell_ms));

	for channel in &params.channels {
		if cancel.get() {
			break;
		}

		if let Err(message) = source.set_channel(*channel) {
			sweep(daemon, source.as_ref());

			source.set_channel(*channel).map_err(|second| {
				(
					Status::Io,
					format!(
						"could not tune to channel {channel}: {message} 						 (still busy after sweeping {phy}: {second})",
						phy = daemon.phyname()
					),
				)
			})?;
		}

		compio::time::sleep(Duration::from_millis(TUNE_SETTLE_MS)).await;

		let visit = async {
			loop {
				let frame = match source.try_next_frame() {
					Ok(frame) => frame,
					Err(std::sync::mpsc::TryRecvError::Empty) => {
						compio::time::sleep(Duration::from_millis(10)).await;
						continue;
					}
					Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
				};

				if let Some(network) = scanner.feed(&frame) {
					queue_event(out, &Event::NetworkFound(Box::new(network)));
				}

				if cancel.get() {
					return;
				}
			}
		};

		let _ = compio::time::timeout(dwell, visit).await;
	}

	Ok(scanner.into_networks())
}

/// The sweep brings every interface on the phy down, this one included, so the source has to be
/// told: it brings itself back up on the next tune, and without the notice it would tune an
/// interface that is down and report nothing.
fn sweep(daemon: &Rc<Daemon>, source: &dyn FrameSource) {
	let lkl = daemon.lkl();
	let Some(ctx) = lkl.context() else {
		return;
	};

	let _ = free_radio(ctx, &daemon.phyname(), &VifNames::default(), None);
	source.interrupted();
}

fn queue_event(out: &Outbound, event: &Event) {
	let Ok(body) = event.encode() else {
		return;
	};

	let _ = out.unbounded_send(encode_frame(Op::Event, 0, &body));
}
