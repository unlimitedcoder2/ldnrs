use std::cell::Cell;
use std::rc::Rc;

use compio::fs::named_pipe::NamedPipeServer;
use futures_channel::mpsc::{UnboundedSender, unbounded};
use futures_util::StreamExt;

use crate::daemon::codec::{Frame, read_frame, write_frame};
use crate::daemon::network::{ChannelState, NetworkState};
use crate::daemon::{ClientIdent, ControlGuard, Daemon};
use ldn::broadcast::Event as BroadcastEvent;
use ldn::crypto::Keys;
use ldn::protocol::messages::{
	ChannelReply, ConnectRequest, CreateNetworkRequest, HandleRequest, HasProdKeysReply,
	KickRequest, OpenDatagramReply, OpenDatagramRequest, SetAcceptFilterRequest,
	SetAcceptPolicyRequest, SetApplicationDataRequest, SetProdKeysRequest, decode_data,
};
use ldn::protocol::{
	Event, Hello, HelloReply, LdnOp, Op, PROTOCOL_VERSION, ScanRequest, Status, StatusReply,
	WireWrite, encode_frame,
};
use ldn::protocol::{WireRead, WirelessProtocol};

pub(super) type Outbound = UnboundedSender<Vec<u8>>;

pub(super) async fn run(daemon: Rc<Daemon>, pipe: NamedPipeServer) {
	let pipe = Rc::new(pipe);

	// The handshake is written directly rather than through the outbound queue: a refused client
	// must see its reply before the pipe closes, and there is no writer task yet to flush it.
	let (control, protocol) = match handshake(&daemon, &pipe).await {
		Ok(Some(accepted)) => accepted,
		Ok(None) => return,
		Err(err) => {
			daemon.log(&format!("connection failed during handshake: {err}"));
			return;
		}
	};

	let (out_tx, mut out_rx) = unbounded::<Vec<u8>>();

	let writer_pipe = Rc::clone(&pipe);
	let writer = compio::runtime::spawn(async move {
		while let Some(bytes) = out_rx.next().await {
			if write_frame(&writer_pipe, bytes).await.is_err() {
				break;
			}
		}
	});

	let radio = spawn_radio_pump(&daemon, out_tx.clone());
	let mut logs = None;
	let mut state = ProtocolState::new(protocol);

	let result = serve_requests(&daemon, &pipe, &out_tx, &mut logs, &mut state).await;

	state.close();
	if let Err(err) = result {
		daemon.log(&format!("connection closed: {err}"));
	}

	drop(radio);
	drop(state);
	drop(logs);
	drop(out_tx);
	drop(writer);
	drop(control);
}

/// `Ok(None)` means the client was answered and should be disconnected.
async fn handshake(
	daemon: &Rc<Daemon>,
	pipe: &NamedPipeServer,
) -> std::io::Result<Option<(ControlGuard, WirelessProtocol)>> {
	let Some(frame) = read_frame(pipe, Vec::new()).await? else {
		return Ok(None);
	};

	let request_id = frame.header.request_id;

	if frame.header.op() != Some(Op::Hello) {
		let reply = StatusReply::error(
			Status::BadRequest,
			"the first frame on a connection must be Hello",
		);
		send_status(pipe, request_id, &reply).await?;
		return Ok(None);
	}

	let hello = match Hello::decode(&frame.body) {
		Ok(hello) => hello,
		Err(err) => {
			let reply = StatusReply::error(Status::BadRequest, format!("malformed Hello: {err}"));
			send_status(pipe, request_id, &reply).await?;
			return Ok(None);
		}
	};

	if hello.protocol_version != PROTOCOL_VERSION {
		let reply = refusal(
			daemon,
			Status::UnsupportedVersion,
			format!(
				"this daemon speaks protocol version {PROTOCOL_VERSION}, the client asked for {}",
				hello.protocol_version
			),
		);
		send_hello_reply(pipe, request_id, &reply).await?;
		return Ok(None);
	}

	let Some(protocol) = hello.wireless_protocol() else {
		let reply = refusal(
			daemon,
			Status::Unsupported,
			format!(
				"this daemon does not know wireless protocol {}",
				hello.wireless_protocol
			),
		);
		send_hello_reply(pipe, request_id, &reply).await?;
		return Ok(None);
	};

	let ident = ClientIdent {
		name: hello.client_name.clone(),
		version: hello.client_version.clone(),
		protocol,
	};

	let Some(control) = daemon.take_control(ident.clone()) else {
		let holder = daemon.control_holder();
		let reply = refusal(
			daemon,
			Status::Busy,
			format!("another client holds this daemon: {holder}"),
		);
		send_hello_reply(pipe, request_id, &reply).await?;

		return Ok(None);
	};

	daemon.log(&format!("client connected: {ident}"));

	let reply = HelloReply {
		status: Status::None,
		protocol_version: PROTOCOL_VERSION,
		daemon_version: daemon.version().to_owned(),
		capabilities: daemon.capabilities(),
		radio_ready: daemon.radio_state() == ldn::protocol::RadioState::Ready,
		error_message: None,
	};
	send_hello_reply(pipe, request_id, &reply).await?;

	Ok(Some((control, protocol)))
}

fn refusal(daemon: &Rc<Daemon>, status: Status, message: String) -> HelloReply {
	HelloReply {
		status,
		error_message: Some(message),
		protocol_version: PROTOCOL_VERSION,
		daemon_version: daemon.version().to_owned(),
		capabilities: daemon.capabilities(),
		radio_ready: daemon.radio_state() == ldn::protocol::RadioState::Ready,
	}
}

enum ProtocolState {
	Ldn(LdnState),
	Nwm,
}

impl ProtocolState {
	fn new(protocol: WirelessProtocol) -> Self {
		match protocol {
			WirelessProtocol::Ldn => Self::Ldn(LdnState::default()),
			WirelessProtocol::Nwm => Self::Nwm,
		}
	}

	fn close(&mut self) {
		match self {
			Self::Ldn(ldn) => ldn.networks.close_all(),
			Self::Nwm => {}
		}
	}
}

#[derive(Default)]
struct LdnState {
	scan: ScanState,
	networks: Networks,
}

#[derive(Default)]
struct Networks {
	current: Option<NetworkState>,
	channels: Vec<ChannelState>,
	/// Handles are assigned in order and never reused, so a stale handle is always an error rather
	/// than a reference to somebody else's network.
	next_handle: u32,
}

impl Networks {
	const fn allocate(&mut self) -> u32 {
		self.next_handle = self.next_handle + 1;
		self.next_handle
	}

	const fn get(&self, handle: u32) -> Option<&NetworkState> {
		match &self.current {
			Some(network) if network.handle() == handle => Some(network),
			_ => None,
		}
	}

	fn network(&self, handle: u32) -> Result<&NetworkState, (Status, String)> {
		self.get(handle).ok_or_else(|| {
			(
				Status::InvalidHandle,
				format!("no network with handle {handle}"),
			)
		})
	}

	fn channel(&self, handle: u32) -> Option<&ChannelState> {
		self.channels
			.iter()
			.find(|channel| channel.handle() == handle)
	}

	fn close_channel(&mut self, handle: u32) -> bool {
		let Some(index) = self
			.channels
			.iter()
			.position(|channel| channel.handle() == handle)
		else {
			return false;
		};

		let mut channel = self.channels.remove(index);
		channel.close();

		true
	}

	/// Channels first: they are bound to the network's interface, and leaving them open across the
	/// disconnect would keep a reader thread on an interface that is going down.
	fn close_all(&mut self) {
		for mut channel in self.channels.drain(..) {
			channel.close();
		}

		if let Some(mut network) = self.current.take() {
			network.close();
		}
	}
}

#[derive(Default)]
struct ScanState {
	task: Option<compio::runtime::JoinHandle<()>>,
	cancel: Option<Rc<Cell<bool>>>,
}

impl ScanState {
	fn is_running(&self) -> bool {
		self.task.as_ref().is_some_and(|task| !task.is_finished())
	}

	fn request_cancel(&self) {
		if let Some(cancel) = &self.cancel {
			cancel.set(true);
		}
	}
}

async fn serve_requests(
	daemon: &Rc<Daemon>,
	pipe: &NamedPipeServer,
	out: &Outbound,
	logs: &mut Option<compio::runtime::JoinHandle<()>>,
	state: &mut ProtocolState,
) -> std::io::Result<()> {
	let mut body = Vec::new();
	while let Some(frame) = read_frame(pipe, body).await? {
		dispatch(daemon, &frame, out, logs, state);
		body = frame.body;
	}

	Ok(())
}

fn dispatch_channel(daemon: &Rc<Daemon>, frame: &Frame, out: &Outbound, networks: &mut Networks) {
	let request_id = frame.header.request_id;

	let reply = match frame.header.ldn_op() {
		Some(op @ (LdnOp::OpenRaw | LdnOp::OpenDatagram)) => {
			let request = if op == LdnOp::OpenDatagram {
				OpenDatagramRequest::decode(&frame.body)
			} else {
				HandleRequest::decode(&frame.body).map(|request| OpenDatagramRequest {
					handle: request.handle,
					port: 0,
				})
			};

			let request = match request {
				Ok(request) => request,
				Err(err) => {
					let (status, message) = bad_request(op.name(), &err);
					queue_status(out, request_id, &StatusReply::error(status, message));
					return;
				}
			};

			let ifindex = match networks.network(request.handle) {
				Ok(network) => network.ifindex(),
				Err((status, message)) => {
					queue_status(out, request_id, &StatusReply::error(status, message));
					return;
				}
			};

			let lkl = daemon.lkl();

			let Some(ctx) = lkl.context() else {
				queue_status(
					out,
					request_id,
					&StatusReply::error(Status::NoRadio, "the adapter is not attached"),
				);
				return;
			};

			let handle = networks.allocate();

			let opened = if op == LdnOp::OpenDatagram {
				super::network::open_datagram(ctx, request.port, out, handle).map(
					|(channel, bound)| {
						(
							channel,
							OpenDatagramReply::ok(handle, bound)
								.encode()
								.unwrap_or_default(),
						)
					},
				)
			} else {
				super::network::open_raw(ctx, ifindex, out, handle).map(|channel| {
					(
						channel,
						ChannelReply::ok(handle).encode().unwrap_or_default(),
					)
				})
			};

			match opened {
				Ok((channel, body)) => {
					networks.channels.push(channel);

					let _ = out.unbounded_send(encode_frame(Op::Reply, request_id, &body));
					return;
				}
				Err(message) => StatusReply::error(Status::Io, message),
			}
		}

		Some(LdnOp::CloseChannel) => match HandleRequest::decode(&frame.body) {
			Ok(request) if networks.close_channel(request.handle) => StatusReply::ok(),
			Ok(request) => StatusReply::error(
				Status::InvalidHandle,
				format!("no channel with handle {}", request.handle),
			),
			Err(err) => {
				let (status, message) = bad_request("CloseChannel", &err);
				StatusReply::error(status, message)
			}
		},

		_ => StatusReply::error(Status::Internal, "not a channel operation"),
	};

	queue_status(out, request_id, &reply);
}

fn send_data(frame: &Frame, out: &Outbound, networks: &Networks) {
	let (handle, failure) = match decode_data(&frame.body) {
		Err(err) => (
			0,
			Some((Status::BadRequest, format!("malformed Data: {err}"))),
		),
		Ok((handle, payload)) => (
			handle,
			networks.channel(handle).map_or_else(
				|| {
					Some((
						Status::InvalidHandle,
						format!("no channel with handle {handle}"),
					))
				},
				|channel| {
					channel
						.send(payload)
						.err()
						.map(|message| (Status::Io, message))
				},
			),
		),
	};

	if let Some((status, message)) = failure {
		queue_event(
			out,
			&Event::ChannelError {
				handle,
				status: status.value(),
				message,
			},
		);
	}
}

fn dispatch_host(frame: &Frame, out: &Outbound, networks: &Networks) {
	let request_id = frame.header.request_id;

	let outcome = match frame.header.ldn_op() {
		Some(LdnOp::SetApplicationData) => SetApplicationDataRequest::decode(&frame.body)
			.map_err(|err| bad_request("SetApplicationData", &err))
			.and_then(|request| {
				networks
					.network(request.handle)?
					.set_application_data(&request.application_data)
			}),

		Some(LdnOp::SetAcceptPolicy) => SetAcceptPolicyRequest::decode(&frame.body)
			.map_err(|err| bad_request("SetAcceptPolicy", &err))
			.and_then(|request| {
				networks
					.network(request.handle)?
					.set_accept_policy(request.accept_policy)
			}),

		Some(LdnOp::SetAcceptFilter) => SetAcceptFilterRequest::decode(&frame.body)
			.map_err(|err| bad_request("SetAcceptFilter", &err))
			.and_then(|request| {
				networks
					.network(request.handle)?
					.set_accept_filter(request.accept_filter)
			}),

		Some(LdnOp::Kick) => KickRequest::decode(&frame.body)
			.map_err(|err| bad_request("Kick", &err))
			.and_then(|request| {
				networks
					.network(request.handle)?
					.kick(request.participant_index)
			}),

		_ => Err((Status::Internal, "not a host operation".to_owned())),
	};

	let reply = match outcome {
		Ok(()) => StatusReply::ok(),
		Err((status, message)) => StatusReply::error(status, message),
	};

	queue_status(out, request_id, &reply);
}

fn bad_request(op: &str, err: &ldn::protocol::DecodeError) -> (Status, String) {
	(Status::BadRequest, format!("malformed {op}: {err}"))
}

fn dispatch_network(daemon: &Rc<Daemon>, frame: &Frame, out: &Outbound, networks: &mut Networks) {
	let request_id = frame.header.request_id;

	let reply = match frame.header.ldn_op() {
		Some(LdnOp::Connect) => {
			if networks.current.is_some() {
				StatusReply::error(
					Status::Busy,
					"this connection already has a network open; close it first",
				)
			} else {
				match ConnectRequest::decode(&frame.body) {
					Ok(request) => {
						let handle = networks.allocate();
						networks.current =
							super::network::connect(daemon, &request, out, request_id, handle);

						return;
					}
					Err(err) => {
						StatusReply::error(Status::BadRequest, format!("malformed Connect: {err}"))
					}
				}
			}
		}

		Some(LdnOp::CreateNetwork) => {
			if networks.current.is_some() {
				StatusReply::error(
					Status::Busy,
					"this connection already has a network open; close it first",
				)
			} else {
				match CreateNetworkRequest::decode(&frame.body) {
					Ok(request) => {
						let handle = networks.allocate();
						networks.current =
							super::network::create(daemon, &request, out, request_id, handle);

						return;
					}
					Err(err) => StatusReply::error(
						Status::BadRequest,
						format!("malformed CreateNetwork: {err}"),
					),
				}
			}
		}

		Some(op @ (LdnOp::CloseNetwork | LdnOp::GetNetworkInfo)) => {
			let network = HandleRequest::decode(&frame.body)
				.map_err(|err| bad_request(op.name(), &err))
				.and_then(|request| networks.network(request.handle));

			match (op, network) {
				(_, Err((status, message))) => StatusReply::error(status, message),

				(LdnOp::GetNetworkInfo, Ok(network)) => {
					let body = network.reply().encode().unwrap_or_default();
					let _ = out.unbounded_send(encode_frame(Op::Reply, request_id, &body));

					return;
				}

				(_, Ok(network)) => {
					if network.is_host() {
						daemon
							.log("the hosted network is being taken down at the client's request");
					}

					networks.close_all();
					StatusReply::ok()
				}
			}
		}

		_ => StatusReply::error(Status::Internal, "not a network operation"),
	};

	queue_status(out, request_id, &reply);
}

fn dispatch(
	daemon: &Rc<Daemon>,
	frame: &Frame,
	out: &Outbound,
	logs: &mut Option<compio::runtime::JoinHandle<()>>,
	state: &mut ProtocolState,
) {
	let request_id = frame.header.request_id;

	let reply = match frame.header.op() {
		Some(Op::Hello) => StatusReply::error(
			Status::BadRequest,
			"Hello may only be sent once, as the first frame",
		),

		Some(Op::SubscribeLog) => {
			if logs.is_none() {
				*logs = Some(spawn_log_pump(daemon, out.clone()));
			}
			StatusReply::ok()
		}

		Some(Op::Shutdown) => {
			daemon.request_shutdown();
			StatusReply::ok()
		}

		Some(op @ (Op::Reply | Op::Event)) => StatusReply::error(
			Status::BadRequest,
			format!("{} is not a request", op.name()),
		),

		Some(Op::Ldn | Op::Nwm | Op::Data) => {
			match state {
				ProtocolState::Ldn(ldn) => dispatch_ldn(daemon, frame, out, ldn),
				ProtocolState::Nwm => super::nwm::dispatch(frame, out),
			}
			return;
		}

		None => StatusReply::error(
			Status::Unsupported,
			format!("unknown opcode {:#04x}", frame.header.op),
		),
	};

	queue_status(out, request_id, &reply);
}

/// Returns without queueing anything for operations that answer asynchronously: a scan takes
/// roughly `channels x dwell` and replies from its own task, so that the read loop stays free to
/// receive the `ScanCancel` that might stop it.
fn dispatch_ldn(daemon: &Rc<Daemon>, frame: &Frame, out: &Outbound, state: &mut LdnState) {
	let request_id = frame.header.request_id;
	let LdnState { scan, networks } = state;

	if frame.header.op() == Some(Op::Data) {
		send_data(frame, out, networks);
		return;
	}

	let Some(op) = frame.header.ldn_op() else {
		let message = if frame.header.op() == Some(Op::Ldn) {
			format!("unknown LDN operation {:#04x}", frame.header.sub_op)
		} else {
			"this connection selected LDN in Hello".to_owned()
		};

		queue_status(
			out,
			request_id,
			&StatusReply::error(Status::Unsupported, message),
		);
		return;
	};

	if op == LdnOp::Scan {
		if scan.is_running() {
			queue_status(
				out,
				request_id,
				&StatusReply::error(Status::Busy, "a scan is already running on this connection"),
			);
			return;
		}

		let request = match ScanRequest::decode(&frame.body) {
			Ok(request) => request,
			Err(err) => {
				queue_status(
					out,
					request_id,
					&StatusReply::error(Status::BadRequest, format!("malformed Scan: {err}")),
				);
				return;
			}
		};

		let cancel = Rc::new(Cell::new(false));
		scan.cancel = Some(Rc::clone(&cancel));
		scan.task = Some(compio::runtime::spawn(super::scan::run(
			Rc::clone(daemon),
			request,
			out.clone(),
			request_id,
			cancel,
		)));

		return;
	}

	let reply = match op {
		LdnOp::ScanCancel => {
			scan.request_cancel();
			StatusReply::ok()
		}

		LdnOp::Connect | LdnOp::CreateNetwork | LdnOp::CloseNetwork | LdnOp::GetNetworkInfo => {
			dispatch_network(daemon, frame, out, networks);
			return;
		}

		LdnOp::SetApplicationData
		| LdnOp::SetAcceptPolicy
		| LdnOp::SetAcceptFilter
		| LdnOp::Kick => {
			dispatch_host(frame, out, networks);
			return;
		}

		LdnOp::OpenRaw | LdnOp::OpenDatagram | LdnOp::CloseChannel => {
			dispatch_channel(daemon, frame, out, networks);
			return;
		}

		LdnOp::SetProdKeys => match SetProdKeysRequest::decode(&frame.body) {
			Ok(request) => match Keys::parse(&request.prod_keys) {
				Ok(keys) => {
					daemon.set_keys(keys);
					StatusReply::ok()
				}
				Err(err) => {
					StatusReply::error(Status::BadRequest, format!("malformed prod.keys: {err}"))
				}
			},
			Err(err) => {
				StatusReply::error(Status::BadRequest, format!("malformed SetProdKeys: {err}"))
			}
		},

		LdnOp::HasProdKeys => {
			let body = HasProdKeysReply::ok(daemon.keys().is_some())
				.encode()
				.unwrap_or_default();
			let _ = out.unbounded_send(encode_frame(Op::Reply, request_id, &body));
			return;
		}

		LdnOp::Scan => StatusReply::error(
			Status::Internal,
			"Scan should have been handled by its own task",
		),
	};

	queue_status(out, request_id, &reply);
}

fn spawn_radio_pump(daemon: &Rc<Daemon>, out: Outbound) -> compio::runtime::JoinHandle<()> {
	let mut updates = daemon.subscribe_radio();

	compio::runtime::spawn(async move {
		loop {
			let event = match updates.try_recv() {
				Ok(event) => event,
				Err(std::sync::mpsc::TryRecvError::Empty) => {
					compio::time::sleep(std::time::Duration::from_millis(10)).await;
					continue;
				}
				Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
			};
			let BroadcastEvent::Item(update) = event else {
				continue;
			};

			queue_event(
				&out,
				&Event::Radio {
					state: update.state.value(),
					message: update.message,
				},
			);
		}
	})
}

fn spawn_log_pump(daemon: &Rc<Daemon>, out: Outbound) -> compio::runtime::JoinHandle<()> {
	let mut logs = daemon.logs();

	compio::runtime::spawn(async move {
		loop {
			let event = match logs.try_recv() {
				Ok(event) => event,
				Err(std::sync::mpsc::TryRecvError::Empty) => {
					compio::time::sleep(std::time::Duration::from_millis(10)).await;
					continue;
				}
				Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
			};
			let message = match event {
				BroadcastEvent::Item(line) => Event::Log { line },
				BroadcastEvent::Dropped(lines) => Event::LogDropped {
					lines: u32::try_from(lines).unwrap_or(u32::MAX),
				},
			};

			queue_event(&out, &message);
		}
	})
}

async fn send_status(
	pipe: &NamedPipeServer,
	request_id: u32,
	reply: &StatusReply,
) -> std::io::Result<()> {
	let body = reply.encode().unwrap_or_default();
	write_frame(pipe, encode_frame(Op::Reply, request_id, &body)).await
}

async fn send_hello_reply(
	pipe: &NamedPipeServer,
	request_id: u32,
	reply: &HelloReply,
) -> std::io::Result<()> {
	let body = reply.encode().unwrap_or_default();
	write_frame(pipe, encode_frame(Op::Reply, request_id, &body)).await
}

pub(super) fn queue_status(out: &Outbound, request_id: u32, reply: &StatusReply) {
	let body = reply.encode().unwrap_or_default();
	let _ = out.unbounded_send(encode_frame(Op::Reply, request_id, &body));
}

pub(super) fn queue_event(out: &Outbound, event: &Event) {
	let Ok(body) = event.encode() else {
		return;
	};

	let _ = out.unbounded_send(encode_frame(Op::Event, 0, &body));
}
