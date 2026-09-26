use std::collections::VecDeque;
use std::io::Write;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender, channel};

use super::pipe::Pipe;
use crate::daemon::codec::{Frame, FrameReader};
use crate::daemon::network::{ChannelState, NetworkState};
use crate::daemon::{ClientIdent, ControlGuard, Daemon};
use ldn::broadcast::Event as BroadcastEvent;
use ldn::crypto::Keys;
use ldn::logs::LogReceiver;
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

pub(super) type Outbound = Sender<Vec<u8>>;

pub(super) struct Session {
	daemon: Rc<Daemon>,
	pipe: Pipe,
	reader: FrameReader,
	out: Outbound,
	incoming: Receiver<Vec<u8>>,
	pending: VecDeque<Vec<u8>>,
	written: usize,
	control: Option<ControlGuard>,
	state: Option<ProtocolState>,
	radio: ldn::broadcast::Receiver<super::RadioUpdate>,
	logs: Option<LogReceiver>,
	closing: bool,
}

impl Session {
	pub(super) fn new(daemon: Rc<Daemon>, pipe: Pipe) -> Self {
		let (out, incoming) = channel();
		let radio = daemon.subscribe_radio();
		Self {
			daemon,
			pipe,
			reader: FrameReader::default(),
			out,
			incoming,
			pending: VecDeque::new(),
			written: 0,
			control: None,
			state: None,
			radio,
			logs: None,
			closing: false,
		}
	}

	pub(super) fn poll(&mut self) -> std::io::Result<bool> {
		// Bound work per turn so a busy client cannot starve cancellation or other clients.
		for _ in 0..64 {
			if self.closing {
				break;
			}
			let Some(frame) = self.reader.read(&mut self.pipe)? else {
				break;
			};
			if let Some(state) = &mut self.state {
				dispatch(&self.daemon, &frame, &self.out, &mut self.logs, state);
			} else if let Some((control, protocol)) = handshake(&self.daemon, &frame, &self.out) {
				self.control = Some(control);
				self.state = Some(ProtocolState::new(protocol));
			} else {
				self.closing = true;
			}
		}
		if let Some(state) = &mut self.state {
			if let ProtocolState::Ldn(ldn) = state {
				if let Some(scan) = &mut ldn.scan
					&& scan.poll(&self.daemon, &self.out)
				{
					ldn.scan = None;
				}
				if let Some(network) = &mut ldn.networks.current {
					network.poll(&self.out);
				}
				for channel in &mut ldn.networks.channels {
					channel.poll(&self.out);
				}
			}
			for _ in 0..64 {
				let Ok(event) = self.radio.try_recv() else {
					break;
				};
				if let BroadcastEvent::Item(update) = event {
					queue_event(
						&self.out,
						&Event::Radio {
							state: update.state.value(),
							message: update.message,
						},
					);
				}
			}
			if let Some(logs) = &mut self.logs {
				for _ in 0..64 {
					let Ok(event) = logs.try_recv() else {
						break;
					};
					let event = match event {
						BroadcastEvent::Item(line) => Event::Log { line },
						BroadcastEvent::Dropped(lines) => Event::LogDropped {
							lines: u32::try_from(lines).unwrap_or(u32::MAX),
						},
					};
					queue_event(&self.out, &event);
				}
			}
		}
		self.pending.extend(self.incoming.try_iter());
		for _ in 0..64 {
			let Some(bytes) = self.pending.front() else {
				break;
			};
			let remaining = bytes.get(self.written..).unwrap_or_default();
			match self.pipe.write(remaining) {
				Ok(0) => break,
				Ok(written) => self.written += written,
				Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
				Err(err) => return Err(err),
			}
			if self.written == bytes.len() {
				self.pending.pop_front();
				self.written = 0;
			}
		}
		Ok(!self.closing || !self.pending.is_empty())
	}
}

impl Drop for Session {
	fn drop(&mut self) {
		if let Some(state) = &mut self.state {
			state.close();
		}
	}
}

/// `None` means the client was answered and should be disconnected.
fn handshake(
	daemon: &Rc<Daemon>,
	frame: &Frame,
	out: &Outbound,
) -> Option<(ControlGuard, WirelessProtocol)> {
	let request_id = frame.header.request_id;

	if frame.header.op() != Some(Op::Hello) {
		let reply = StatusReply::error(
			Status::BadRequest,
			"the first frame on a connection must be Hello",
		);
		queue_status(out, request_id, &reply);
		return None;
	}

	let hello = match Hello::decode(&frame.body) {
		Ok(hello) => hello,
		Err(err) => {
			let reply = StatusReply::error(Status::BadRequest, format!("malformed Hello: {err}"));
			queue_status(out, request_id, &reply);
			return None;
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
		queue_hello_reply(out, request_id, &reply);
		return None;
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
		queue_hello_reply(out, request_id, &reply);
		return None;
	};

	let ident = ClientIdent {
		name: hello.client_name,
		version: hello.client_version,
		protocol,
	};

	let Some(control) = daemon.take_control(ident.clone()) else {
		let holder = daemon.control_holder();
		let reply = refusal(
			daemon,
			Status::Busy,
			format!("another client holds this daemon: {holder}"),
		);
		queue_hello_reply(out, request_id, &reply);

		return None;
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
	queue_hello_reply(out, request_id, &reply);

	Some((control, protocol))
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
	Ldn(Box<LdnState>),
	Nwm,
}

impl ProtocolState {
	fn new(protocol: WirelessProtocol) -> Self {
		match protocol {
			WirelessProtocol::Ldn => Self::Ldn(Box::default()),
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
	scan: Option<super::scan::Scan>,
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
				super::network::open_datagram(ctx, request.port, handle).map(|(channel, bound)| {
					(
						channel,
						OpenDatagramReply::ok(handle, bound)
							.encode()
							.unwrap_or_default(),
					)
				})
			} else {
				super::network::open_raw(ctx, ifindex, handle).map(|channel| {
					(
						channel,
						ChannelReply::ok(handle).encode().unwrap_or_default(),
					)
				})
			};

			match opened {
				Ok((channel, body)) => {
					networks.channels.push(channel);

					let _ = out.send(encode_frame(Op::Reply, request_id, &body));
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
					let _ = out.send(encode_frame(Op::Reply, request_id, &body));

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
	logs: &mut Option<LogReceiver>,
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
				*logs = Some(daemon.logs());
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

/// Scans advance between requests so `ScanCancel` remains responsive during a dwell.
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
		if scan.is_some() {
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

		*scan = super::scan::Scan::start(daemon, &request, out, request_id);

		return;
	}

	let reply = match op {
		LdnOp::ScanCancel => {
			if let Some(scan) = scan.take() {
				scan.finish(out);
			}
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
			let _ = out.send(encode_frame(Op::Reply, request_id, &body));
			return;
		}

		LdnOp::Scan => StatusReply::error(
			Status::Internal,
			"Scan should have been handled before dispatch",
		),
	};

	queue_status(out, request_id, &reply);
}

fn queue_hello_reply(out: &Outbound, request_id: u32, reply: &HelloReply) {
	let body = reply.encode().unwrap_or_default();
	let _ = out.send(encode_frame(Op::Reply, request_id, &body));
}

pub(super) fn queue_status(out: &Outbound, request_id: u32, reply: &StatusReply) {
	let body = reply.encode().unwrap_or_default();
	let _ = out.send(encode_frame(Op::Reply, request_id, &body));
}

pub(super) fn queue_event(out: &Outbound, event: &Event) {
	let Ok(body) = event.encode() else {
		return;
	};

	let _ = out.send(encode_frame(Op::Event, 0, &body));
}
