use std::cell::RefCell;
use std::rc::Rc;

use super::session::Outbound;

use ldn::channel::{DatagramChannel, RawChannel};
use ldn::crypto::KeyError;
use ldn::network::{
	ApNetwork, ConnectError, ConnectParam, CreateError, CreateParam, DISCONNECT_CONNECTION_LOST,
	Network, NetworkEvent,
};
use ldn::protocol::messages::{
	ConnectRequest, CreateNetworkRequest, DatagramData, NetworkReply, encode_data,
};
use ldn::protocol::{Event, Op, Status, WireWrite, encode_frame};
use ldn::wlan::MacAddress;

use super::Daemon;

const POLL_MS: u32 = 1;
const DROP_REPORT_INTERVAL: usize = 1;

enum ChannelKind {
	Raw(Rc<RawChannel>),
	Datagram(Rc<DatagramChannel>),
}

pub(super) struct ChannelState {
	handle: u32,
	kind: ChannelKind,
	reported: usize,
	active: bool,
}

impl ChannelState {
	pub(super) const fn handle(&self) -> u32 {
		self.handle
	}

	/// `payload` is the `DATA` body after the handle.
	pub(super) fn send(&self, payload: &[u8]) -> Result<(), String> {
		match &self.kind {
			ChannelKind::Raw(channel) => channel.send(payload).map_err(|err| format!("{err}")),
			ChannelKind::Datagram(channel) => {
				let data = DatagramData::decode(payload).map_err(|err| format!("{err}"))?;

				channel
					.send_to(&data.payload, data.peer, data.port)
					.map_err(|err| format!("{err}"))
			}
		}
	}

	pub(super) const fn close(&mut self) {
		self.active = false;
	}
}

enum NetworkKind {
	Station(Rc<RefCell<Network>>),
	AccessPoint(Rc<RefCell<ApNetwork>>),
}

pub(super) struct NetworkState {
	handle: u32,
	kind: NetworkKind,
	active: bool,
	ifindex: i32,
}

impl NetworkState {
	pub(super) const fn handle(&self) -> u32 {
		self.handle
	}

	pub(super) const fn ifindex(&self) -> i32 {
		self.ifindex
	}

	pub(super) const fn is_host(&self) -> bool {
		matches!(self.kind, NetworkKind::AccessPoint(_))
	}

	pub(super) fn close(&mut self) {
		self.active = false;

		match &self.kind {
			NetworkKind::Station(network) => {
				if let Ok(mut network) = network.try_borrow_mut() {
					let _ = network.disconnect();
				}
			}
			NetworkKind::AccessPoint(network) => {
				if let Ok(mut network) = network.try_borrow_mut() {
					let _ = network.close();
				}
			}
		}
	}

	pub(super) fn reply(&self) -> NetworkReply {
		match &self.kind {
			NetworkKind::Station(network) => network.try_borrow().map_or_else(
				|_| NetworkReply::error(Status::Internal, "the network is busy"),
				|network| {
					let index = u8::try_from(network.participant_index()).unwrap_or(0);
					NetworkReply::joined(self.handle, network.info().clone(), index)
				},
			),
			NetworkKind::AccessPoint(network) => network.try_borrow().map_or_else(
				|_| NetworkReply::error(Status::Internal, "the network is busy"),
				|network| NetworkReply::joined(self.handle, network.info().clone(), 0),
			),
		}
	}

	fn host(&self) -> Result<std::cell::RefMut<'_, ApNetwork>, (Status, String)> {
		let NetworkKind::AccessPoint(network) = &self.kind else {
			return Err((
				Status::InvalidParam,
				format!(
					"network {} was joined, not created; only a host can be mutated",
					self.handle
				),
			));
		};

		network.try_borrow_mut().map_err(|_| {
			(
				Status::Busy,
				"the network is mid-poll; try again".to_owned(),
			)
		})
	}

	pub(super) fn set_application_data(&self, data: &[u8]) -> Result<(), (Status, String)> {
		self.host()?
			.set_application_data(data)
			.map_err(|err| create_status(&err))
	}

	pub(super) fn set_accept_policy(&self, policy: u8) -> Result<(), (Status, String)> {
		self.host()?.set_accept_policy(policy);

		Ok(())
	}

	pub(super) fn set_accept_filter(
		&self,
		filter: Vec<MacAddress>,
	) -> Result<(), (Status, String)> {
		self.host()?.set_accept_filter(filter);

		Ok(())
	}

	pub(super) fn kick(&self, index: u8) -> Result<(), (Status, String)> {
		self.host()?
			.kick(usize::from(index))
			.map_err(|err| create_status(&err))
	}
}

pub(super) fn connect(
	daemon: &Rc<Daemon>,
	request: &ConnectRequest,
	out: &Outbound,
	request_id: u32,
	handle: u32,
) -> Option<NetworkState> {
	let lkl = daemon.lkl();
	let Some(ctx) = lkl.context() else {
		queue_reply(
			out,
			request_id,
			&NetworkReply::error(Status::NoRadio, "the adapter is not attached"),
		);
		return None;
	};

	let param = ConnectParam {
		phyname: daemon.phyname(),
		ifname: "ldn".to_owned(),
		ifname_monitor: ConnectParam::default().ifname_monitor,
		password: request.password.clone(),
		name: request.name.clone(),
		app_version: request.app_version,
		platform: request.platform,
		enable_challenge: request.enable_challenge,
		device_id: request.device_id,
		// A client that does not supply one gets a fresh value; reusing a random across joins
		// would let a stale response be mistaken for a live one.
		client_random: request.client_random.unwrap_or_else(fresh_random),
		dev: request.dev,
		timeout_ms: request.timeout_ms,
	};

	if let Some(source) = daemon.frame_source() {
		source.interrupted();
	}

	let Some(keys) = daemon.keys() else {
		queue_reply(
			out,
			request_id,
			&connect_error(&ConnectError::Key(KeyError::NotLoaded)),
		);
		return None;
	};

	match Network::connect(ctx, &keys, &request.network, &param) {
		Ok(network) => {
			let index = u8::try_from(network.participant_index()).unwrap_or(0);
			let info = network.info().clone();
			let ifindex = network.station().ifindex();

			let network = Rc::new(RefCell::new(network));

			queue_reply(out, request_id, &NetworkReply::joined(handle, info, index));

			Some(NetworkState {
				handle,
				kind: NetworkKind::Station(network),
				active: true,
				ifindex,
			})
		}
		Err(err) => {
			queue_reply(out, request_id, &connect_error(&err));
			None
		}
	}
}

pub(super) fn create(
	daemon: &Rc<Daemon>,
	request: &CreateNetworkRequest,
	out: &Outbound,
	request_id: u32,
	handle: u32,
) -> Option<NetworkState> {
	let lkl = daemon.lkl();
	let Some(ctx) = lkl.context() else {
		queue_reply(
			out,
			request_id,
			&NetworkReply::error(Status::NoRadio, "the adapter is not attached"),
		);
		return None;
	};

	let defaults = CreateParam::default();

	let param = CreateParam {
		phyname: daemon.phyname(),
		ifname: defaults.ifname,
		phyname_monitor: daemon.phyname(),
		ifname_monitor: defaults.ifname_monitor,
		local_communication_id: request.local_communication_id,
		scene_id: request.scene_id,
		max_participants: request
			.max_participants
			.unwrap_or(defaults.max_participants),
		application_data: request.application_data.clone(),
		accept_policy: request.accept_policy.unwrap_or(defaults.accept_policy),
		accept_filter: request.accept_filter.clone(),
		security_mode: request.security_mode.unwrap_or(defaults.security_mode),
		ssid: request.ssid,
		name: request.name.clone(),
		app_version: request.app_version,
		platform: request.platform,
		channel: request.channel,
		server_random: request.server_random,
		password: request.password.clone(),
		version: request.version.unwrap_or(defaults.version),
		enable_challenge: request.enable_challenge,
		device_id: request.device_id,
		protocol: request.protocol.unwrap_or(defaults.protocol),
		dev: request.dev,
	};

	// Hosting takes the phy the same way joining does: the AP and the monitor both come out of it,
	// and `free_radio` tears down whatever was there. Telling the scanner means the next scan
	// rebuilds its monitor rather than tuning one that no longer exists.
	if let Some(source) = daemon.frame_source() {
		source.interrupted();
	}

	let Some(keys) = daemon.keys() else {
		let (status, message) = create_status(&CreateError::Key(KeyError::NotLoaded));
		queue_reply(out, request_id, &NetworkReply::error(status, message));
		return None;
	};

	match ApNetwork::create(ctx, &keys, &param) {
		Ok(network) => {
			let info = network.info().clone();
			let ifindex = network.access_point().ifindex();

			let network = Rc::new(RefCell::new(network));

			queue_reply(out, request_id, &NetworkReply::joined(handle, info, 0));

			Some(NetworkState {
				handle,
				kind: NetworkKind::AccessPoint(network),
				active: true,
				ifindex,
			})
		}
		Err(err) => {
			let (status, message) = create_status(&err);
			queue_reply(out, request_id, &NetworkReply::error(status, message));

			None
		}
	}
}

fn create_status(err: &CreateError) -> (Status, String) {
	let status = match err {
		CreateError::InvalidParam { .. } | CreateError::NoParticipant { .. } => {
			Status::InvalidParam
		}
		CreateError::Key(_) => Status::NoKeys,
		CreateError::Random => Status::Internal,
		_ => Status::Io,
	};

	(status, format!("{err}"))
}

impl NetworkState {
	pub(super) fn poll(&mut self, out: &Outbound) {
		if !self.active {
			return;
		}
		let event = match &self.kind {
			NetworkKind::Station(network) => network.borrow_mut().poll(POLL_MS).map_err(|_| ()),
			NetworkKind::AccessPoint(network) => {
				let mut network = network.borrow_mut();
				if network.is_stopped() {
					self.active = false;
					return;
				}
				network.poll(POLL_MS).map_err(|_| ())
			}
		};
		let event = match event {
			Ok(Some(event)) => event,
			Ok(None) => return,
			Err(()) => NetworkEvent::Disconnect {
				reason: DISCONNECT_CONNECTION_LOST,
			},
		};
		if matches!(event, NetworkEvent::Disconnect { .. }) {
			self.active = false;
		}
		queue_event(out, &wire_event(self.handle, &event));
	}
}

pub(super) fn open_raw(
	ctx: ldn::sys::KernelContext,
	ifindex: i32,
	handle: u32,
) -> Result<ChannelState, String> {
	let channel = Rc::new(RawChannel::open(ctx, ifindex).map_err(|err| format!("{err}"))?);

	Ok(ChannelState {
		handle,
		kind: ChannelKind::Raw(channel),
		reported: 0,
		active: true,
	})
}

pub(super) fn open_datagram(
	ctx: ldn::sys::KernelContext,
	port: u16,
	handle: u32,
) -> Result<(ChannelState, u16), String> {
	let channel = Rc::new(DatagramChannel::open(ctx, port).map_err(|err| format!("{err}"))?);
	let bound = channel.port();

	let state = ChannelState {
		handle,
		kind: ChannelKind::Datagram(channel),
		reported: 0,
		active: true,
	};

	Ok((state, bound))
}

impl ChannelState {
	pub(super) fn poll(&mut self, out: &Outbound) {
		if !self.active {
			return;
		}
		for _ in 0..64 {
			let payload = match &self.kind {
				ChannelKind::Raw(channel) => channel.try_next_frame(),
				ChannelKind::Datagram(channel) => channel.try_next_datagram().map(|datagram| {
					DatagramData::new(datagram.peer, datagram.port, &datagram.payload).encode()
				}),
			};
			match payload {
				Ok(payload) => {
					if out
						.send(encode_frame(
							Op::Data,
							0,
							&encode_data(self.handle, &payload),
						))
						.is_err()
					{
						self.active = false;
						return;
					}
				}
				Err(std::sync::mpsc::TryRecvError::Empty) => break,
				Err(std::sync::mpsc::TryRecvError::Disconnected) => {
					self.active = false;
					break;
				}
			}
		}
		if let ChannelKind::Raw(channel) = &self.kind {
			let dropped = channel.dropped();
			if dropped.saturating_sub(self.reported) >= DROP_REPORT_INTERVAL {
				self.reported = dropped;
				queue_event(
					out,
					&Event::ChannelError {
						handle: self.handle,
						status: Status::Io.value(),
						message: format!("the channel reader has dropped {dropped} frames"),
					},
				);
			}
		}
	}
}

fn connect_error(err: &ConnectError) -> NetworkReply {
	let (status, auth_status) = match err {
		ConnectError::Rejected { status } => (Status::AuthFailed, Some(*status)),
		ConnectError::AuthTimeout(_) => (Status::AuthFailed, None),
		ConnectError::NotListed | ConnectError::Disassociated => (Status::Timeout, None),
		ConnectError::Key(_) => (Status::NoKeys, None),
		ConnectError::NoAddress => (Status::NoRadio, None),
		_ => (Status::Io, None),
	};

	NetworkReply {
		auth_status,
		..NetworkReply::error(status, format!("{err}"))
	}
}

fn wire_event(handle: u32, event: &NetworkEvent) -> Event {
	match event {
		NetworkEvent::Join { index, participant } => Event::Join {
			handle,
			index: u8::try_from(*index).unwrap_or(0),
			participant: participant.clone(),
		},
		NetworkEvent::Leave { index, participant } => Event::Leave {
			handle,
			index: u8::try_from(*index).unwrap_or(0),
			participant: participant.clone(),
		},
		NetworkEvent::Disconnect { reason } => Event::Disconnect {
			handle,
			reason: *reason,
		},
		NetworkEvent::ApplicationDataChanged { old, new } => Event::AppDataChanged {
			handle,
			old: old.clone(),
			new: new.clone(),
		},
		NetworkEvent::AcceptPolicyChanged { old, new } => Event::PolicyChanged {
			handle,
			old: *old,
			new: *new,
		},
	}
}

fn queue_reply(out: &Outbound, request_id: u32, reply: &NetworkReply) {
	let body = reply.encode().unwrap_or_default();
	let _ = out.send(encode_frame(Op::Reply, request_id, &body));
}

fn queue_event(out: &Outbound, event: &Event) {
	let Ok(body) = event.encode() else {
		return;
	};

	let _ = out.send(encode_frame(Op::Event, 0, &body));
}

fn fresh_random() -> [u8; 16] {
	let nanos = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map_or(0, |since| since.subsec_nanos());

	std::array::from_fn(|i| {
		u8::try_from((usize::try_from(nanos).unwrap_or(0) ^ (i << 3)) & 0xFF).unwrap_or(0)
	})
}
