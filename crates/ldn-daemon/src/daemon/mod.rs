mod codec;
mod network;
mod nwm;
mod scan;
mod session;

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use compio::fs::named_pipe::ServerOptions;
use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures_util::StreamExt;

use ldn::Lkl;
use ldn::broadcast::{Broadcast, Receiver};
use ldn::crypto::Keys;
use ldn::logs::LogReceiver;
use ldn::protocol::messages::{Capabilities, LdnCapability, NwmCapability};
use ldn::protocol::{RadioState, WirelessProtocol};
use ldn::scan::FrameSource;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct ClientIdent {
	pub(crate) name: String,
	pub(crate) version: String,
	pub(crate) protocol: WirelessProtocol,
}

impl core::fmt::Display for ClientIdent {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		if self.version.is_empty() {
			write!(f, "{}", self.name)?;
		} else {
			write!(f, "{} {}", self.name, self.version)?;
		}

		write!(f, " ({})", self.protocol.name())
	}
}

pub(crate) struct ControlGuard {
	daemon: Rc<Daemon>,
}

impl Drop for ControlGuard {
	fn drop(&mut self) {
		let released = self.daemon.control.borrow_mut().take();

		if let Some(ident) = released {
			self.daemon.log(&format!("client disconnected: {ident}"));
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioUpdate {
	pub state: RadioState,
	pub message: Option<String>,
}

pub struct Daemon {
	lkl: Lkl,
	keys: RefCell<Option<Rc<Keys>>>,
	frame_source: RefCell<Option<Rc<dyn FrameSource>>>,
	radio: Cell<RadioState>,
	radio_events: Broadcast<RadioUpdate>,
	control: RefCell<Option<ClientIdent>>,
	phyname: RefCell<String>,
	shutdown_tx: UnboundedSender<()>,
	shutdown_rx: RefCell<Option<UnboundedReceiver<()>>>,
}

impl Daemon {
	/// # Errors
	/// If `keys_path` is given but the file at it cannot be loaded. `None` starts the daemon
	/// without `prod.keys`; operations that need them fail with [`Status::NoKeys`](ldn::protocol::Status)
	/// until a [`SetProdKeys`](ldn::protocol::LdnOp::SetProdKeys) arrives.
	pub fn new(lkl: Lkl, keys_path: Option<&Path>) -> anyhow::Result<Rc<Self>> {
		let (shutdown_tx, shutdown_rx) = unbounded();

		let keys = keys_path
			.map(|path| {
				Keys::load(path)
					.map(Rc::new)
					.map_err(|err| anyhow::anyhow!("could not load {}: {err}", path.display()))
			})
			.transpose()?;

		let keys = RefCell::new(keys);

		Ok(Rc::new(Self {
			lkl,
			keys,
			frame_source: RefCell::new(None),
			radio: Cell::new(RadioState::Idle),
			radio_events: Broadcast::new(),
			control: RefCell::new(None),
			phyname: RefCell::new("phy0".to_owned()),
			shutdown_tx,
			shutdown_rx: RefCell::new(Some(shutdown_rx)),
		}))
	}

	#[must_use]
	pub const fn version(&self) -> &'static str {
		env!("CARGO_PKG_VERSION")
	}

	#[must_use]
	pub fn phyname(&self) -> String {
		self.phyname.borrow().clone()
	}

	pub fn set_phyname(&self, phyname: &str) {
		phyname.clone_into(&mut self.phyname.borrow_mut());
	}

	#[must_use]
	pub fn capabilities(&self) -> Capabilities {
		// TODO: Detect capabilities from device
		Capabilities {
			ldn: LdnCapability::Scan | LdnCapability::Join | LdnCapability::Host,
			nwm: NwmCapability::empty(),
		}
	}

	#[must_use]
	pub fn keys(&self) -> Option<Rc<Keys>> {
		self.keys.borrow().clone()
	}

	pub fn set_keys(&self, keys: Keys) {
		*self.keys.borrow_mut() = Some(Rc::new(keys));
	}

	pub fn set_frame_source(&self, source: Rc<dyn FrameSource>) {
		*self.frame_source.borrow_mut() = Some(source);
	}

	#[must_use]
	pub fn frame_source(&self) -> Option<Rc<dyn FrameSource>> {
		self.frame_source.borrow().clone()
	}

	#[must_use]
	pub const fn radio_state(&self) -> RadioState {
		self.radio.get()
	}

	pub fn set_radio_state(&self, state: RadioState, message: Option<String>) {
		self.radio.set(state);
		self.radio_events.send(&RadioUpdate { state, message });
	}

	pub(crate) fn subscribe_radio(&self) -> Receiver<RadioUpdate> {
		self.radio_events.subscribe()
	}

	#[must_use]
	pub fn logs(&self) -> LogReceiver {
		self.lkl.logs()
	}

	#[must_use]
	pub const fn lkl(&self) -> &Lkl {
		&self.lkl
	}

	#[allow(
		clippy::unused_self,
		reason = "a method so it can route through daemon state later"
	)]
	pub(crate) fn log(&self, message: &str) {
		println!("ldnd: {message}");
	}

	pub(crate) fn control_holder(&self) -> String {
		self.control
			.borrow()
			.as_ref()
			.map_or_else(|| "unknown".to_owned(), ToString::to_string)
	}

	pub(crate) fn take_control(self: &Rc<Self>, ident: ClientIdent) -> Option<ControlGuard> {
		let mut control = self.control.borrow_mut();

		if control.is_some() {
			return None;
		}

		*control = Some(ident);

		Some(ControlGuard {
			daemon: Rc::clone(self),
		})
	}

	pub fn request_shutdown(&self) {
		let _ = self.shutdown_tx.unbounded_send(());
	}

	pub async fn wait_for_shutdown(&self) {
		let receiver = self.shutdown_rx.borrow_mut().take();

		match receiver {
			Some(mut rx) => {
				let _ = rx.next().await;
			}
			None => core::future::pending::<()>().await,
		}
	}
}

/// # Errors
/// If the named pipe cannot be created.
pub async fn serve(daemon: Rc<Daemon>, socket: String) -> anyhow::Result<()> {
	let mut next = ServerOptions::new()
		.first_pipe_instance(true)
		.create(&socket)
		.map_err(|err| anyhow::anyhow!("failed to create the pipe {socket}: {err}"))?;

	daemon.log(&format!("listening on {socket}"));

	loop {
		let pipe = next;

		next = ServerOptions::new()
			.create(&socket)
			.map_err(|err| anyhow::anyhow!("failed to create a pipe instance: {err}"))?;

		if let Err(err) = pipe.connect().await {
			daemon.log(&format!("failed to accept a connection: {err}"));
			continue;
		}

		let daemon = Rc::clone(&daemon);
		compio::runtime::spawn(session::run(daemon, pipe)).detach();
	}
}
