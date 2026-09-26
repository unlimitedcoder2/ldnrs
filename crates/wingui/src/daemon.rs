use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use ldn::Lkl;
use ldn::monitor::MonitorSource;
use ldn::protocol::RadioState;
use ldn::winusb::UsbDevice;
use ldn_daemon::daemon::{Daemon, Server};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::WM_APP;

use crate::app::App;
use crate::ui;

pub const PIPE: &str = r"\\.\pipe\ldnd";

pub const WM_DAEMON_STATUS: u32 = WM_APP + 6;

pub const WM_ADAPTER_STATUS: u32 = WM_APP + 7;

pub type Status = Result<(), String>;

pub type Adapter = Result<(), String>;

const PHY: &str = "phy0";
const MONITOR: &str = "ldn-mon";

const MONITOR_TRIES: u32 = 30;

struct Request {
	device: UsbDevice,
	window: isize,
}

struct Attachment {
	window: isize,
	result: Receiver<anyhow::Result<()>>,
	attached: bool,
	attempts: u32,
	next_try: Instant,
}

pub struct Handle {
	requests: Sender<Request>,
}

impl Handle {
	pub fn attach(&self, device: UsbDevice, hwnd: HWND) {
		let _ = self.requests.send(Request {
			device,
			window: ui::int_from_ptr(hwnd.0),
		});
	}
}

pub fn start(app: &App, hwnd: HWND, keys: PathBuf) -> Handle {
	let window = ui::int_from_ptr(hwnd.0);
	let lkl = Lkl::clone(&app.lkl);
	let (requests, incoming) = mpsc::channel::<Request>();

	thread::spawn(move || {
		let daemon = match Daemon::new(lkl, Some(&keys)) {
			Ok(daemon) => daemon,
			Err(err) => {
				let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Err(format!("{err:#}")));
				return;
			}
		};

		let mut server = match Server::new(Rc::clone(&daemon), PIPE.to_owned()) {
			Ok(server) => server,
			Err(err) => {
				let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Err(format!("{err:#}")));
				return;
			}
		};
		let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Ok(()));
		let mut attachment: Option<Attachment> = None;

		while !daemon.shutdown_requested() {
			if let Err(err) = server.poll() {
				let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Err(format!("{err:#}")));
				daemon.request_shutdown();
				break;
			}

			if attachment.is_none()
				&& let Ok(request) = incoming.try_recv()
			{
				attachment = begin_attach(&daemon, request);
			}

			if let Some(active) = attachment.as_mut()
				&& let Some(outcome) = poll_attach(&daemon, active)
			{
				finish_attach(&daemon, active.window, outcome);
				attachment = None;
			}

			thread::sleep(Duration::from_millis(10));
		}
	});

	Handle { requests }
}

fn begin_attach(daemon: &Rc<Daemon>, request: Request) -> Option<Attachment> {
	daemon.set_radio_state(RadioState::Attaching, None);
	if !request.device.driver.eq_ignore_ascii_case("winusb") {
		let err = format!(
			"{} is bound to the {} driver, not WinUSB",
			request.device.name, request.device.driver
		);
		finish_attach(daemon, request.window, Err(err));
		return None;
	}

	let (sender, result) = mpsc::channel();
	let lkl = daemon.lkl().clone();
	thread::spawn(move || {
		let _ = sender.send(lkl.attach(request.device));
	});
	Some(Attachment {
		window: request.window,
		result,
		attached: false,
		attempts: 0,
		next_try: Instant::now(),
	})
}

fn poll_attach(daemon: &Rc<Daemon>, active: &mut Attachment) -> Option<Adapter> {
	if !active.attached {
		match active.result.try_recv() {
			Ok(Ok(())) => active.attached = true,
			Ok(Err(err)) => return Some(Err(format!("{err:#}"))),
			Err(TryRecvError::Disconnected) => {
				return Some(Err("adapter worker stopped unexpectedly".to_owned()));
			}
			Err(TryRecvError::Empty) => return None,
		}
	}

	if Instant::now() < active.next_try {
		return None;
	}
	let Some(ctx) = daemon.lkl().context() else {
		return Some(Err("the kernel is not running".to_owned()));
	};
	match MonitorSource::create(ctx, PHY, MONITOR) {
		Ok(monitor) => {
			daemon.set_phyname(PHY);
			daemon.set_frame_source(monitor.into_source());
			Some(Ok(()))
		}
		Err(err) => {
			active.attempts += 1;
			if active.attempts == MONITOR_TRIES {
				Some(Err(format!(
					"the adapter attached but no monitor interface could be created: {err}"
				)))
			} else {
				active.next_try = Instant::now() + Duration::from_secs(1);
				None
			}
		}
	}
}

fn finish_attach(daemon: &Rc<Daemon>, window: isize, outcome: Adapter) {
	match &outcome {
		Ok(()) => daemon.set_radio_state(RadioState::Ready, None),
		Err(err) => daemon.set_radio_state(RadioState::Failed, Some(err.clone())),
	}
	let _ = ui::post_owned(window, WM_ADAPTER_STATUS, outcome);
}
