use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use futures_channel::mpsc::{UnboundedSender, unbounded};
use futures_util::StreamExt;
use ldn::Lkl;
use ldn::monitor::MonitorSource;
use ldn::protocol::RadioState;
use ldn::winusb::UsbDevice;
use ldn_daemon::daemon::{Daemon, serve};
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

pub struct Handle {
	requests: UnboundedSender<Request>,
}

impl Handle {
	pub fn attach(&self, device: UsbDevice, hwnd: HWND) {
		let _ = self.requests.unbounded_send(Request {
			device,
			window: ui::int_from_ptr(hwnd.0),
		});
	}
}

pub fn start(app: &App, hwnd: HWND, keys: PathBuf) -> Handle {
	let window = ui::int_from_ptr(hwnd.0);

	let lkl = Lkl::clone(&app.lkl);

	let (requests, mut incoming) = unbounded::<Request>();

	app.worker.spawn(move || async move {
		let daemon = match Daemon::new(lkl, Some(&keys)) {
			Ok(daemon) => daemon,
			Err(err) => {
				let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Err(format!("{err:#}")));
				return;
			}
		};

		let _ = ui::post_owned(window, WM_DAEMON_STATUS, Status::Ok(()));

		compio::runtime::spawn({
			let daemon = Rc::clone(&daemon);

			async move {
				if let Err(err) = serve(daemon, PIPE.to_owned()).await {
					let _ =
						ui::post_owned(window, WM_DAEMON_STATUS, Status::Err(format!("{err:#}")));
				}
			}
		})
		.detach();

		while let Some(request) = incoming.next().await {
			let reply = request.window;

			daemon.set_radio_state(RadioState::Attaching, None);

			match bring_up(&daemon, request.device).await {
				Ok(()) => {
					daemon.set_radio_state(RadioState::Ready, None);
					let _ = ui::post_owned(reply, WM_ADAPTER_STATUS, Adapter::Ok(()));
				}
				Err(err) => {
					let err = format!("{err:#}");
					daemon.set_radio_state(RadioState::Failed, Some(err.clone()));
					let _ = ui::post_owned(reply, WM_ADAPTER_STATUS, Adapter::Err(err));
				}
			}
		}
	});

	Handle { requests }
}

async fn bring_up(daemon: &Rc<Daemon>, device: UsbDevice) -> anyhow::Result<()> {
	anyhow::ensure!(
		device.driver.eq_ignore_ascii_case("winusb"),
		"{} is bound to the {} driver, not WinUSB",
		device.name,
		device.driver
	);

	let lkl = daemon.lkl();

	compio::runtime::spawn_blocking({
		let lkl = lkl.clone();
		move || lkl.attach(device)
	})
	.await
	.map_err(|err| anyhow::anyhow!("blocking task failed: {err}"))??;

	// The driver registers its wiphy asynchronously once probe finishes, so the monitor cannot be
	// created the instant attach returns.
	let ctx = lkl
		.context()
		.ok_or_else(|| anyhow::anyhow!("the kernel is not running"))?;

	let mut last = None;
	for _ in 0..MONITOR_TRIES {
		match MonitorSource::create(ctx, PHY, MONITOR) {
			Ok(monitor) => {
				daemon.set_phyname(PHY);
				daemon.set_frame_source(monitor.into_source());
				return Ok(());
			}
			Err(err) => last = Some(err),
		}

		compio::time::sleep(Duration::from_secs(1)).await;
	}

	anyhow::bail!(
		"the adapter attached but no monitor interface could be created: {}",
		last.map_or_else(|| "no wiphy appeared".to_owned(), |err| format!("{err}"))
	)
}
