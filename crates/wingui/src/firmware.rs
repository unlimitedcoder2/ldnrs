use std::path::PathBuf;
use std::sync::Arc;

use ldn::winusb::UsbDevice;
use ldn::{FirmwareProgress, FirmwareProgressFn, Lkl};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::WM_APP;
use wrest::Client;

use crate::app::App;
use crate::ui;

pub const WM_FIRMWARE_PROGRESS: u32 = WM_APP + 1;

pub const WM_FIRMWARE_DONE: u32 = WM_APP + 2;

pub type Outcome = Result<PathBuf, String>;

pub fn start(app: &App, hwnd: HWND, device: UsbDevice) {
	let window = ui::int_from_ptr(hwnd.0);
	let lkl = app.lkl.clone();
	let client = app.client.clone();

	app.worker.spawn(move || async move {
		let outcome = download(window, &lkl, &client, device)
			.await
			.map_err(|err| format!("{err:#}"));

		let _ = ui::post_owned(window, WM_FIRMWARE_DONE, outcome);
	});
}

async fn download(
	window: isize,
	lkl: &Lkl,
	client: &Client,
	device: UsbDevice,
) -> anyhow::Result<PathBuf> {
	let progress: FirmwareProgressFn = Arc::new(move |progress: FirmwareProgress| {
		let _ = ui::post(
			window,
			WM_FIRMWARE_PROGRESS,
			progress.done,
			progress.total.cast_signed(),
		);
	});

	ldn_daemon::firmware::download_firmware(lkl, &device, client, Some(progress)).await?;

	ldn::firmware_dir()
}
