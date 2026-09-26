use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use ldn::winusb::UsbDevice;
use ldn::{FirmwareProgress, FirmwareProgressFn, Lkl};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::WM_APP;

use crate::app::App;
use crate::{manual_firmware, ui};

pub const WM_FIRMWARE_PROGRESS: u32 = WM_APP + 1;

pub const WM_FIRMWARE_DONE: u32 = WM_APP + 2;

pub type Outcome = Result<PathBuf, String>;

pub fn start(app: &App, hwnd: HWND, device: UsbDevice) {
	let window = ui::int_from_ptr(hwnd.0);
	let lkl = app.lkl.clone();

	std::thread::spawn(move || {
		let outcome = download(window, &lkl, &device).map_err(|err| format!("{err:#}"));

		let _ = ui::post_owned(window, WM_FIRMWARE_DONE, outcome);
	});
}

fn download(window: isize, lkl: &Lkl, device: &UsbDevice) -> anyhow::Result<PathBuf> {
	let progress: FirmwareProgressFn = Arc::new(move |progress: FirmwareProgress| {
		let _ = ui::post(
			window,
			WM_FIRMWARE_PROGRESS,
			progress.done,
			progress.total.cast_signed(),
		);
	});

	let prompt = Mutex::new(());
	let manual: ldn_daemon::firmware::ManualFetchFn = Arc::new(move |name: &str, page: &str| {
		let _prompt = prompt.lock().unwrap_or_else(PoisonError::into_inner);
		manual_firmware::ask(name, page)
	});

	ldn_daemon::firmware::download_firmware(lkl, device, Some(&progress), Some(&manual))?;

	ldn::firmware_dir()
}
