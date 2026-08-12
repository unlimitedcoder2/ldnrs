//! Drives `Lkl::download_firmware` from the wizard.
//!
//! Downloads run as tasks on the runtime [`App`] brought up at startup, so the
//! wizard keeps pumping messages while they are in flight, and report back
//! through posted messages.

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::Arc;

use ldn::winusb::UsbDevice;
use ldn::{FirmwareProgress, FirmwareProgressFn, Lkl};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_APP};
use wrest::Client;

use crate::app::App;

pub const WM_FIRMWARE_PROGRESS: u32 = WM_APP + 1;

pub const WM_FIRMWARE_DONE: u32 = WM_APP + 2;

pub type Outcome = Result<PathBuf, String>;

pub fn start(app: &App, hwnd: HWND, device: UsbDevice) {
	let window = hwnd.0 as isize;
	let lkl = app.lkl.clone();
	let client = app.client.clone();

	app.runtime.spawn(async move {
		let outcome = download(window, &lkl, &client, device)
			.await
			.map_err(|err| format!("{err:#}"));

		let outcome = Box::into_raw(Box::new(outcome));

		if post(window, WM_FIRMWARE_DONE, 0, outcome as isize).is_err() {
			drop(unsafe { Box::from_raw(outcome) });
		}
	});
}

fn post(window: isize, message: u32, wparam: usize, lparam: isize) -> windows::core::Result<()> {
	unsafe {
		PostMessageW(
			Some(HWND(window as *mut c_void)),
			message,
			WPARAM(wparam),
			LPARAM(lparam),
		)
	}
}

async fn download(
	window: isize,
	lkl: &Lkl,
	client: &Client,
	device: UsbDevice,
) -> anyhow::Result<PathBuf> {
	let progress: FirmwareProgressFn = Arc::new(move |progress: FirmwareProgress| {
		let _ = post(
			window,
			WM_FIRMWARE_PROGRESS,
			progress.done,
			progress.total as isize,
		);
	});

	lkl.download_firmware(&device, client, Some(progress))
		.await?;

	ldn::firmware_dir()
}
