use ldn::logs::LogEvent;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::WM_APP;

use crate::app::App;
use crate::ui;

pub const WM_LKL_READY: u32 = WM_APP + 3;
pub const WM_LKL_LOG: u32 = WM_APP + 4;
pub const WM_LKL_STOPPED: u32 = WM_APP + 5;

pub type Outcome = Result<(), String>;

pub fn start(app: &App, hwnd: HWND) {
	let window = ui::int_from_ptr(hwnd.0);
	let lkl = app.lkl.clone();
	let mut logs = lkl.logs();

	app.worker.spawn(move || async move {
		loop {
			let line = match logs.try_recv() {
				Ok(LogEvent::Item(line)) => line,
				Ok(LogEvent::Dropped(dropped)) => format!("[{dropped} log lines dropped]\r\n"),
				Err(std::sync::mpsc::TryRecvError::Empty) => {
					compio::time::sleep(std::time::Duration::from_millis(10)).await;
					continue;
				}
				Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
			};

			if ui::post_owned(window, WM_LKL_LOG, line).is_err() {
				break;
			}
		}
	});

	let lkl = app.lkl.clone();
	app.worker.spawn(move || async move {
		let _ = ui::post_owned(
			window,
			WM_LKL_READY,
			compio::runtime::spawn_blocking(move || lkl.init())
				.await
				.map_err(|err| format!("{err}"))
				.and_then(|result| result.map_err(|err| format!("{err:#}"))),
		);
	});
}

pub fn shutdown(app: &App, hwnd: HWND) {
	let window = ui::int_from_ptr(hwnd.0);
	let lkl = app.lkl.clone();

	app.worker.spawn(move || async move {
		lkl.shutdown();
		let _ = ui::post_owned(window, WM_LKL_STOPPED, Outcome::Ok(()));
	});
}
