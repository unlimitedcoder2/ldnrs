#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod codesign;
mod config;
mod daemon;
mod firmware;
mod install;
mod keys;
mod lkl;
mod logwindow;
mod manual_firmware;
mod theme;
mod ui;
mod wizard;

use windows::Win32::UI::Controls::{
	ICC_LISTVIEW_CLASSES, ICC_PROGRESS_CLASS, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX,
	InitCommonControlsEx,
};
use windows::Win32::UI::WindowsAndMessaging::{
	DispatchMessageW, GetMessageW, IsDialogMessageW, MSG, TranslateMessage,
};

use crate::app::App;
use crate::wizard::Wizard;

fn main() {
	if let Err(err) = run() {
		ui::error_box(None, "ldnrs", &format!("{err:#}"));
	}
}

fn run() -> anyhow::Result<()> {
	let controls = INITCOMMONCONTROLSEX {
		dwSize: ui::size_u32::<INITCOMMONCONTROLSEX>(),
		dwICC: ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES,
	};
	let _ = unsafe { InitCommonControlsEx(&raw const controls) };

	theme::init_process();

	let app = App::new();
	let wizard = Box::new(Wizard::new(app));

	wizard::open(&wizard)?;

	let mut msg = MSG::default();
	loop {
		let result = unsafe { GetMessageW(&raw mut msg, None, 0, 0) };

		if result.0 == 0 {
			break;
		}

		if result.0 == -1 {
			return Err(windows::core::Error::from_thread().into());
		}

		if let Some(dialog) = wizard.dialog()
			&& unsafe { IsDialogMessageW(dialog, &raw const msg) }.as_bool()
		{
			continue;
		}

		unsafe {
			let _ = TranslateMessage(&raw const msg);
			DispatchMessageW(&raw const msg);
		}
	}

	drop(wizard);

	Ok(())
}
