#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod firmware;
mod install;
mod ui;
mod wizard;

use windows::Win32::Foundation::{HINSTANCE, RECT};
use windows::Win32::Graphics::Gdi::{COLOR_WINDOW, GetSysColorBrush, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
	ICC_LISTVIEW_CLASSES, ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, InitCommonControlsEx,
};
use windows::Win32::UI::WindowsAndMessaging::{
	AdjustWindowRectEx, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DispatchMessageW, GetMessageW,
	GetSystemMetrics, IDC_ARROW, IsDialogMessageW, LoadCursorW, MSG, RegisterClassW, SM_CXSCREEN,
	SM_CYSCREEN, SW_SHOW, ShowWindow, TranslateMessage, WINDOW_EX_STYLE, WNDCLASSW, WS_CAPTION,
	WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU,
};
use windows::core::w;

use crate::app::App;
use crate::wizard::{CLIENT_HEIGHT, CLIENT_WIDTH, Wizard, wndproc};

fn main() {
	if let Err(err) = run() {
		ui::error_box(None, "ldnrs", &format!("{err:#}"));
	}
}

fn run() -> anyhow::Result<()> {
	let instance = HINSTANCE(unsafe { GetModuleHandleW(None) }?.0);

	let controls = INITCOMMONCONTROLSEX {
		dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
		dwICC: ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS,
	};
	let _ = unsafe { InitCommonControlsEx(&raw const controls) };

	let class_name = w!("LdnrsWizard");

	let class = WNDCLASSW {
		style: CS_HREDRAW | CS_VREDRAW,
		lpfnWndProc: Some(wndproc),
		hInstance: instance,
		hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }?,
		hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
		lpszClassName: class_name,
		..Default::default()
	};

	if unsafe { RegisterClassW(&raw const class) } == 0 {
		return Err(windows::core::Error::from_thread().into());
	}

	let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;

	let mut rect = RECT {
		left: 0,
		top: 0,
		right: CLIENT_WIDTH,
		bottom: CLIENT_HEIGHT,
	};
	unsafe { AdjustWindowRectEx(&raw mut rect, style, false, WINDOW_EX_STYLE::default()) }?;

	let width = rect.right.saturating_sub(rect.left);
	let height = rect.bottom.saturating_sub(rect.top);
	let x = unsafe { GetSystemMetrics(SM_CXSCREEN) }
		.saturating_sub(width)
		.saturating_div(2);
	let y = unsafe { GetSystemMetrics(SM_CYSCREEN) }
		.saturating_sub(height)
		.saturating_div(2);

	let app = App::new()?;

	let mut wizard = Box::new(Wizard::new(app));

	let hwnd = unsafe {
		CreateWindowExW(
			WINDOW_EX_STYLE::default(),
			class_name,
			w!("ldnrs device wizard"),
			style,
			x,
			y,
			width,
			height,
			None,
			None,
			Some(instance),
			Some(std::ptr::from_mut(wizard.as_mut()).cast()),
		)
	}?;

	unsafe {
		let _ = ShowWindow(hwnd, SW_SHOW);
		let _ = UpdateWindow(hwnd);
	}

	let mut msg = MSG::default();
	loop {
		let result = unsafe { GetMessageW(&raw mut msg, None, 0, 0) };

		if result.0 == 0 {
			break;
		}

		if result.0 == -1 {
			return Err(windows::core::Error::from_thread().into());
		}

		if unsafe { IsDialogMessageW(hwnd, &raw const msg) }.as_bool() {
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
