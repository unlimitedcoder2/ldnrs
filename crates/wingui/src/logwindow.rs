use std::cell::Cell;

use windows::Win32::Foundation::{
	ERROR_CLASS_ALREADY_EXISTS, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{HBRUSH, HDC};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::SS_LEFT;
use windows::Win32::UI::WindowsAndMessaging::{
	CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, ES_AUTOVSCROLL,
	ES_MULTILINE, ES_READONLY, GWLP_USERDATA, GetClientRect, GetWindowLongPtrW, GetWindowRect,
	IDC_ARROW, LoadCursorW, MoveWindow, RegisterClassW, SetWindowLongPtrW, WINDOW_EX_STYLE,
	WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORBTN, WM_CTLCOLORSTATIC, WM_DESTROY,
	WM_ERASEBKGND, WM_NCCREATE, WM_NCDESTROY, WM_SETTINGCHANGE, WM_SIZE, WNDCLASSW, WS_BORDER,
	WS_CHILD, WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};
use windows::core::w;

use crate::daemon::{self, WM_ADAPTER_STATUS};
use crate::lkl::{self, WM_LKL_LOG, WM_LKL_READY, WM_LKL_STOPPED};
use crate::theme;
use crate::ui;
use crate::wizard::Wizard;

const CLASS_NAME: windows::core::PCWSTR = w!("LdnrsLklWindow");

const ID_SHUTDOWN: i32 = 201;
const ID_LOG: i32 = 202;

const WIDTH: i32 = 720;
const HEIGHT: i32 = 460;
const MARGIN: i32 = 12;

#[derive(Clone, Copy)]
struct Controls {
	log_view: HWND,
	status: HWND,
}

struct State {
	/// Borrowed from `open`'s caller, which outlives the window.
	wizard: *const Wizard,
	controls: Cell<Option<Controls>>,
}

impl State {
	const fn wizard(&self) -> &Wizard {
		// `open` takes a `&Wizard` that outlives the window, and nothing but
		// this window's own messages ever reaches the pointer.
		unsafe { &*self.wizard }
	}

	fn with_controls<T>(&self, f: impl FnOnce(Controls) -> T) -> Option<T> {
		self.controls.get().map(f)
	}
}

fn register(instance: HINSTANCE) -> anyhow::Result<()> {
	let class = WNDCLASSW {
		style: CS_HREDRAW | CS_VREDRAW,
		lpfnWndProc: Some(wndproc),
		hInstance: instance,
		hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }?,
		hbrBackground: HBRUSH::default(),
		lpszClassName: CLASS_NAME,
		..Default::default()
	};

	if unsafe { RegisterClassW(&raw const class) } == 0 {
		let err = windows::core::Error::from_thread();
		if err.code() != ERROR_CLASS_ALREADY_EXISTS.into() {
			return Err(err.into());
		}
	}

	Ok(())
}

pub fn open(wizard: &Wizard, owner: HWND) -> anyhow::Result<HWND> {
	let instance = HINSTANCE(unsafe { GetModuleHandleW(None) }?.0);
	register(instance)?;

	let mut anchor = RECT::default();
	let (x, y) = if unsafe { GetWindowRect(owner, &raw mut anchor) }.is_ok() {
		(anchor.left + 48, anchor.top + 48)
	} else {
		(64, 64)
	};

	let hwnd = unsafe {
		CreateWindowExW(
			WINDOW_EX_STYLE::default(),
			CLASS_NAME,
			w!("lkl"),
			WS_OVERLAPPEDWINDOW,
			x,
			y,
			WIDTH,
			HEIGHT,
			None,
			None,
			Some(instance),
			Some(std::ptr::from_ref(wizard).cast()),
		)
	}?;

	Ok(hwnd)
}

fn create_controls(state: &State, hwnd: HWND) -> anyhow::Result<()> {
	let wizard = state.wizard();
	let fonts = wizard.fonts();

	let controls = Controls {
		log_view: ui::create_control(
			hwnd,
			w!("EDIT"),
			"",
			WINDOW_STYLE(
				WS_CHILD.0
					| WS_VISIBLE.0 | WS_BORDER.0
					| WS_VSCROLL.0 | WS_TABSTOP.0
					| (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL).cast_unsigned(),
			),
			WINDOW_EX_STYLE::default(),
			ID_LOG,
			fonts.mono,
		)?,
		status: ui::create_control(
			hwnd,
			w!("STATIC"),
			&wizard.lkl_status(),
			WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | SS_LEFT.0),
			WINDOW_EX_STYLE::default(),
			0,
			fonts.ui,
		)?,
	};

	state.controls.set(Some(controls));

	refresh(state);
	apply_theme(state, hwnd);

	Ok(())
}

fn apply_theme(state: &State, hwnd: HWND) {
	let palette = state.wizard().theme().palette();

	theme::apply_window(hwnd, palette.dark);

	let controls = state.with_controls(|controls| [controls.log_view, controls.status]);

	for control in controls.into_iter().flatten() {
		theme::apply_control_with(control, palette);
	}

	theme::repaint(hwnd);
}

fn on_ctl_colour(state: &State, hdc: HDC, control: HWND) -> LRESULT {
	let palette = state.wizard().theme().palette();

	let is_log = state
		.with_controls(|controls| controls.log_view == control)
		.unwrap_or(false);

	if is_log {
		theme::ctl_colour_field(hdc, palette)
	} else {
		theme::ctl_colour(hdc, palette.text, palette)
	}
}

fn layout(state: &State, hwnd: HWND) {
	let mut client = RECT::default();
	if unsafe { GetClientRect(hwnd, &raw mut client) }.is_err() {
		return;
	}

	let width = client.right;
	let height = client.bottom;
	let content_width = width.saturating_sub(MARGIN * 2);
	let log_height = height.saturating_sub(MARGIN * 3);
	let row_y = height.saturating_sub(MARGIN / 2).saturating_sub(MARGIN / 2);

	state.with_controls(|controls| {
		let place = |control: HWND, x: i32, y: i32, w: i32, h: i32| {
			let _ = unsafe { MoveWindow(control, x, y, w, h, true) };
		};

		place(
			controls.log_view,
			MARGIN,
			MARGIN,
			content_width,
			log_height - 10,
		);

		let status_x = MARGIN + MARGIN;

		place(
			controls.status,
			status_x,
			row_y,
			width.saturating_sub(status_x).saturating_sub(MARGIN),
			20,
		);
	});
}

fn refresh(state: &State) {
	let wizard = state.wizard();

	state.with_controls(|controls| {
		ui::set_text(controls.status, &wizard.lkl_status());
	});
}

/// `WM_LKL_READY` and `WM_LKL_STOPPED`, whose `lparam` is a boxed [`lkl::Outcome`].
///
/// On an exit this destroys the window and frees `state`, so the caller must not touch it after.
fn on_lkl_outcome(state: &State, hwnd: HWND, msg: u32, lparam: LPARAM) -> LRESULT {
	let wizard = state.wizard();
	let outcome = ui::ptr_from_int::<lkl::Outcome>(lparam.0);
	if !outcome.is_null() {
		let outcome = *unsafe { Box::from_raw(outcome) };

		if msg == WM_LKL_READY {
			wizard.on_lkl_ready(hwnd, outcome);
		} else {
			wizard.on_lkl_stopped(&outcome);

			let failed = outcome.err();

			if let Some(err) = failed.as_ref() {
				state.with_controls(|controls| {
					ui::set_text(controls.status, &format!("Shutdown failed: {err}"));
				});
			}

			if wizard.exiting() {
				wizard.finish_exit();
				return LRESULT(0);
			}

			if failed.is_some() {
				return LRESULT(0);
			}
		}

		refresh(state);
	}
	LRESULT(0)
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
	if msg == WM_NCCREATE {
		let create = ui::ptr_from_int::<CREATESTRUCTW>(lparam.0);
		let wizard = unsafe { (*create).lpCreateParams }.cast::<Wizard>();
		let state = Box::into_raw(Box::new(State {
			wizard,
			controls: Cell::new(None),
		}));
		unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, ui::int_from_ptr(state)) };
		return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
	}

	let ptr = ui::ptr_from_int::<State>(unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) });
	let Some(state) = (unsafe { ptr.as_ref() }) else {
		return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
	};
	let wizard = state.wizard();

	match msg {
		WM_CREATE => {
			if let Err(err) = create_controls(state, hwnd) {
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not create the lkl window:\r\n\r\n{err:#}"),
				);
				return LRESULT(-1);
			}

			wizard.window_opened();
			layout(state, hwnd);
			LRESULT(0)
		}

		WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => on_ctl_colour(
			state,
			HDC(std::ptr::with_exposed_provenance_mut(wparam.0)),
			HWND(ui::ptr_from_int(lparam.0)),
		),

		WM_ERASEBKGND => theme::erase_background(
			hwnd,
			HDC(std::ptr::with_exposed_provenance_mut(wparam.0)),
			wizard.theme().palette(),
		),

		WM_SETTINGCHANGE => {
			if theme::is_colour_setting_change(lparam) && wizard.theme().reread() {
				apply_theme(state, hwnd);
			}

			unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
		}

		WM_SIZE => {
			layout(state, hwnd);
			LRESULT(0)
		}

		WM_COMMAND => {
			if ui::command_id(wparam) == ID_SHUTDOWN {
				wizard.shutdown_lkl(hwnd);
			}
			LRESULT(0)
		}

		WM_LKL_LOG => {
			let line = ui::ptr_from_int::<String>(lparam.0);
			if !line.is_null() {
				let line = *unsafe { Box::from_raw(line) };
				state.with_controls(|controls| ui::append_line(controls.log_view, &line));
			}
			LRESULT(0)
		}

		WM_ADAPTER_STATUS => {
			let status = ui::ptr_from_int::<daemon::Adapter>(lparam.0);
			if !status.is_null() {
				wizard.on_adapter_status(*unsafe { Box::from_raw(status) });
				refresh(state);
			}
			LRESULT(0)
		}

		WM_LKL_READY | WM_LKL_STOPPED => on_lkl_outcome(state, hwnd, msg, lparam),

		// The close box on this window closes the app, and the kernel it is a console for stops
		// first. `begin_exit` can destroy this window outright when there is nothing to wind down,
		// which frees `state` -- so nothing below may touch it.
		WM_CLOSE => {
			wizard.begin_exit();
			LRESULT(0)
		}

		WM_DESTROY => {
			state.controls.set(None);
			wizard.window_closed();
			LRESULT(0)
		}

		// The last message the window sees, so the state it has been carrying
		// goes here rather than in `WM_DESTROY`, which is followed by more.
		WM_NCDESTROY => {
			unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
			drop(unsafe { Box::from_raw(ptr) });
			unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
		}

		_ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
	}
}
