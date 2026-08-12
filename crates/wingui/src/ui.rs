//! Thin helpers over the raw Win32 controls used by the wizard.

use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
	CreateFontIndirectW, DEFAULT_GUI_FONT, DeleteObject, GetStockObject, HFONT, HGDIOBJ,
};
use windows::Win32::UI::Controls::{
	LIST_VIEW_ITEM_STATE_FLAGS, LVCF_SUBITEM, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT,
	LVIS_FOCUSED, LVIS_SELECTED, LVITEMW, LVM_DELETEALLITEMS, LVM_GETNEXTITEM, LVM_INSERTCOLUMNW,
	LVM_INSERTITEMW, LVM_SETITEMSTATE, LVM_SETITEMTEXTW, LVNI_SELECTED,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
	CreateWindowExW, HMENU, MB_ICONERROR, MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxW,
	NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS, SW_HIDE, SW_SHOW,
	SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SendMessageW, SetWindowTextW, ShowWindow,
	SystemParametersInfoW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT,
};
use windows::core::{PCWSTR, PWSTR};

#[must_use]
pub fn wide(s: &str) -> Vec<u16> {
	s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn lparam_of<T>(ptr: *const T) -> LPARAM {
	LPARAM(ptr as isize)
}

pub fn set_text(hwnd: HWND, text: &str) {
	let text = wide(text);
	let _ = unsafe { SetWindowTextW(hwnd, PCWSTR(text.as_ptr())) };
}

pub fn show(hwnd: HWND, visible: bool) {
	let cmd = if visible { SW_SHOW } else { SW_HIDE };
	let _ = unsafe { ShowWindow(hwnd, cmd) };
}

pub fn enable(hwnd: HWND, enabled: bool) {
	let _ = unsafe { EnableWindow(hwnd, enabled) };
}

pub fn error_box(owner: Option<HWND>, caption: &str, message: &str) {
	let _ = message_box(owner, caption, message, MB_OK | MB_ICONERROR);
}

pub fn message_box(
	owner: Option<HWND>,
	caption: &str,
	message: &str,
	style: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
	let caption = wide(caption);
	let message = wide(message);
	unsafe {
		MessageBoxW(
			owner,
			PCWSTR(message.as_ptr()),
			PCWSTR(caption.as_ptr()),
			style,
		)
	}
}

#[allow(clippy::too_many_arguments)]
pub fn create_control(
	parent: HWND,
	class: PCWSTR,
	text: &str,
	style: WINDOW_STYLE,
	ex_style: WINDOW_EX_STYLE,
	id: i32,
	font: HFONT,
) -> anyhow::Result<HWND> {
	let text = wide(text);

	let hwnd = unsafe {
		CreateWindowExW(
			ex_style,
			class,
			PCWSTR(text.as_ptr()),
			style,
			0,
			0,
			0,
			0,
			Some(parent),
			Some(HMENU(std::ptr::without_provenance_mut::<c_void>(
				id as usize,
			))),
			None,
			None,
		)
	}?;

	unsafe {
		SendMessageW(
			hwnd,
			WM_SETFONT,
			Some(WPARAM(font.0.addr())),
			Some(LPARAM(1)),
		)
	};

	Ok(hwnd)
}

pub struct Fonts {
	pub ui: HFONT,
	pub heading: HFONT,
}

impl Fonts {
	#[must_use]
	pub fn new() -> Self {
		let mut metrics = NONCLIENTMETRICSW {
			cbSize: size_of::<NONCLIENTMETRICSW>() as u32,
			..Default::default()
		};

		let queried = unsafe {
			SystemParametersInfoW(
				SPI_GETNONCLIENTMETRICS,
				metrics.cbSize,
				Some((&raw mut metrics).cast::<c_void>()),
				SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
			)
		};

		if queried.is_err() {
			let stock = HFONT(unsafe { GetStockObject(DEFAULT_GUI_FONT) }.0);
			return Self {
				ui: stock,
				heading: stock,
			};
		}

		let ui = unsafe { CreateFontIndirectW(&raw const metrics.lfMessageFont) };

		let mut heading_font = metrics.lfMessageFont;
		heading_font.lfHeight = heading_font.lfHeight.saturating_mul(7).saturating_div(5);
		heading_font.lfWeight = 700;
		let heading = unsafe { CreateFontIndirectW(&raw const heading_font) };

		Self { ui, heading }
	}
}

impl Default for Fonts {
	fn default() -> Self {
		Self::new()
	}
}

impl Drop for Fonts {
	fn drop(&mut self) {
		if self.ui != self.heading {
			let _ = unsafe { DeleteObject(HGDIOBJ(self.heading.0)) };
		}
		let _ = unsafe { DeleteObject(HGDIOBJ(self.ui.0)) };
	}
}

pub fn list_add_column(list: HWND, index: i32, title: &str, width: i32) {
	let mut title = wide(title);

	let column = LVCOLUMNW {
		mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
		cx: width,
		pszText: PWSTR(title.as_mut_ptr()),
		iSubItem: index,
		..Default::default()
	};

	unsafe {
		SendMessageW(
			list,
			LVM_INSERTCOLUMNW,
			Some(WPARAM(index as usize)),
			Some(lparam_of(&raw const column)),
		)
	};
}

pub fn list_clear(list: HWND) {
	unsafe { SendMessageW(list, LVM_DELETEALLITEMS, None, None) };
}

pub fn list_add_row(list: HWND, index: i32, columns: &[&str]) {
	for (subitem, text) in columns.iter().enumerate() {
		let mut text = wide(text);

		let item = LVITEMW {
			mask: LVIF_TEXT,
			iItem: index,
			iSubItem: subitem as i32,
			pszText: PWSTR(text.as_mut_ptr()),
			..Default::default()
		};

		let message = if subitem == 0 {
			LVM_INSERTITEMW
		} else {
			LVM_SETITEMTEXTW
		};

		unsafe {
			SendMessageW(
				list,
				message,
				Some(WPARAM(index as usize)),
				Some(lparam_of(&raw const item)),
			)
		};
	}
}

#[must_use]
pub fn list_selection(list: HWND) -> Option<usize> {
	let selected = unsafe {
		SendMessageW(
			list,
			LVM_GETNEXTITEM,
			Some(WPARAM(usize::MAX)),
			Some(LPARAM(LVNI_SELECTED as isize)),
		)
	};

	usize::try_from(selected.0).ok()
}

pub fn list_select(list: HWND, index: usize) {
	let state = LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0);
	let item = LVITEMW {
		state,
		stateMask: state,
		..Default::default()
	};

	unsafe {
		SendMessageW(
			list,
			LVM_SETITEMSTATE,
			Some(WPARAM(index)),
			Some(lparam_of(&raw const item)),
		)
	};
}
