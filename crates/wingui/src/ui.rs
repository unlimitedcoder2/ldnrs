use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{
	ANSI_FIXED_FONT, CreateFontIndirectW, DEFAULT_GUI_FONT, DeleteObject, GetStockObject, HFONT,
	HGDIOBJ,
};
use windows::Win32::UI::Controls::{
	EM_REPLACESEL, EM_SCROLLCARET, EM_SETSEL, LIST_VIEW_ITEM_STATE_FLAGS, LVCF_SUBITEM, LVCF_TEXT,
	LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVIS_FOCUSED, LVIS_SELECTED, LVITEMW, LVM_DELETEALLITEMS,
	LVM_GETNEXTITEM, LVM_INSERTCOLUMNW, LVM_INSERTITEMW, LVM_SETITEMSTATE, LVM_SETITEMTEXTW,
	LVNI_SELECTED, PBM_SETPOS, PBM_SETRANGE32,
};
use windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows::Win32::UI::WindowsAndMessaging::{
	BeginDeferWindowPos, CreateWindowExW, DeferWindowPos, EndDeferWindowPos, HMENU, MB_ICONERROR,
	MB_OK, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE, MessageBoxW, NONCLIENTMETRICSW, PostMessageW,
	SPI_GETNONCLIENTMETRICS, SW_HIDE, SW_SHOW, SWP_HIDEWINDOW, SWP_NOACTIVATE, SWP_NOMOVE,
	SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, SendMessageW,
	SetWindowTextW, ShowWindow, SystemParametersInfoW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT,
};
use windows::core::{PCWSTR, PWSTR};

#[must_use]
pub fn wide(s: &str) -> Vec<u16> {
	s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[must_use]
pub fn int_from_ptr<T>(ptr: *const T) -> isize {
	ptr.expose_provenance().cast_signed()
}

#[must_use]
pub const fn ptr_from_int<T>(value: isize) -> *mut T {
	std::ptr::with_exposed_provenance_mut(value.cast_unsigned())
}

pub fn post(
	window: isize,
	message: u32,
	wparam: usize,
	lparam: isize,
) -> windows::core::Result<()> {
	unsafe {
		PostMessageW(
			Some(HWND(ptr_from_int(window))),
			message,
			WPARAM(wparam),
			LPARAM(lparam),
		)
	}
}

/// Transfers a payload to the window procedure, which must reclaim it with `Box::from_raw`.
/// A failed post reclaims it here instead.
pub fn post_owned<T: Send + 'static>(
	window: isize,
	message: u32,
	payload: T,
) -> windows::core::Result<()> {
	let payload = Box::into_raw(Box::new(payload));
	let result = post(window, message, 0, int_from_ptr(payload));
	if result.is_err() {
		drop(unsafe { Box::from_raw(payload) });
	}
	result
}

#[must_use]
pub fn size_u32<T>() -> u32 {
	u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
}

#[must_use]
pub fn low_u32(value: isize) -> u32 {
	u32::try_from(value.cast_unsigned() & 0xFFFF_FFFF).unwrap_or(u32::MAX)
}

#[must_use]
pub fn command_id(wparam: WPARAM) -> i32 {
	u16::try_from(wparam.0 & 0xFFFF).map_or(0, i32::from)
}

fn lparam_of<T>(ptr: *const T) -> LPARAM {
	LPARAM(int_from_ptr(ptr))
}

/// `EM_SETSEL`'s start of -1, as the 32-bit int the control reads it as.
fn no_selection() -> WPARAM {
	WPARAM(usize::try_from(u32::MAX).unwrap_or(usize::MAX))
}

pub fn set_text(hwnd: HWND, text: &str) {
	let text = wide(text);
	let _ = unsafe { SetWindowTextW(hwnd, PCWSTR(text.as_ptr())) };
}

pub fn show(hwnd: HWND, visible: bool) {
	let cmd = if visible { SW_SHOW } else { SW_HIDE };
	let _ = unsafe { ShowWindow(hwnd, cmd) };
}

pub fn show_many(controls: &[(HWND, bool)]) {
	let Ok(count) = i32::try_from(controls.len()) else {
		return;
	};

	let Ok(mut defer) = (unsafe { BeginDeferWindowPos(count) }) else {
		for (hwnd, visible) in controls {
			show(*hwnd, *visible);
		}

		return;
	};

	for (hwnd, visible) in controls {
		let visibility = if *visible {
			SWP_SHOWWINDOW
		} else {
			SWP_HIDEWINDOW
		};

		let Ok(next) = (unsafe {
			DeferWindowPos(
				defer,
				*hwnd,
				None,
				0,
				0,
				0,
				0,
				SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | visibility,
			)
		}) else {
			return;
		};

		defer = next;
	}

	let _ = unsafe { EndDeferWindowPos(defer) };
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
				usize::try_from(id).unwrap_or_default(),
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
	pub mono: HFONT,
}

fn face(name: &str) -> [u16; 32] {
	let mut buf = [0u16; 32];

	for (slot, c) in buf.iter_mut().take(31).zip(name.encode_utf16()) {
		*slot = c;
	}

	buf
}

impl Fonts {
	#[must_use]
	pub fn new() -> Self {
		let mut metrics = NONCLIENTMETRICSW {
			cbSize: size_u32::<NONCLIENTMETRICSW>(),
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
				mono: HFONT(unsafe { GetStockObject(ANSI_FIXED_FONT) }.0),
			};
		}

		let ui = unsafe { CreateFontIndirectW(&raw const metrics.lfMessageFont) };

		let mut heading_font = metrics.lfMessageFont;
		heading_font.lfHeight = heading_font.lfHeight * 7 / 5;
		heading_font.lfWeight = 700;
		let heading = unsafe { CreateFontIndirectW(&raw const heading_font) };

		let mut mono_font = metrics.lfMessageFont;
		mono_font.lfFaceName = face("Consolas");
		let mono = unsafe { CreateFontIndirectW(&raw const mono_font) };

		Self { ui, heading, mono }
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
			let _ = unsafe { DeleteObject(HGDIOBJ(self.mono.0)) };
		}
		let _ = unsafe { DeleteObject(HGDIOBJ(self.ui.0)) };
	}
}

pub fn append_line(edit: HWND, text: &str) {
	let text = wide(&text.replace("\r\n", "\n").replace('\n', "\r\n"));

	unsafe {
		SendMessageW(edit, EM_SETSEL, Some(no_selection()), Some(LPARAM(-1)));
		SendMessageW(
			edit,
			EM_REPLACESEL,
			Some(WPARAM(0)),
			Some(lparam_of(text.as_ptr())),
		);
	};

	scroll_to_end(edit);
}

/// Scrolling a hidden control does nothing, so this is also needed on show.
pub fn scroll_to_end(edit: HWND) {
	unsafe {
		SendMessageW(edit, EM_SETSEL, Some(no_selection()), Some(LPARAM(-1)));
		SendMessageW(edit, EM_SCROLLCARET, None, None);
	};
}

pub fn set_progress_range(bar: HWND, total: i32) {
	unsafe {
		SendMessageW(
			bar,
			PBM_SETRANGE32,
			Some(WPARAM(0)),
			Some(LPARAM(isize::try_from(total).unwrap_or_default())),
		)
	};
}

pub fn set_progress_pos(bar: HWND, done: i32) {
	unsafe {
		SendMessageW(
			bar,
			PBM_SETPOS,
			Some(WPARAM(usize::try_from(done).unwrap_or_default())),
			None,
		)
	};
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
			Some(WPARAM(usize::try_from(index).unwrap_or_default())),
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
			iSubItem: i32::try_from(subitem).unwrap_or(i32::MAX),
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
				Some(WPARAM(usize::try_from(index).unwrap_or_default())),
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
			Some(LPARAM(isize::try_from(LVNI_SELECTED).unwrap_or_default())),
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
