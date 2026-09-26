use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
	BeginPaint, COLOR_WINDOW, COLOR_WINDOWTEXT, CreatePen, CreateSolidBrush, DRAW_TEXT_FORMAT,
	DT_CALCRECT, DT_CENTER, DT_LEFT, DT_SINGLELINE, DT_VCENTER, DeleteObject, DrawFocusRect,
	DrawTextW, EndPaint, FillRect, GetSysColor, HBRUSH, HDC, HFONT, HGDIOBJ, InvalidateRect,
	PAINTSTRUCT, PS_SOLID, Polyline, RoundRect, SelectObject, SetBkColor, SetBkMode, SetTextColor,
	TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::{
	GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows::Win32::UI::Controls::{
	LVM_GETHEADER, LVM_SETBKCOLOR, LVM_SETTEXTBKCOLOR, LVM_SETTEXTCOLOR, SetWindowTheme,
	WM_MOUSELEAVE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled;
use windows::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows::Win32::UI::WindowsAndMessaging::{
	BM_GETSTATE, BM_SETCHECK, BM_SETSTATE, BM_SETSTYLE, BS_AUTOCHECKBOX, BS_CHECKBOX,
	BS_DEFPUSHBUTTON, BS_PUSHBUTTON, BST_FOCUS, BST_PUSHED, GWL_STYLE, GetClassNameW,
	GetClientRect, GetSystemMetrics, GetWindowLongPtrW, GetWindowTextW, SM_CXMENUCHECK,
	SendMessageW, WM_ENABLE, WM_ERASEBKGND, WM_GETFONT, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS,
	WM_LBUTTONDBLCLK, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCDESTROY, WM_PAINT,
	WM_SETFOCUS, WM_SETREDRAW, WM_SETTEXT,
};

use windows::core::{BOOL, PCSTR, PCWSTR, w};

use crate::ui;

const BST_CHECKED: u32 = 0x0001;
const BST_HOT: u32 = 0x0200;

/// Colours are `0x00bbggrr`, so each pair below reads backwards from hex CSS.
mod colour {
	use windows::Win32::Foundation::COLORREF;

	pub const LIGHT_RULE: COLORREF = COLORREF(0x00dc_dcdc);
	pub const LIGHT_GOOD: COLORREF = COLORREF(0x0020_7000);
	pub const LIGHT_BAD: COLORREF = COLORREF(0x0020_20c0);

	pub const DARK_WINDOW: COLORREF = COLORREF(0x0020_2020);
	pub const DARK_TEXT: COLORREF = COLORREF(0x00f0_f0f0);
	pub const DARK_FIELD: COLORREF = COLORREF(0x002b_2b2b);
	pub const DARK_RULE: COLORREF = COLORREF(0x003c_3c3c);
	pub const DARK_GOOD: COLORREF = COLORREF(0x0076_c94e);
	pub const DARK_BAD: COLORREF = COLORREF(0x0069_69f0);

	pub const BUTTON_FACE: COLORREF = COLORREF(0x002d_2d2d);
	pub const BUTTON_HOT: COLORREF = COLORREF(0x0034_3434);
	pub const BUTTON_PRESSED: COLORREF = COLORREF(0x0027_2727);
	pub const BUTTON_BORDER: COLORREF = COLORREF(0x003d_3d3d);
	pub const BUTTON_DISABLED: COLORREF = COLORREF(0x0026_2626);
	pub const BUTTON_DISABLED_TEXT: COLORREF = COLORREF(0x006b_6b6b);
	pub const BUTTON_DEFAULT_BORDER: COLORREF = COLORREF(0x008a_8a8a);

	pub const CHECK_BORDER: COLORREF = COLORREF(0x009a_9a9a);
	pub const CHECK_BORDER_HOT: COLORREF = COLORREF(0x00c8_c8c8);
}

pub struct Palette {
	pub dark: bool,
	pub text: COLORREF,
	pub window: COLORREF,
	pub field: COLORREF,
	pub good: COLORREF,
	pub bad: COLORREF,
	window_brush: HBRUSH,
	field_brush: HBRUSH,
	rule_brush: HBRUSH,
}

impl Palette {
	fn new(dark: bool) -> Self {
		let (text, window, field, rule, good, bad) = if dark {
			(
				colour::DARK_TEXT,
				colour::DARK_WINDOW,
				colour::DARK_FIELD,
				colour::DARK_RULE,
				colour::DARK_GOOD,
				colour::DARK_BAD,
			)
		} else {
			let window = COLORREF(unsafe { GetSysColor(COLOR_WINDOW) });

			(
				COLORREF(unsafe { GetSysColor(COLOR_WINDOWTEXT) }),
				window,
				window,
				colour::LIGHT_RULE,
				colour::LIGHT_GOOD,
				colour::LIGHT_BAD,
			)
		};

		Self {
			dark,
			text,
			window,
			field,
			good,
			bad,
			window_brush: unsafe { CreateSolidBrush(window) },
			field_brush: unsafe { CreateSolidBrush(field) },
			rule_brush: unsafe { CreateSolidBrush(rule) },
		}
	}

	fn delete_brushes(&self) {
		for brush in [self.window_brush, self.field_brush, self.rule_brush] {
			let _ = unsafe { DeleteObject(HGDIOBJ(brush.0)) };
		}
	}
}

pub struct Theme {
	light: Palette,
	dark: Palette,
	using_dark: Cell<bool>,
}

impl Theme {
	#[must_use]
	pub fn new() -> Self {
		Self {
			light: Palette::new(false),
			dark: Palette::new(true),
			using_dark: Cell::new(system_prefers_dark()),
		}
	}

	#[must_use]
	pub const fn palette(&self) -> &Palette {
		if self.using_dark.get() {
			&self.dark
		} else {
			&self.light
		}
	}

	pub fn reread(&self) -> bool {
		let dark = system_prefers_dark();
		let changed = dark != self.using_dark.get();
		self.using_dark.set(dark);
		changed
	}
}

impl Default for Theme {
	fn default() -> Self {
		Self::new()
	}
}

impl Drop for Theme {
	fn drop(&mut self) {
		self.light.delete_brushes();
		self.dark.delete_brushes();
	}
}

const PERSONALIZE: PCWSTR = w!(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
const APPS_USE_LIGHT_THEME: PCWSTR = w!("AppsUseLightTheme");

#[must_use]
fn system_prefers_dark() -> bool {
	let mut value = 0u32;
	let mut size = ui::size_u32::<u32>();

	let status = unsafe {
		RegGetValueW(
			HKEY_CURRENT_USER,
			PERSONALIZE,
			APPS_USE_LIGHT_THEME,
			RRF_RT_REG_DWORD,
			None,
			Some((&raw mut value).cast::<c_void>()),
			Some(&raw mut size),
		)
	};

	status.is_ok() && value == 0
}

#[must_use]
pub fn is_colour_setting_change(lparam: LPARAM) -> bool {
	let name = PCWSTR(ui::ptr_from_int(lparam.0));

	!name.is_null() && unsafe { name.to_string() }.is_ok_and(|name| name == "ImmersiveColorSet")
}

/// uxtheme's dark mode entry points have no headers and no names in the export
/// table: they are reachable only by ordinal, and only on Windows 10 1903 and
/// later. A missing export is not an error, it just means this Windows cannot
/// draw dark common controls, so every call site treats absence as "skip it"
/// and falls back to the hand painted colours alone.
#[derive(Default)]
struct UxTheme {
	set_preferred_app_mode: Option<unsafe extern "system" fn(i32) -> i32>,
	allow_dark_mode_for_window: Option<unsafe extern "system" fn(HWND, BOOL) -> BOOL>,
	refresh_immersive_colour_policy_state: Option<unsafe extern "system" fn()>,
}

const ALLOW_DARK: i32 = 1;

const fn ordinal(value: usize) -> PCSTR {
	PCSTR(std::ptr::without_provenance::<u8>(value))
}

fn uxtheme() -> &'static UxTheme {
	static UXTHEME: OnceLock<UxTheme> = OnceLock::new();

	UXTHEME.get_or_init(|| {
		let module =
			unsafe { LoadLibraryExW(w!("uxtheme.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) };

		let Ok(module) = module else {
			return UxTheme::default();
		};

		unsafe {
			UxTheme {
				set_preferred_app_mode: GetProcAddress(module, ordinal(135))
					.map(|proc| std::mem::transmute(proc)),
				allow_dark_mode_for_window: GetProcAddress(module, ordinal(133))
					.map(|proc| std::mem::transmute(proc)),
				refresh_immersive_colour_policy_state: GetProcAddress(module, ordinal(104))
					.map(|proc| std::mem::transmute(proc)),
			}
		}
	})
}

pub fn init_process() {
	let uxtheme = uxtheme();

	if let Some(set_mode) = uxtheme.set_preferred_app_mode {
		unsafe { set_mode(ALLOW_DARK) };
	}

	if let Some(refresh) = uxtheme.refresh_immersive_colour_policy_state {
		unsafe { refresh() };
	}
}

fn allow_dark(hwnd: HWND, dark: bool) {
	if let Some(allow) = uxtheme().allow_dark_mode_for_window {
		let _ = unsafe { allow(hwnd, BOOL::from(dark)) };
	}
}

fn set_theme(hwnd: HWND, name: PCWSTR) {
	let _ = unsafe { SetWindowTheme(hwnd, name, None) };
}

pub fn apply_window(hwnd: HWND, dark: bool) {
	allow_dark(hwnd, dark);

	let flag = BOOL::from(dark);
	let _ = unsafe {
		DwmSetWindowAttribute(
			hwnd,
			DWMWA_USE_IMMERSIVE_DARK_MODE,
			(&raw const flag).cast::<c_void>(),
			ui::size_u32::<BOOL>(),
		)
	};
}

const BUTTON_TYPE: u32 = 0x0f;

fn class_is(hwnd: HWND, wanted: &str) -> bool {
	let mut class = [0u16; 32];
	let len = usize::try_from(unsafe { GetClassNameW(hwnd, &mut class) }).unwrap_or(0);

	class
		.get(..len)
		.is_some_and(|class| String::from_utf16_lossy(class).eq_ignore_ascii_case(wanted))
}

fn button_type(hwnd: HWND) -> Option<u32> {
	class_is(hwnd, "Button")
		.then(|| ui::low_u32(unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) }) & BUTTON_TYPE)
}

fn is_push_button(hwnd: HWND) -> bool {
	button_type(hwnd).is_some_and(|style| {
		style == BS_PUSHBUTTON.cast_unsigned() || style == BS_DEFPUSHBUTTON.cast_unsigned()
	})
}

fn is_check_box(hwnd: HWND) -> bool {
	button_type(hwnd).is_some_and(|style| {
		style == BS_CHECKBOX.cast_unsigned() || style == BS_AUTOCHECKBOX.cast_unsigned()
	})
}

pub fn apply_control(hwnd: HWND, dark: bool) {
	allow_dark(hwnd, dark);

	let name = if dark && !class_is(hwnd, "Button") {
		w!("DarkMode_Explorer")
	} else {
		PCWSTR::null()
	};

	set_theme(hwnd, name);
}

pub fn apply_control_with(hwnd: HWND, palette: &Palette) {
	apply_control(hwnd, palette.dark);

	if is_push_button(hwnd) || is_check_box(hwnd) {
		subclass_button(hwnd, palette);
	}
}

const BUTTON_CORNER: i32 = 8;
const CHECK_CORNER: i32 = 5;
const FOCUS_INSET: i32 = 3;
const FOCUS_PAD: i32 = 2;
const CHECK_GAP: i32 = 6;
const CHECK_TICK: i32 = 2;

const BUTTON_SUBCLASS: usize = 1;

fn subclass_button(hwnd: HWND, palette: &Palette) {
	if palette.dark {
		// Re-installing under the same id just refreshes the reference data,
		// which is what a mode switch wants. The theme outlives every window,
		// so handing its palette out as a pointer is sound.
		let _ = unsafe {
			SetWindowSubclass(
				hwnd,
				Some(button_subclass),
				BUTTON_SUBCLASS,
				std::ptr::from_ref(palette).expose_provenance(),
			)
		};
	} else {
		let _ = unsafe { RemoveWindowSubclass(hwnd, Some(button_subclass), BUTTON_SUBCLASS) };
	}

	let _ = unsafe { InvalidateRect(Some(hwnd), None, true) };
}

unsafe extern "system" fn button_subclass(
	hwnd: HWND,
	msg: u32,
	wparam: WPARAM,
	lparam: LPARAM,
	_id: usize,
	data: usize,
) -> LRESULT {
	let Some(palette) = (unsafe { std::ptr::with_exposed_provenance::<Palette>(data).as_ref() })
	else {
		return unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };
	};

	match msg {
		// Straight through, and before anything else: this is how the painter
		// and `button_look` read the button, so routing it past them would be
		// unbounded recursion rather than an answer.
		BM_GETSTATE => unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) },

		// The paint covers every pixel, so erasing first would only flicker.
		WM_ERASEBKGND => LRESULT(1),

		WM_PAINT => {
			paint_button(hwnd, palette);
			LRESULT(0)
		}

		WM_NCDESTROY => {
			let _ = unsafe { RemoveWindowSubclass(hwnd, Some(button_subclass), BUTTON_SUBCLASS) };
			unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
		}

		_ => {
			let before = button_look(hwnd);
			let repaints_itself = REPAINTS_ITSELF.contains(&msg);

			// This is the flash: for these messages the classic button draws the
			// new state the moment the message lands, straight to a device context
			// of its own rather than through WM_PAINT. The light look reaches the
			// screen and stands there until the invalidate below replaces it with
			// the dark one. Redraw off across the default handler drops that paint
			// on the floor, leaving only ours.
			//
			// Named rather than applied to everything, because the same trick over
			// WM_WINDOWPOSCHANGED would drop the repaint a move needs and leave the
			// button behind where it used to be.
			if repaints_itself {
				unsafe { SendMessageW(hwnd, WM_SETREDRAW, Some(WPARAM(0)), None) };
			}

			let result = unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) };

			if repaints_itself {
				unsafe { SendMessageW(hwnd, WM_SETREDRAW, Some(WPARAM(1)), None) };
			}

			// WM_ENABLE arrives after the style bit has already moved, and a new
			// caption is not part of the look, so neither shows up in the
			// comparison and both are named here instead.
			if msg == WM_ENABLE || msg == WM_SETTEXT || button_look(hwnd) != before {
				let _ = unsafe { InvalidateRect(Some(hwnd), None, false) };
			}

			result
		}
	}
}

const REPAINTS_ITSELF: &[u32] = &[
	WM_ENABLE,
	WM_SETTEXT,
	WM_SETFOCUS,
	WM_KILLFOCUS,
	WM_MOUSEMOVE,
	WM_MOUSELEAVE,
	WM_LBUTTONDOWN,
	WM_LBUTTONUP,
	WM_LBUTTONDBLCLK,
	WM_KEYDOWN,
	WM_KEYUP,
	BM_SETSTATE,
	BM_SETCHECK,
	BM_SETSTYLE,
];

fn button_look(hwnd: HWND) -> (u32, bool) {
	let state = ui::low_u32(unsafe { SendMessageW(hwnd, BM_GETSTATE, None, None) }.0);

	(state, unsafe { IsWindowEnabled(hwnd) }.as_bool())
}

fn paint_button(hwnd: HWND, palette: &Palette) {
	let mut paint = PAINTSTRUCT::default();
	let hdc = unsafe { BeginPaint(hwnd, &raw mut paint) };

	let mut rect = RECT::default();
	if unsafe { GetClientRect(hwnd, &raw mut rect) }.is_ok() {
		if is_check_box(hwnd) {
			draw_check_box(hwnd, hdc, rect, palette);
		} else {
			draw_push_button(hwnd, hdc, rect, palette);
		}
	}

	let _ = unsafe { EndPaint(hwnd, &raw const paint) };
}

fn rounded_slab(hdc: HDC, rect: RECT, corner: i32, face: COLORREF, border: COLORREF) {
	let brush = unsafe { CreateSolidBrush(face) };
	let pen = unsafe { CreatePen(PS_SOLID, 1, border) };
	let old_brush = unsafe { SelectObject(hdc, HGDIOBJ(brush.0)) };
	let old_pen = unsafe { SelectObject(hdc, HGDIOBJ(pen.0)) };

	let _ = unsafe {
		RoundRect(
			hdc,
			rect.left,
			rect.top,
			rect.right,
			rect.bottom,
			corner,
			corner,
		)
	};

	unsafe {
		SelectObject(hdc, old_pen);
		SelectObject(hdc, old_brush);
		let _ = DeleteObject(HGDIOBJ(pen.0));
		let _ = DeleteObject(HGDIOBJ(brush.0));
	}
}

fn draw_push_button(hwnd: HWND, hdc: HDC, rect: RECT, palette: &Palette) {
	let state = ui::low_u32(unsafe { SendMessageW(hwnd, BM_GETSTATE, None, None) }.0);
	let style = ui::low_u32(unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) });
	let disabled = !unsafe { IsWindowEnabled(hwnd) }.as_bool();
	let has = |flag: u32| state & flag != 0;

	let (face, border, text) = if disabled {
		(
			colour::BUTTON_DISABLED,
			colour::BUTTON_BORDER,
			colour::BUTTON_DISABLED_TEXT,
		)
	} else {
		let face = if has(BST_PUSHED) {
			colour::BUTTON_PRESSED
		} else if has(BST_HOT) {
			colour::BUTTON_HOT
		} else {
			colour::BUTTON_FACE
		};

		let border = if style & BUTTON_TYPE == BS_DEFPUSHBUTTON.cast_unsigned() {
			colour::BUTTON_DEFAULT_BORDER
		} else {
			colour::BUTTON_BORDER
		};

		(face, border, palette.text)
	};

	unsafe { FillRect(hdc, &raw const rect, palette.window_brush) };

	rounded_slab(hdc, rect, BUTTON_CORNER, face, border);

	draw_button_text(hwnd, hdc, rect, text);

	if has(BST_FOCUS) && !disabled {
		let focus = RECT {
			left: rect.left + FOCUS_INSET,
			top: rect.top + FOCUS_INSET,
			right: rect.right.saturating_sub(FOCUS_INSET),
			bottom: rect.bottom.saturating_sub(FOCUS_INSET),
		};

		let _ = unsafe { DrawFocusRect(hdc, &raw const focus) };
	}
}

fn draw_check_box(hwnd: HWND, hdc: HDC, rect: RECT, palette: &Palette) {
	let state = ui::low_u32(unsafe { SendMessageW(hwnd, BM_GETSTATE, None, None) }.0);
	let disabled = !unsafe { IsWindowEnabled(hwnd) }.as_bool();
	let has = |flag: u32| state & flag != 0;

	let height = rect.bottom.saturating_sub(rect.top);
	let side = unsafe { GetSystemMetrics(SM_CXMENUCHECK) }.clamp(12, height.max(12));

	let box_rect = RECT {
		left: rect.left,
		top: rect.top + height.saturating_sub(side) / 2,
		right: rect.left + side,
		bottom: rect.top + height.saturating_sub(side) / 2 + side,
	};

	let border = if disabled {
		colour::BUTTON_DISABLED_TEXT
	} else if has(BST_HOT) {
		colour::CHECK_BORDER_HOT
	} else {
		colour::CHECK_BORDER
	};

	let face = if disabled {
		colour::BUTTON_DISABLED
	} else if has(BST_HOT) {
		colour::BUTTON_HOT
	} else {
		colour::BUTTON_FACE
	};

	unsafe { FillRect(hdc, &raw const rect, palette.window_brush) };

	rounded_slab(hdc, box_rect, CHECK_CORNER, face, border);

	if has(BST_CHECKED) {
		let tick = if disabled {
			colour::BUTTON_DISABLED_TEXT
		} else {
			palette.text
		};

		draw_tick(hdc, box_rect, side, tick);
	}

	let label = RECT {
		left: box_rect.right + CHECK_GAP,
		..rect
	};

	let text = if disabled {
		colour::BUTTON_DISABLED_TEXT
	} else {
		palette.text
	};

	let drawn = draw_button_text_aligned(hwnd, hdc, label, text, DT_LEFT);

	if has(BST_FOCUS) && !disabled {
		let focus = RECT {
			left: drawn.left.saturating_sub(FOCUS_PAD),
			top: drawn.top.saturating_sub(FOCUS_PAD),
			right: drawn.right + FOCUS_PAD,
			bottom: drawn.bottom + FOCUS_PAD,
		};

		let _ = unsafe { DrawFocusRect(hdc, &raw const focus) };
	}
}

fn draw_tick(hdc: HDC, box_rect: RECT, side: i32, colour: COLORREF) {
	let along = |from: i32, numerator: i32| from + side * numerator / 100;

	let points = [
		POINT {
			x: along(box_rect.left, 24),
			y: along(box_rect.top, 52),
		},
		POINT {
			x: along(box_rect.left, 43),
			y: along(box_rect.top, 71),
		},
		POINT {
			x: along(box_rect.left, 78),
			y: along(box_rect.top, 30),
		},
	];

	let pen = unsafe { CreatePen(PS_SOLID, CHECK_TICK, colour) };
	let old_pen = unsafe { SelectObject(hdc, HGDIOBJ(pen.0)) };

	let _ = unsafe { Polyline(hdc, &points) };

	unsafe {
		SelectObject(hdc, old_pen);
		let _ = DeleteObject(HGDIOBJ(pen.0));
	}
}

fn draw_button_text(hwnd: HWND, hdc: HDC, rect: RECT, colour: COLORREF) {
	draw_button_text_aligned(hwnd, hdc, rect, colour, DT_CENTER);
}

fn draw_button_text_aligned(
	hwnd: HWND,
	hdc: HDC,
	rect: RECT,
	colour: COLORREF,
	align: DRAW_TEXT_FORMAT,
) -> RECT {
	let font = HFONT(ui::ptr_from_int(
		unsafe { SendMessageW(hwnd, WM_GETFONT, None, None) }.0,
	));
	let old_font = (!font.is_invalid()).then(|| unsafe { SelectObject(hdc, HGDIOBJ(font.0)) });

	let mut caption = [0u16; 64];
	let len = usize::try_from(unsafe { GetWindowTextW(hwnd, &mut caption) }).unwrap_or(0);

	unsafe {
		SetBkMode(hdc, TRANSPARENT);
		SetTextColor(hdc, colour);
	}

	let format = align | DT_VCENTER | DT_SINGLELINE;
	let mut drawn = rect;

	if let Some(caption) = caption.get_mut(..len) {
		let mut measured = rect;
		unsafe { DrawTextW(hdc, caption, &raw mut measured, format | DT_CALCRECT) };

		// DT_CALCRECT reports a box at the top left corner; DT_VCENTER is what
		// the real draw does with it, so the report has to be moved to match.
		let height = measured.bottom.saturating_sub(measured.top);
		let top = rect.top + rect.bottom.saturating_sub(rect.top).saturating_sub(height) / 2;

		drawn = RECT {
			left: measured.left,
			top,
			right: measured.right,
			bottom: top + height,
		};

		let mut rect = rect;
		unsafe { DrawTextW(hdc, caption, &raw mut rect, format) };
	}

	if let Some(old_font) = old_font {
		unsafe { SelectObject(hdc, old_font) };
	}

	drawn
}

pub fn apply_listview(list: HWND, palette: &Palette) {
	apply_control(list, palette.dark);

	let header = HWND(ui::ptr_from_int(
		unsafe { SendMessageW(list, LVM_GETHEADER, None, None) }.0,
	));
	if !header.is_invalid() {
		allow_dark(header, palette.dark);
		set_theme(
			header,
			if palette.dark {
				w!("ItemsView")
			} else {
				PCWSTR::null()
			},
		);
	}

	for (message, colour) in [
		(LVM_SETBKCOLOR, palette.field),
		(LVM_SETTEXTBKCOLOR, palette.field),
		(LVM_SETTEXTCOLOR, palette.text),
	] {
		unsafe {
			SendMessageW(
				list,
				message,
				None,
				Some(LPARAM(isize::try_from(colour.0).unwrap_or_default())),
			)
		};
	}
}

pub fn erase_background(hwnd: HWND, hdc: HDC, palette: &Palette) -> LRESULT {
	let mut client = RECT::default();

	if unsafe { GetClientRect(hwnd, &raw mut client) }.is_ok() {
		unsafe { FillRect(hdc, &raw const client, palette.window_brush) };
	}

	LRESULT(1)
}

pub fn ctl_colour(hdc: HDC, text: COLORREF, palette: &Palette) -> LRESULT {
	unsafe {
		SetTextColor(hdc, text);
		SetBkColor(hdc, palette.window);
	}

	LRESULT(ui::int_from_ptr(palette.window_brush.0))
}

pub fn ctl_colour_field(hdc: HDC, palette: &Palette) -> LRESULT {
	unsafe {
		SetTextColor(hdc, palette.text);
		SetBkColor(hdc, palette.field);
	}

	LRESULT(ui::int_from_ptr(palette.field_brush.0))
}

pub fn ctl_colour_rule(palette: &Palette) -> LRESULT {
	LRESULT(ui::int_from_ptr(palette.rule_brush.0))
}

pub fn repaint(hwnd: HWND) {
	let _ = unsafe { InvalidateRect(Some(hwnd), None, true) };
}
