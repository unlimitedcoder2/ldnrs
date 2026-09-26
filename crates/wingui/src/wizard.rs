use std::cell::{Cell, RefCell};
use std::path::PathBuf;

use ldn::winusb::{self, UsbDevice};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{HBRUSH, HDC, UpdateWindow};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemServices::SS_LEFT;
use windows::Win32::UI::Controls::{
	LVM_SETEXTENDEDLISTVIEWSTYLE, LVN_ITEMCHANGED, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT,
	LVS_NOSORTHEADER, LVS_REPORT, LVS_SHOWSELALWAYS, LVS_SINGLESEL, NM_DBLCLK, NMHDR, PBS_SMOOTH,
	PROGRESS_CLASSW, WC_LISTVIEWW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
	AdjustWindowRectEx, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CREATESTRUCTW,
	CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow, ES_AUTOHSCROLL,
	ES_READONLY, GWLP_USERDATA, GetClientRect, GetSystemMetrics, GetWindowLongPtrW, IDC_ARROW,
	IDCANCEL, IDYES, IsWindow, LoadCursorW, MB_ICONWARNING, MB_YESNO, MoveWindow, PostQuitMessage,
	RegisterClassW, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW, SendMessageW, SetWindowLongPtrW, ShowWindow,
	WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_CTLCOLORBTN,
	WM_CTLCOLORSTATIC, WM_DESTROY, WM_ERASEBKGND, WM_NCCREATE, WM_NOTIFY, WM_SETTINGCHANGE,
	WM_SIZE, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_GROUP, WS_MINIMIZEBOX,
	WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use windows::core::{PCWSTR, w};

use crate::app::App;
use crate::codesign;
use crate::config;
use crate::daemon::{self, WM_DAEMON_STATUS};
use crate::firmware::{self, WM_FIRMWARE_DONE, WM_FIRMWARE_PROGRESS};
use crate::install;
use crate::keys;
use crate::lkl;
use crate::logwindow;
use crate::theme::{self, Theme};
use crate::ui::{self, Fonts};

const ID_BACK: i32 = 101;
const ID_NEXT: i32 = 102;
const ID_CANCEL: i32 = 103;
const ID_REFRESH: i32 = 104;
const ID_LIST: i32 = 105;
const ID_SHOW_ALL: i32 = 106;
const ID_BROWSE: i32 = 107;
const ID_KEYS_PATH: i32 = 108;

pub const CLIENT_WIDTH: i32 = 660;
pub const CLIENT_HEIGHT: i32 = 470;

const MARGIN: i32 = 20;
const HEADER_HEIGHT: i32 = 74;
const FOOTER_HEIGHT: i32 = 52;
const BUTTON_WIDTH: i32 = 104;
const BUTTON_HEIGHT: i32 = 26;
const CHECKBOX_WIDTH: i32 = 130;

const WINUSB_SERVICE: &str = "winusb";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
	Welcome,
	Select,
	Result,
	Install,
	Firmware,
	Keys,
}

#[derive(Clone, Copy)]
struct Controls {
	title: HWND,
	subtitle: HWND,
	header_rule: HWND,
	footer_rule: HWND,

	welcome_text: HWND,

	list: HWND,
	refresh: HWND,
	show_all: HWND,
	list_hint: HWND,

	verdict: HWND,
	details: HWND,
	advice: HWND,

	install_intro: HWND,
	install_status: HWND,

	firmware_intro: HWND,
	firmware_status: HWND,
	firmware_progress: HWND,

	keys_intro: HWND,
	keys_path: HWND,
	keys_browse: HWND,
	keys_status: HWND,

	back: HWND,
	next: HWND,
	cancel: HWND,
}

impl Controls {
	const fn all(&self) -> [HWND; 24] {
		[
			self.title,
			self.subtitle,
			self.header_rule,
			self.footer_rule,
			self.welcome_text,
			self.list,
			self.refresh,
			self.show_all,
			self.list_hint,
			self.verdict,
			self.details,
			self.advice,
			self.install_intro,
			self.install_status,
			self.firmware_intro,
			self.firmware_status,
			self.firmware_progress,
			self.keys_intro,
			self.keys_path,
			self.keys_browse,
			self.keys_status,
			self.back,
			self.next,
			self.cancel,
		]
	}
}

pub struct Wizard {
	fonts: Fonts,
	theme: Theme,
	controls: RefCell<Option<Controls>>,
	dialog: Cell<Option<HWND>>,
	app: App,
	page: Cell<Page>,
	devices: RefCell<Vec<UsbDevice>>,
	show_all: Cell<bool>,
	selected: RefCell<Option<UsbDevice>>,
	keys_path: RefCell<Option<PathBuf>>,
	keys_status: RefCell<String>,
	keys_ok: Cell<bool>,
	serving: Cell<bool>,
	daemon: RefCell<Option<daemon::Handle>>,
	daemon_status: RefCell<String>,
	attaching: Cell<bool>,
	adapter_status: RefCell<String>,
	log_window: Cell<Option<HWND>>,
	exiting: Cell<bool>,
	verdict_ok: Cell<bool>,
	downloading: Cell<bool>,
	firmware_ready: Cell<bool>,
	firmware_total: Cell<usize>,
	progress_shown: Cell<bool>,
	lkl_state: Cell<LklState>,
	open_windows: Cell<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LklState {
	Idle,
	Starting,
	Running,
	Stopped,
	Failed,
}

#[must_use]
fn hint(shown: usize, total: usize) -> String {
	let hidden = total.saturating_sub(shown);

	match (shown, hidden) {
		(0, 0) => "No USB devices found.".to_owned(),
		(0, hidden) => format!("No likely adapters. Show all devices to see the other {hidden}."),
		(_, 0) => format!("Showing all {total} devices."),
		(_, hidden) => format!("Showing {shown} of {total} devices; {hidden} hidden."),
	}
}

#[must_use]
fn is_winusb(device: &UsbDevice) -> bool {
	device.driver.eq_ignore_ascii_case(WINUSB_SERVICE)
}

#[derive(Clone, Copy)]
struct Body {
	top: i32,
	height: i32,
	width: i32,
}

fn place(control: HWND, x: i32, y: i32, w: i32, h: i32) {
	let _ = unsafe { MoveWindow(control, x, y, w, h, true) };
}

fn layout_select(controls: &Controls, body: Body) {
	let list_height = body
		.height
		.saturating_sub(BUTTON_HEIGHT)
		.saturating_sub(MARGIN * 2);
	place(controls.list, MARGIN, body.top, body.width, list_height);
	place(
		controls.refresh,
		MARGIN,
		body.top + list_height + MARGIN / 2,
		BUTTON_WIDTH,
		BUTTON_HEIGHT,
	);
	let under_list = body.top + list_height + MARGIN / 2;
	let show_all_x = MARGIN + BUTTON_WIDTH + 12;

	place(
		controls.show_all,
		show_all_x,
		under_list + 4,
		CHECKBOX_WIDTH,
		BUTTON_HEIGHT.saturating_sub(6),
	);

	let hint_x = show_all_x + CHECKBOX_WIDTH + 12;
	place(
		controls.list_hint,
		hint_x,
		under_list + 5,
		body.width.saturating_sub(hint_x) + MARGIN,
		40,
	);
}

fn layout_pages(controls: &Controls, body: Body) {
	place(
		controls.welcome_text,
		MARGIN,
		body.top,
		body.width,
		body.height,
	);

	place(controls.verdict, MARGIN, body.top, body.width, 28);
	place(controls.details, MARGIN, body.top + 44, body.width, 104);
	place(
		controls.advice,
		MARGIN,
		body.top + 160,
		body.width,
		body.height.saturating_sub(160),
	);

	place(
		controls.install_intro,
		MARGIN,
		body.top,
		body.width,
		body.height.saturating_sub(60),
	);
	place(
		controls.install_status,
		MARGIN,
		(body.top + body.height).saturating_sub(56),
		body.width,
		56,
	);

	place(
		controls.firmware_intro,
		MARGIN,
		body.top,
		body.width,
		body.height.saturating_sub(90),
	);
	place(
		controls.firmware_progress,
		MARGIN,
		(body.top + body.height).saturating_sub(80),
		body.width,
		18,
	);
	place(
		controls.firmware_status,
		MARGIN,
		(body.top + body.height).saturating_sub(54),
		body.width,
		54,
	);

	place(controls.keys_intro, MARGIN, body.top, body.width, 76);

	let keys_row = body.top + 84;
	let keys_path_width = body
		.width
		.saturating_sub(BUTTON_WIDTH)
		.saturating_sub(MARGIN / 2);
	place(controls.keys_path, MARGIN, keys_row, keys_path_width, 24);
	place(
		controls.keys_browse,
		MARGIN + keys_path_width + MARGIN / 2,
		keys_row.saturating_sub(1),
		BUTTON_WIDTH,
		BUTTON_HEIGHT,
	);
	place(controls.keys_status, MARGIN, keys_row + 36, body.width, 40);
}

fn setup_list(list: HWND) {
	unsafe {
		SendMessageW(
			list,
			LVM_SETEXTENDEDLISTVIEWSTYLE,
			None,
			Some(LPARAM(
				isize::try_from(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER).unwrap_or_default(),
			)),
		)
	};

	ui::list_add_column(list, 0, "Device", 268);
	ui::list_add_column(list, 1, "VID:PID", 84);
	ui::list_add_column(list, 2, "Driver", 130);
}

impl Wizard {
	#[must_use]
	pub fn new(app: App) -> Self {
		Self {
			fonts: Fonts::new(),
			theme: Theme::new(),
			controls: RefCell::new(None),
			dialog: Cell::new(None),
			app,
			page: Cell::new(Page::Welcome),
			devices: RefCell::new(Vec::new()),
			show_all: Cell::new(false),
			selected: RefCell::new(None),
			keys_path: RefCell::new(config::keys_path()),
			keys_status: RefCell::new(String::new()),
			keys_ok: Cell::new(false),
			serving: Cell::new(false),
			daemon: RefCell::new(None),
			daemon_status: RefCell::new(String::new()),
			attaching: Cell::new(false),
			adapter_status: RefCell::new(String::new()),
			log_window: Cell::new(None),
			exiting: Cell::new(false),
			verdict_ok: Cell::new(false),
			downloading: Cell::new(false),
			firmware_ready: Cell::new(false),
			firmware_total: Cell::new(1),
			progress_shown: Cell::new(false),
			lkl_state: Cell::new(LklState::Idle),
			open_windows: Cell::new(0),
		}
	}

	fn create_controls(&self, hwnd: HWND) -> anyhow::Result<()> {
		let child = WS_CHILD | WS_VISIBLE;
		let label = WINDOW_STYLE(child.0 | SS_LEFT.0);
		let hidden_label = WINDOW_STYLE(WS_CHILD.0 | SS_LEFT.0);
		let button = WINDOW_STYLE(child.0 | WS_TABSTOP.0 | BS_PUSHBUTTON.cast_unsigned());
		let hidden_button = WINDOW_STYLE(WS_CHILD.0 | WS_TABSTOP.0 | BS_PUSHBUTTON.cast_unsigned());
		let default_button =
			WINDOW_STYLE(child.0 | WS_TABSTOP.0 | BS_DEFPUSHBUTTON.cast_unsigned());

		let text = |text: &str, style: WINDOW_STYLE, font| {
			ui::create_control(
				hwnd,
				w!("STATIC"),
				text,
				style,
				WINDOW_EX_STYLE::default(),
				0,
				font,
			)
		};
		let control = |class, text: &str, style: WINDOW_STYLE, id| {
			ui::create_control(
				hwnd,
				class,
				text,
				style,
				WINDOW_EX_STYLE::default(),
				id,
				self.fonts.ui,
			)
		};

		let controls = Controls {
			title: text("", label, self.fonts.heading)?,
			subtitle: text("", label, self.fonts.ui)?,
			header_rule: text("", label, self.fonts.ui)?,
			footer_rule: text("", label, self.fonts.ui)?,

			welcome_text: text("", label, self.fonts.ui)?,

			list: control(
				WC_LISTVIEWW,
				"",
				WINDOW_STYLE(
					WS_CHILD.0
						| WS_TABSTOP.0 | WS_BORDER.0
						| LVS_REPORT | LVS_SINGLESEL
						| LVS_SHOWSELALWAYS
						| LVS_NOSORTHEADER,
				),
				ID_LIST,
			)?,
			refresh: control(w!("BUTTON"), "&Refresh", hidden_button, ID_REFRESH)?,
			show_all: control(
				w!("BUTTON"),
				"Show &all devices",
				WINDOW_STYLE(WS_CHILD.0 | WS_TABSTOP.0 | BS_AUTOCHECKBOX.cast_unsigned()),
				ID_SHOW_ALL,
			)?,
			list_hint: text("", hidden_label, self.fonts.ui)?,

			verdict: text("", hidden_label, self.fonts.heading)?,
			details: text("", hidden_label, self.fonts.ui)?,
			advice: text("", hidden_label, self.fonts.ui)?,

			install_intro: text("", hidden_label, self.fonts.ui)?,
			install_status: text("", hidden_label, self.fonts.ui)?,

			firmware_intro: text("", hidden_label, self.fonts.ui)?,
			firmware_status: text("", hidden_label, self.fonts.ui)?,
			firmware_progress: control(
				PROGRESS_CLASSW,
				"",
				WINDOW_STYLE(WS_CHILD.0 | PBS_SMOOTH),
				0,
			)?,

			keys_intro: text("", hidden_label, self.fonts.ui)?,
			keys_path: control(
				w!("EDIT"),
				"",
				WINDOW_STYLE(
					WS_CHILD.0
						| WS_BORDER.0 | WS_TABSTOP.0
						| (ES_READONLY | ES_AUTOHSCROLL).cast_unsigned(),
				),
				ID_KEYS_PATH,
			)?,
			keys_browse: control(w!("BUTTON"), "&Browse...", hidden_button, ID_BROWSE)?,
			keys_status: text("", hidden_label, self.fonts.ui)?,

			back: control(
				w!("BUTTON"),
				"< &Back",
				WINDOW_STYLE(button.0 | WS_GROUP.0),
				ID_BACK,
			)?,
			next: control(w!("BUTTON"), "&Next >", default_button, ID_NEXT)?,
			cancel: control(w!("BUTTON"), "Cancel", button, ID_CANCEL)?,
		};

		setup_list(controls.list);

		*self.controls.borrow_mut() = Some(controls);

		self.show_page(Page::Welcome);

		Ok(())
	}

	fn controls(&self) -> Option<Controls> {
		*self.controls.borrow()
	}

	fn layout(&self, hwnd: HWND) {
		let Some(controls) = self.controls() else {
			return;
		};

		let mut client = RECT::default();
		if unsafe { GetClientRect(hwnd, &raw mut client) }.is_err() {
			return;
		}

		let width = client.right;
		let height = client.bottom;
		let content_width = width.saturating_sub(MARGIN * 2);

		place(controls.title, MARGIN, 16, content_width, 26);
		place(controls.subtitle, MARGIN, 44, content_width, 20);
		place(controls.header_rule, 0, HEADER_HEIGHT, width, 1);

		let body_top = HEADER_HEIGHT + MARGIN;
		let footer_top = height.saturating_sub(FOOTER_HEIGHT);
		let body_height = footer_top.saturating_sub(body_top).saturating_sub(MARGIN);

		let body = Body {
			top: body_top,
			height: body_height,
			width: content_width,
		};
		layout_select(&controls, body);
		layout_pages(&controls, body);

		place(controls.footer_rule, 0, footer_top, width, 1);

		let button_y = footer_top + 14;
		let cancel_x = width.saturating_sub(MARGIN).saturating_sub(BUTTON_WIDTH);
		let next_x = cancel_x.saturating_sub(BUTTON_WIDTH).saturating_sub(10);
		let back_x = next_x.saturating_sub(BUTTON_WIDTH);

		place(controls.back, back_x, button_y, BUTTON_WIDTH, BUTTON_HEIGHT);
		place(controls.next, next_x, button_y, BUTTON_WIDTH, BUTTON_HEIGHT);
		place(
			controls.cancel,
			cancel_x,
			button_y,
			BUTTON_WIDTH,
			BUTTON_HEIGHT,
		);
	}

	fn show_page(&self, page: Page) {
		let Some(controls) = self.controls() else {
			return;
		};

		self.page.set(page);

		let welcome = page == Page::Welcome;
		let select = page == Page::Select;
		let result = page == Page::Result;
		let install = page == Page::Install;
		let firmware = page == Page::Firmware;
		let keys = page == Page::Keys;

		ui::show_many(&[
			(controls.welcome_text, welcome),
			(controls.list, select),
			(controls.refresh, select),
			(controls.show_all, select),
			(controls.list_hint, select),
			(controls.verdict, result),
			(controls.details, result),
			(controls.advice, result),
			(controls.install_intro, install),
			(controls.install_status, install),
			(controls.keys_intro, keys),
			(controls.keys_path, keys),
			(controls.keys_browse, keys),
			(controls.keys_status, keys),
			(controls.firmware_intro, firmware),
			(controls.firmware_status, firmware),
			(
				controls.firmware_progress,
				firmware && self.progress_shown.get(),
			),
		]);

		self.set_page_text(&controls, page);
	}

	fn set_page_text(&self, controls: &Controls, page: Page) {
		match page {
			Page::Welcome => {
				ui::set_text(
					controls.title,
					"Welcome to the nintendo local networking tool",
				);
				ui::set_text(controls.subtitle, "Switch ldn (supported) 3ds nwm (TODO)");
				ui::set_text(controls.next, "&Next >");
				ui::enable(controls.back, false);
				ui::enable(controls.next, true);
			}
			Page::Select => {
				ui::set_text(controls.title, "Select a USB device");
				ui::set_text(
					controls.subtitle,
					"Pick the adapter you want to use, then click Next.",
				);
				ui::set_text(controls.next, "&Next >");
				ui::enable(controls.back, true);
				ui::enable(controls.next, ui::list_selection(controls.list).is_some());
				let _ = unsafe { SetFocus(Some(controls.list)) };
			}
			Page::Result => {
				ui::set_text(controls.title, "Driver check");
				ui::set_text(controls.subtitle, "");
				ui::set_text(
					controls.next,
					if self.verdict_ok.get() {
						"&Next >"
					} else {
						"&Install WinUSB >"
					},
				);
				ui::enable(controls.back, true);
				ui::enable(controls.next, true);
			}
			Page::Install => {
				ui::set_text(controls.title, "Install the WinUSB driver");
				ui::set_text(
					controls.subtitle,
					"Windows will load WinUSB for this device instead of its current driver.",
				);
				ui::set_text(
					controls.next,
					if self.verdict_ok.get() {
						"&Next >"
					} else {
						"&Install"
					},
				);
				ui::enable(controls.back, true);
				ui::enable(controls.next, true);
			}
			Page::Keys => {
				ui::set_text(controls.title, "Choose your prod.keys");
				ui::set_text(
					controls.subtitle,
					"ldnrs needs your console's keys to read LDN traffic.",
				);
				ui::set_text(controls.next, "&Next >");
				ui::enable(controls.back, true);
				ui::enable(controls.next, self.keys_ok.get());
			}
			Page::Firmware => {
				ui::set_text(controls.title, "Download the driver firmware");
				ui::set_text(
					controls.subtitle,
					"ldnrs fetches the linux-firmware files the driver for this adapter needs.",
				);
				ui::set_text(
					controls.next,
					if self.firmware_ready.get() {
						"&Finish"
					} else {
						"&Download"
					},
				);
				let idle = !self.downloading.get() && self.lkl_state.get() != LklState::Starting;
				ui::enable(controls.back, idle);
				ui::enable(controls.next, idle);
			}
		}
	}

	fn start_lkl(&self, hwnd: HWND) {
		if self.lkl_state.get() != LklState::Idle {
			return;
		}

		let window = match logwindow::open(self, hwnd) {
			Ok(window) => window,
			Err(err) => {
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not open the lkl window:\r\n\r\n{err:#}"),
				);
				return;
			}
		};

		self.lkl_state.set(LklState::Starting);
		self.log_window.set(Some(window));
		lkl::start(&self.app, window);
	}

	fn cancel(&self) {
		self.begin_exit();
	}

	pub fn begin_exit(&self) {
		if self.exiting.replace(true) {
			self.close_windows();
			return;
		}

		match self.log_window.get() {
			Some(window) if self.lkl_running() => lkl::shutdown(&self.app, window),

			_ => self.close_windows(),
		}
	}

	/// Destroys every window this app opened, which empties the count and ends the message loop.
	///
	/// **Callers inside a window procedure must not touch that window's own state afterwards.**
	/// `DestroyWindow` delivers `WM_DESTROY` and `WM_NCDESTROY` before it returns, so by the time
	/// this call is done the state those windows hang off has already been dropped.
	fn close_windows(&self) {
		if let Some(dialog) = self.dialog() {
			let _ = unsafe { DestroyWindow(dialog) };
		}

		if let Some(window) = self.log_window.take() {
			let _ = unsafe { DestroyWindow(window) };
		}
	}

	pub const fn exiting(&self) -> bool {
		self.exiting.get()
	}

	pub fn lkl_running(&self) -> bool {
		self.lkl_state.get() == LklState::Running
	}

	pub fn shutdown_lkl(&self, window: HWND) {
		if self.lkl_running() {
			lkl::shutdown(&self.app, window);
		}
	}

	pub fn on_lkl_ready(&self, window: HWND, outcome: lkl::Outcome) {
		match outcome {
			Ok(()) => self.lkl_state.set(LklState::Running),
			Err(err) => {
				self.lkl_state.set(LklState::Failed);
				self.show_log_window();
				ui::error_box(
					Some(window),
					"ldnrs",
					&format!("Could not start lkl:\r\n\r\n{err}"),
				);
			}
		}

		if self.page.get() == Page::Firmware {
			self.show_firmware();
		}
		self.show_page(self.page.get());

		if let Some(dialog) = self.dialog()
			&& self.page.get() == Page::Firmware
		{
			self.complete(dialog);
		}
	}

	pub fn on_lkl_stopped(&self, outcome: &lkl::Outcome) {
		if outcome.is_ok() {
			self.lkl_state.set(LklState::Stopped);
		}
	}

	pub fn finish_exit(&self) {
		if self.exiting.get() {
			self.close_windows();
		}
	}

	pub fn lkl_status(&self) -> String {
		let kernel = match self.lkl_state.get() {
			LklState::Idle => "",
			LklState::Starting => "Starting",
			LklState::Running => "Running.",
			LklState::Stopped => "Stopped.",
			LklState::Failed => "Error.",
		};

		let adapter = self.adapter_status.borrow();

		if adapter.is_empty() {
			kernel.to_owned()
		} else {
			format!("{kernel} {adapter}")
		}
	}

	pub const fn theme(&self) -> &Theme {
		&self.theme
	}

	pub const fn fonts(&self) -> &Fonts {
		&self.fonts
	}

	pub fn dialog(&self) -> Option<HWND> {
		let hwnd = self.dialog.get()?;

		if unsafe { IsWindow(Some(hwnd)) }.as_bool() {
			Some(hwnd)
		} else {
			None
		}
	}

	fn show_keys(&self) {
		let Some(controls) = self.controls() else {
			return;
		};

		let path = self.keys_path.borrow().clone();

		if self.keys_status.borrow().is_empty()
			&& let Some(path) = path.as_ref()
		{
			let verdict = keys::inspect(path);
			self.keys_ok.set(verdict.ok);
			*self.keys_status.borrow_mut() = verdict.text;
		}

		ui::set_text(
			controls.keys_intro,
			"LDN traffic is encrypted with keys derived from your console's own keys, so ldnrs \
			 needs a prod.keys file to read it. It cannot ship with ldnrs: the keys come off \
			 your own console.\r\n\r\nThe file is remembered, so this only has to be done once.",
		);

		ui::set_text(
			controls.keys_path,
			&path
				.as_ref()
				.map_or_else(String::new, |path| path.display().to_string()),
		);

		let status = if path.is_none() {
			"Click Browse to choose the file. Setup cannot go on without it.".to_owned()
		} else {
			self.keys_status.borrow().clone()
		};

		let daemon_status = self.daemon_status.borrow().clone();
		ui::set_text(
			controls.keys_status,
			&if daemon_status.is_empty() {
				status
			} else {
				format!("{status}\r\n{daemon_status}")
			},
		);

		ui::enable(controls.next, self.keys_ok.get());

		if let Some(hwnd) = self.dialog() {
			self.start_daemon(hwnd);
		}
	}

	fn start_daemon(&self, hwnd: HWND) {
		if self.serving.get() || !self.keys_ok.get() {
			return;
		}

		let Some(keys) = self.keys_path.borrow().clone() else {
			return;
		};

		self.serving.set(true);
		*self.daemon.borrow_mut() = Some(daemon::start(&self.app, hwnd, keys));
	}

	fn start_adapter(&self) {
		if self.attaching.get()
			|| self.lkl_state.get() != LklState::Running
			|| !self.firmware_ready.get()
		{
			return;
		}

		let Some(window) = self.log_window.get() else {
			return;
		};

		let Some(device) = self.selected.borrow().clone() else {
			return;
		};

		let daemon = self.daemon.borrow();
		let Some(daemon) = daemon.as_ref() else {
			return;
		};

		self.attaching.set(true);
		"Attaching the adapter...".clone_into(&mut self.adapter_status.borrow_mut());
		daemon.attach(device, window);
	}

	pub fn on_adapter_status(&self, status: daemon::Adapter) {
		*self.adapter_status.borrow_mut() = match status {
			Ok(()) => "Adapter ready.".to_owned(),
			Err(err) => format!("Adapter failed: {err}"),
		};
	}

	pub fn on_daemon_status(&self, hwnd: HWND, status: daemon::Status) {
		match status {
			Ok(()) => {
				*self.daemon_status.borrow_mut() =
					format!("Clients can connect on {}.", daemon::PIPE);
			}
			Err(err) => {
				*self.daemon_status.borrow_mut() = String::new();
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not serve {}:\r\n\r\n{err}", daemon::PIPE),
				);
			}
		}

		self.show_keys();
	}

	fn browse_keys(&self, hwnd: HWND) {
		let Some(path) = keys::ask_for_file(hwnd) else {
			return;
		};

		let verdict = keys::inspect(&path);

		self.keys_ok.set(verdict.ok);
		*self.keys_status.borrow_mut() = verdict.text;
		*self.keys_path.borrow_mut() = Some(path.clone());

		if !self.keys_ok.get() {
			self.show_keys();
			return;
		}

		if let Err(err) = config::set_keys_path(&path) {
			ui::error_box(
				Some(hwnd),
				"ldnrs",
				&format!(
					"The keys file was read, but could not be saved for next time:\r\n\r\n{err}"
				),
			);
		}

		self.show_keys();
	}

	fn complete(&self, hwnd: HWND) {
		if self.lkl_state.get() != LklState::Running || !self.firmware_ready.get() {
			return;
		}

		self.start_adapter();
		self.show_log_window();

		let _ = unsafe { DestroyWindow(hwnd) };
	}

	fn show_log_window(&self) {
		if let Some(window) = self.log_window.get() {
			let _ = unsafe { ShowWindow(window, SW_SHOW) };
		}
	}

	pub fn window_opened(&self) {
		self.open_windows.set(self.open_windows.get() + 1);
	}

	pub fn window_closed(&self) {
		let left = self.open_windows.get().saturating_sub(1);
		self.open_windows.set(left);

		if left == 0 {
			unsafe { PostQuitMessage(0) };
		}
	}

	fn refresh_devices(&self, hwnd: HWND) {
		let Some(controls) = self.controls() else {
			return;
		};

		let all = match winusb::get_devices() {
			Ok(devices) => devices,
			Err(err) => {
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not enumerate USB devices:\r\n\r\n{err:#}"),
				);
				Vec::new()
			}
		};

		let total = all.len();

		let show_all = self.show_all.get();
		let devices: Vec<UsbDevice> = all
			.into_iter()
			.filter(|device| show_all || device.might_be_a_wifi_adapter())
			.collect();

		let selected = ui::list_selection(controls.list)
			.and_then(|index| self.devices.borrow().get(index).cloned());

		ui::list_clear(controls.list);

		for (index, device) in devices.iter().enumerate() {
			let vidpid = format!("{:04x}:{:04x}", device.vid, device.pid);

			ui::list_add_row(
				controls.list,
				i32::try_from(index).unwrap_or(i32::MAX),
				&[&device.name, &vidpid, &device.driver],
			);
		}

		let reselect = selected.and_then(|previous| {
			devices
				.iter()
				.position(|device| device.path == previous.path)
		});

		let shown = devices.len();
		*self.devices.borrow_mut() = devices;

		if let Some(index) = reselect {
			ui::list_select(controls.list, index);
		}

		ui::set_text(controls.list_hint, &hint(shown, total));
		ui::enable(controls.next, ui::list_selection(controls.list).is_some());
	}

	fn selected_device(&self) -> Option<UsbDevice> {
		let controls = self.controls()?;
		let index = ui::list_selection(controls.list)?;
		self.devices.borrow().get(index).cloned()
	}

	fn show_result(&self, device: &UsbDevice) {
		let Some(controls) = self.controls() else {
			return;
		};

		let ok = is_winusb(device);
		self.verdict_ok.set(ok);
		*self.selected.borrow_mut() = Some(device.clone());

		ui::set_text(
			controls.verdict,
			if ok {
				"This device is using WinUSB"
			} else {
				"This device is not using WinUSB"
			},
		);

		ui::set_text(
			controls.details,
			&format!(
				"Device:\t{}\r\nVID:PID:\t{:04x}:{:04x}\r\nDriver:\t{}\r\nPath:\t{}",
				device.name, device.vid, device.pid, device.driver, device.path
			),
		);
	}

	fn show_install(&self) {
		let Some(controls) = self.controls() else {
			return;
		};

		let Some(device) = self.selected.borrow().clone() else {
			return;
		};

		ui::set_text(
			controls.install_intro,
			&format!(
				"The wizard will bind WinUSB to:\r\n\r\n    {} ({:04x}:{:04x}), currently using \
				 \"{}\"\r\n\r\nIt writes a WinUSB driver package for this hardware ID and asks \
				 Windows to install it, which needs administrator rights. Only this device is \
				 affected, and you can put the old driver back from Device Manager with Update \
				 driver > Browse my computer > Let me pick.\r\n\r\nWindows only accepts driver \
				 packages whose catalog is signed, so the install can be refused on a machine \
				 without test signing.\r\n\r\nClick Install to be asked for confirmation.",
				device.name, device.vid, device.pid, device.driver
			),
		);

		ui::set_text(controls.install_status, "");
	}

	fn run_install(&self, hwnd: HWND) {
		let Some(controls) = self.controls() else {
			return;
		};

		let Some(device) = self.selected.borrow().clone() else {
			return;
		};

		let answer = ui::message_box(
			Some(hwnd),
			"Install WinUSB?",
			&format!(
				"Bind WinUSB to {} ({:04x}:{:04x}) in place of \"{}\"?\r\n\r\nWindows will stop \
				 using the current driver for this device.\r\n\r\nWindows only installs signed \
				 driver packages, so a certificate named \"{}\" will be created and trusted on \
				 this machine to sign it. Its private key is destroyed once the package is \
				 signed, so nothing else can be signed with it.",
				device.name,
				device.vid,
				device.pid,
				device.driver,
				codesign::certificate_subject(&install::hardware_id(&device)),
			),
			MB_YESNO | MB_ICONWARNING,
		);

		if answer != IDYES {
			ui::set_text(controls.install_status, "Nothing was installed.");
			return;
		}

		ui::set_text(controls.install_status, "Installing...");

		match install::install(hwnd, &device) {
			Ok(outcome) => {
				let reboot = if outcome.reboot_required {
					" Reboot to finish."
				} else {
					""
				};

				ui::set_text(
					controls.install_status,
					&format!(
						"WinUSB installed from {}.{reboot}",
						outcome.inf_path.display()
					),
				);

				self.recheck_device(hwnd, &device);
			}
			Err(err) => {
				ui::set_text(controls.install_status, "The driver was not installed.");
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not install WinUSB:\r\n\r\n{err:#}"),
				);
			}
		}
	}

	fn recheck_device(&self, hwnd: HWND, device: &UsbDevice) {
		self.refresh_devices(hwnd);

		let updated = self
			.devices
			.borrow()
			.iter()
			.find(|d| d.vid == device.vid && d.pid == device.pid)
			.cloned();

		if let Some(updated) = updated {
			self.show_result(&updated);
			self.show_page(Page::Install);
		}
	}

	fn show_firmware(&self) {
		let Some(controls) = self.controls() else {
			return;
		};

		let Some(device) = self.selected.borrow().clone() else {
			return;
		};

		let destination = ldn::firmware_dir().map_or_else(
			|_| "your home directory".to_owned(),
			|dir| dir.display().to_string(),
		);

		if self.lkl_state.get() == LklState::Starting {
			self.firmware_ready.set(false);
			self.progress_shown.set(false);
			ui::set_text(
				controls.firmware_intro,
				&format!(
					"Starting lkl to find out which firmware the driver for {} ({:04x}:{:04x}) \
					 needs...",
					device.name, device.vid, device.pid
				),
			);
			ui::set_text(controls.firmware_status, "");
			return;
		}

		let missing = self.app.lkl.missing_firmware(&device);
		let nothing_missing = missing.as_ref().is_ok_and(Vec::is_empty);

		self.firmware_ready.set(nothing_missing);
		self.progress_shown.set(false);

		let body = if nothing_missing {
			format!(
				"The firmware the driver for {} ({:04x}:{:04x}) needs is already \
				 here:\r\n\r\n    {destination}\r\n\r\nThere is nothing left to download.",
				device.name, device.vid, device.pid
			)
		} else {
			let count = missing.as_ref().map_or(0, Vec::len);
			let files = if count == 1 { "file" } else { "files" };
			let missing = if count == 0 {
				String::new()
			} else {
				format!("{count} {files} are missing. ")
			};

			format!(
				"The driver for {} ({:04x}:{:04x}) loads firmware blobs that cannot ship with \
				 ldnrs, so they are fetched from the kernel.org linux-firmware tree.\r\n\r\nThey \
				 are written to:\r\n\r\n    {destination}\r\n\r\n{missing}Files already there are \
				 kept, so this only fetches what is missing. It needs an internet \
				 connection.\r\n\r\nClick Download to fetch them now.",
				device.name, device.vid, device.pid
			)
		};

		ui::set_text(controls.firmware_intro, &body);

		ui::set_text(
			controls.firmware_status,
			&match missing {
				Ok(_) => String::new(),
				Err(err) => format!("Could not read the firmware list: {err:#}"),
			},
		);
	}

	fn start_download(&self, hwnd: HWND) {
		let Some(controls) = self.controls() else {
			return;
		};

		let Some(device) = self.selected.borrow().clone() else {
			return;
		};

		if self.downloading.get() {
			return;
		}

		self.downloading.set(true);
		self.progress_shown.set(true);
		self.set_progress(0, 1);
		ui::set_text(
			controls.firmware_status,
			"Downloading... this can take a while on the first run.",
		);
		self.show_page(Page::Firmware);

		firmware::start(&self.app, hwnd, device);
	}

	fn fill_progress(&self) {
		let total = self.firmware_total.get();
		self.set_progress(total, total);
	}

	fn set_progress(&self, done: usize, total: usize) {
		let Some(controls) = self.controls() else {
			return;
		};

		self.firmware_total.set(total.max(1));
		let total = i32::try_from(total.max(1)).unwrap_or(i32::MAX);
		let done = i32::try_from(done).unwrap_or(i32::MAX).min(total);

		ui::set_progress_range(controls.firmware_progress, total);
		ui::set_progress_pos(controls.firmware_progress, done);
	}

	fn on_firmware_progress(&self, done: usize, total: usize) {
		let Some(controls) = self.controls() else {
			return;
		};

		self.set_progress(done, total);

		ui::set_text(
			controls.firmware_status,
			&format!("Downloading firmware... {done} of {total} files."),
		);
	}

	fn on_firmware_done(&self, hwnd: HWND, outcome: firmware::Outcome) {
		let Some(controls) = self.controls() else {
			return;
		};

		self.downloading.set(false);

		match outcome {
			Ok(dir) => {
				self.firmware_ready.set(true);
				self.fill_progress();
				ui::set_text(
					controls.firmware_status,
					&format!("Firmware downloaded to {}.", dir.display()),
				);
			}
			Err(err) => {
				ui::set_text(controls.firmware_status, "The firmware was not downloaded.");
				self.show_log_window();
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not download the firmware:\r\n\r\n{err}"),
				);
			}
		}

		self.show_page(Page::Firmware);
		self.complete(hwnd);
	}

	fn go_next(&self, hwnd: HWND) {
		match self.page.get() {
			Page::Welcome => {
				self.show_page(Page::Select);
				self.refresh_devices(hwnd);
				if let Some(controls) = self.controls() {
					ui::enable(controls.next, ui::list_selection(controls.list).is_some());
				}
			}
			Page::Select => {
				let Some(device) = self.selected_device() else {
					return;
				};

				self.show_result(&device);

				if self.verdict_ok.get() {
					self.show_keys();
					self.show_page(Page::Keys);
				} else {
					self.show_page(Page::Result);
				}
			}
			Page::Result | Page::Install => {
				if self.verdict_ok.get() {
					self.show_keys();
					self.show_page(Page::Keys);
				} else if self.page.get() == Page::Result {
					self.show_install();
					self.show_page(Page::Install);
				} else {
					self.run_install(hwnd);
				}
			}
			Page::Firmware => {
				if self.firmware_ready.get() {
					self.start_adapter();
					self.show_log_window();
					let _ = unsafe { DestroyWindow(hwnd) };
				} else {
					self.start_download(hwnd);
				}
			}
			Page::Keys => {
				if !self.keys_ok.get() {
					return;
				}

				self.start_lkl(hwnd);
				self.show_firmware();
				self.show_page(Page::Firmware);
				self.complete(hwnd);
			}
		}
	}

	fn go_back(&self) {
		match self.page.get() {
			Page::Welcome => {}
			Page::Select => self.show_page(Page::Welcome),
			Page::Result | Page::Keys => self.show_page(Page::Select),
			Page::Install => self.show_page(Page::Result),
			Page::Firmware => self.show_page(Page::Keys),
		}
	}

	fn on_command(&self, hwnd: HWND, id: i32) {
		match id {
			ID_NEXT => self.go_next(hwnd),
			ID_BACK => self.go_back(),
			ID_REFRESH => self.refresh_devices(hwnd),
			ID_BROWSE => self.browse_keys(hwnd),
			ID_SHOW_ALL => {
				self.show_all.set(!self.show_all.get());
				self.refresh_devices(hwnd);
			}
			ID_CANCEL | IDCANCEL_ID => self.cancel(),
			_ => {}
		}
	}

	fn on_notify(&self, hwnd: HWND, header: &NMHDR) {
		if usize::try_from(ID_LIST).ok() != Some(header.idFrom) {
			return;
		}

		match header.code {
			LVN_ITEMCHANGED => {
				if let Some(controls) = self.controls()
					&& self.page.get() == Page::Select
				{
					ui::enable(controls.next, ui::list_selection(controls.list).is_some());
				}
			}
			NM_DBLCLK if self.page.get() == Page::Select => {
				self.go_next(hwnd);
			}
			_ => {}
		}
	}

	fn apply_theme(&self, hwnd: HWND) {
		let palette = self.theme.palette();

		theme::apply_window(hwnd, palette.dark);

		if let Some(controls) = self.controls() {
			for control in controls.all() {
				theme::apply_control_with(control, palette);
			}

			theme::apply_listview(controls.list, palette);
		}

		theme::repaint(hwnd);
	}

	fn on_setting_change(&self, hwnd: HWND, lparam: LPARAM) {
		if theme::is_colour_setting_change(lparam) && self.theme.reread() {
			self.apply_theme(hwnd);
		}
	}

	fn on_ctl_color_static(&self, hdc: HDC, control: HWND) -> LRESULT {
		let palette = self.theme.palette();

		let Some(controls) = self.controls() else {
			return theme::ctl_colour(hdc, palette.text, palette);
		};

		if control == controls.header_rule || control == controls.footer_rule {
			return theme::ctl_colour_rule(palette);
		}

		// Read only, so it sends WM_CTLCOLORSTATIC like a label and has to be
		// told apart by handle to get the colours of the field it looks like.
		if control == controls.keys_path {
			return theme::ctl_colour_field(hdc, palette);
		}

		let text = if control == controls.verdict {
			if self.verdict_ok.get() {
				palette.good
			} else {
				palette.bad
			}
		} else {
			palette.text
		};

		theme::ctl_colour(hdc, text, palette)
	}
}

const IDCANCEL_ID: i32 = IDCANCEL.0;
const CLASS_NAME: PCWSTR = w!("LdnrsWizard");

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
		return Err(windows::core::Error::from_thread().into());
	}

	Ok(())
}

/// Opens the dialog centred on screen. The window only borrows `wizard`, which
/// outlives it.
pub fn open(wizard: &Wizard) -> anyhow::Result<HWND> {
	let instance = HINSTANCE(unsafe { GetModuleHandleW(None) }?.0);
	register(instance)?;

	let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;

	let mut rect = RECT {
		left: 0,
		top: 0,
		right: CLIENT_WIDTH,
		bottom: CLIENT_HEIGHT,
	};
	unsafe { AdjustWindowRectEx(&raw mut rect, style, false, WINDOW_EX_STYLE::default()) }?;

	let width = rect.right.saturating_sub(rect.left);
	let height = rect.bottom.saturating_sub(rect.top);
	let x = unsafe { GetSystemMetrics(SM_CXSCREEN) }.saturating_sub(width) / 2;
	let y = unsafe { GetSystemMetrics(SM_CYSCREEN) }.saturating_sub(height) / 2;

	let hwnd = unsafe {
		CreateWindowExW(
			WINDOW_EX_STYLE::default(),
			CLASS_NAME,
			w!("Nintendo networking tool"),
			style,
			x,
			y,
			width,
			height,
			None,
			None,
			Some(instance),
			Some(std::ptr::from_ref(wizard).cast()),
		)
	}?;

	unsafe {
		let _ = ShowWindow(hwnd, SW_SHOW);
		let _ = UpdateWindow(hwnd);
	}

	Ok(hwnd)
}

pub unsafe extern "system" fn wndproc(
	hwnd: HWND,
	msg: u32,
	wparam: WPARAM,
	lparam: LPARAM,
) -> LRESULT {
	if msg == WM_NCCREATE {
		let create = ui::ptr_from_int::<CREATESTRUCTW>(lparam.0);
		let wizard = unsafe { (*create).lpCreateParams }.cast::<Wizard>();
		unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, ui::int_from_ptr(wizard)) };
		return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
	}

	let ptr = ui::ptr_from_int::<Wizard>(unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) });
	let Some(wizard) = (unsafe { ptr.as_ref() }) else {
		return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
	};

	match msg {
		WM_CREATE => {
			if let Err(err) = wizard.create_controls(hwnd) {
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not create the window:\r\n\r\n{err:#}"),
				);
				return LRESULT(-1);
			}

			wizard.dialog.set(Some(hwnd));
			wizard.window_opened();
			wizard.apply_theme(hwnd);
			wizard.layout(hwnd);
			LRESULT(0)
		}

		WM_SIZE => {
			wizard.layout(hwnd);
			LRESULT(0)
		}

		WM_COMMAND => {
			wizard.on_command(hwnd, ui::command_id(wparam));
			LRESULT(0)
		}

		WM_NOTIFY => {
			let header = ui::ptr_from_int::<NMHDR>(lparam.0);
			if let Some(header) = unsafe { header.as_ref() } {
				wizard.on_notify(hwnd, header);
			}
			LRESULT(0)
		}

		WM_DAEMON_STATUS => {
			let status = ui::ptr_from_int::<daemon::Status>(lparam.0);
			if !status.is_null() {
				let status = *unsafe { Box::from_raw(status) };
				wizard.on_daemon_status(hwnd, status);
			}
			LRESULT(0)
		}

		WM_FIRMWARE_PROGRESS => {
			wizard.on_firmware_progress(wparam.0, lparam.0.cast_unsigned());
			LRESULT(0)
		}

		WM_FIRMWARE_DONE => {
			let outcome = ui::ptr_from_int::<firmware::Outcome>(lparam.0);
			if !outcome.is_null() {
				let outcome = *unsafe { Box::from_raw(outcome) };
				wizard.on_firmware_done(hwnd, outcome);
			}
			LRESULT(0)
		}

		WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => wizard.on_ctl_color_static(
			HDC(std::ptr::with_exposed_provenance_mut(wparam.0)),
			HWND(ui::ptr_from_int(lparam.0)),
		),

		WM_ERASEBKGND => theme::erase_background(
			hwnd,
			HDC(std::ptr::with_exposed_provenance_mut(wparam.0)),
			wizard.theme.palette(),
		),

		WM_SETTINGCHANGE => {
			wizard.on_setting_change(hwnd, lparam);
			unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
		}

		WM_CLOSE => {
			wizard.cancel();
			LRESULT(0)
		}

		WM_DESTROY => {
			wizard.dialog.set(None);
			*wizard.controls.borrow_mut() = None;
			wizard.window_closed();
			LRESULT(0)
		}

		_ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
	}
}

#[cfg(test)]
mod tests {
	use super::hint;

	#[test]
	fn the_hint_always_says_how_many_are_hidden() {
		assert_eq!(hint(1, 12), "Showing 1 of 12 devices; 11 hidden.");

		assert_eq!(hint(12, 12), "Showing all 12 devices.");
	}

	#[test]
	fn an_empty_list_says_which_kind_of_empty_it_is() {
		assert_eq!(
			hint(0, 12),
			"No likely adapters. Show all devices to see the other 12."
		);

		assert_eq!(hint(0, 0), "No USB devices found.");
	}
}
