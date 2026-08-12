//! The wizard window: pick a USB device, report whether Windows has bound the
//! WinUSB driver to it (which is what `ldn` needs to open the device), and offer
//! to install WinUSB when it has not.

use std::cell::{Cell, OnceCell, RefCell};
use std::ffi::c_void;

use ldn::winusb::{self, UsbDevice};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
	COLOR_WINDOW, COLOR_WINDOWTEXT, GetSysColor, GetSysColorBrush, HDC, SetBkColor, SetTextColor,
};
use windows::Win32::System::SystemServices::{SS_ETCHEDHORZ, SS_LEFT};
use windows::Win32::UI::Controls::{
	LVM_SETEXTENDEDLISTVIEWSTYLE, LVN_ITEMCHANGED, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT,
	LVS_NOSORTHEADER, LVS_REPORT, LVS_SHOWSELALWAYS, LVS_SINGLESEL, NM_DBLCLK, NMHDR, PBM_SETPOS,
	PBM_SETRANGE32, PBS_SMOOTH, PROGRESS_CLASSW, WC_LISTVIEWW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
use windows::Win32::UI::WindowsAndMessaging::{
	BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CREATESTRUCTW, DefWindowProcW, DestroyWindow, GWLP_USERDATA,
	GetClientRect, GetWindowLongPtrW, IDCANCEL, MoveWindow, PostQuitMessage, SendMessageW,
	SetWindowLongPtrW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND, WM_CREATE, WM_CTLCOLORSTATIC,
	WM_DESTROY, WM_NCCREATE, WM_NOTIFY, WM_SIZE, WS_BORDER, WS_CHILD, WS_GROUP, WS_TABSTOP,
	WS_VISIBLE,
};
use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONWARNING, MB_YESNO};
use windows::core::w;

use crate::app::App;
use crate::firmware::{self, WM_FIRMWARE_DONE, WM_FIRMWARE_PROGRESS};
use crate::install;
use crate::ui::{self, Fonts};

const ID_BACK: i32 = 101;
const ID_NEXT: i32 = 102;
const ID_CANCEL: i32 = 103;
const ID_REFRESH: i32 = 104;
const ID_LIST: i32 = 105;

pub const CLIENT_WIDTH: i32 = 660;
pub const CLIENT_HEIGHT: i32 = 470;

const MARGIN: i32 = 20;
const HEADER_HEIGHT: i32 = 74;
const FOOTER_HEIGHT: i32 = 52;
const BUTTON_WIDTH: i32 = 104;
const BUTTON_HEIGHT: i32 = 26;

const WINUSB_SERVICE: &str = "winusb";

const GREEN: COLORREF = COLORREF(0x0020_7000);
const RED: COLORREF = COLORREF(0x0020_20c0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
	Welcome,
	Select,
	Result,
	Install,
	Firmware,
}

struct Controls {
	title: HWND,
	subtitle: HWND,
	header_rule: HWND,
	footer_rule: HWND,

	welcome_text: HWND,

	list: HWND,
	refresh: HWND,
	list_hint: HWND,

	verdict: HWND,
	details: HWND,
	advice: HWND,

	install_intro: HWND,
	install_status: HWND,

	firmware_intro: HWND,
	firmware_status: HWND,
	firmware_progress: HWND,

	back: HWND,
	next: HWND,
	cancel: HWND,
}

pub struct Wizard {
	fonts: Fonts,
	controls: OnceCell<Controls>,
	app: App,
	page: Cell<Page>,
	devices: RefCell<Vec<UsbDevice>>,
	selected: RefCell<Option<UsbDevice>>,
	verdict_ok: Cell<bool>,
	downloading: Cell<bool>,
	firmware_ready: Cell<bool>,
	firmware_total: Cell<usize>,
	progress_shown: Cell<bool>,
}

#[must_use]
fn is_winusb(device: &UsbDevice) -> bool {
	device.driver.eq_ignore_ascii_case(WINUSB_SERVICE)
}

impl Wizard {
	#[must_use]
	pub fn new(app: App) -> Self {
		Self {
			fonts: Fonts::new(),
			controls: OnceCell::new(),
			app,
			page: Cell::new(Page::Welcome),
			devices: RefCell::new(Vec::new()),
			selected: RefCell::new(None),
			verdict_ok: Cell::new(false),
			downloading: Cell::new(false),
			firmware_ready: Cell::new(false),
			firmware_total: Cell::new(1),
			progress_shown: Cell::new(false),
		}
	}

	fn create_controls(&self, hwnd: HWND) -> anyhow::Result<()> {
		let child = WS_CHILD | WS_VISIBLE;
		let label = WINDOW_STYLE(child.0 | SS_LEFT.0);
		let hidden_label = WINDOW_STYLE(WS_CHILD.0 | SS_LEFT.0);
		let button = WINDOW_STYLE(child.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32);

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

		let controls = Controls {
			title: text("", label, self.fonts.heading)?,
			subtitle: text("", label, self.fonts.ui)?,
			header_rule: text("", WINDOW_STYLE(child.0 | SS_ETCHEDHORZ.0), self.fonts.ui)?,
			footer_rule: text("", WINDOW_STYLE(child.0 | SS_ETCHEDHORZ.0), self.fonts.ui)?,

			welcome_text: text(WELCOME_BODY, label, self.fonts.ui)?,

			list: ui::create_control(
				hwnd,
				WC_LISTVIEWW,
				"",
				WINDOW_STYLE(
					WS_CHILD.0
						| WS_TABSTOP.0 | WS_BORDER.0
						| LVS_REPORT | LVS_SINGLESEL
						| LVS_SHOWSELALWAYS
						| LVS_NOSORTHEADER,
				),
				WINDOW_EX_STYLE::default(),
				ID_LIST,
				self.fonts.ui,
			)?,
			refresh: ui::create_control(
				hwnd,
				w!("BUTTON"),
				"&Refresh",
				WINDOW_STYLE(WS_CHILD.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32),
				WINDOW_EX_STYLE::default(),
				ID_REFRESH,
				self.fonts.ui,
			)?,
			list_hint: text(LIST_HINT, hidden_label, self.fonts.ui)?,

			verdict: text("", hidden_label, self.fonts.heading)?,
			details: text("", hidden_label, self.fonts.ui)?,
			advice: text("", hidden_label, self.fonts.ui)?,

			install_intro: text("", hidden_label, self.fonts.ui)?,
			install_status: text("", hidden_label, self.fonts.ui)?,

			firmware_intro: text("", hidden_label, self.fonts.ui)?,
			firmware_status: text("", hidden_label, self.fonts.ui)?,
			firmware_progress: ui::create_control(
				hwnd,
				PROGRESS_CLASSW,
				"",
				WINDOW_STYLE(WS_CHILD.0 | PBS_SMOOTH),
				WINDOW_EX_STYLE::default(),
				0,
				self.fonts.ui,
			)?,

			back: ui::create_control(
				hwnd,
				w!("BUTTON"),
				"< &Back",
				WINDOW_STYLE(button.0 | WS_GROUP.0),
				WINDOW_EX_STYLE::default(),
				ID_BACK,
				self.fonts.ui,
			)?,
			next: ui::create_control(
				hwnd,
				w!("BUTTON"),
				"&Next >",
				WINDOW_STYLE(child.0 | WS_TABSTOP.0 | BS_DEFPUSHBUTTON as u32),
				WINDOW_EX_STYLE::default(),
				ID_NEXT,
				self.fonts.ui,
			)?,
			cancel: ui::create_control(
				hwnd,
				w!("BUTTON"),
				"Cancel",
				button,
				WINDOW_EX_STYLE::default(),
				ID_CANCEL,
				self.fonts.ui,
			)?,
		};

		unsafe {
			SendMessageW(
				controls.list,
				LVM_SETEXTENDEDLISTVIEWSTYLE,
				None,
				Some(LPARAM(
					(LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize,
				)),
			)
		};

		ui::list_add_column(controls.list, 0, "Device", 268);
		ui::list_add_column(controls.list, 1, "VID:PID", 84);
		ui::list_add_column(controls.list, 2, "Driver", 130);
		ui::list_add_column(controls.list, 3, "WinUSB", 70);

		if self.controls.set(controls).is_err() {
			anyhow::bail!("controls already created");
		}

		self.show_page(Page::Welcome);

		Ok(())
	}

	fn controls(&self) -> Option<&Controls> {
		self.controls.get()
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
		let content_width = width.saturating_sub(MARGIN.saturating_mul(2));

		let place = |control: HWND, x: i32, y: i32, w: i32, h: i32| {
			let _ = unsafe { MoveWindow(control, x, y, w, h, true) };
		};

		place(controls.title, MARGIN, 16, content_width, 26);
		place(controls.subtitle, MARGIN, 44, content_width, 20);
		place(controls.header_rule, 0, HEADER_HEIGHT, width, 2);

		let body_top = HEADER_HEIGHT.saturating_add(MARGIN);
		let footer_top = height.saturating_sub(FOOTER_HEIGHT);
		let body_height = footer_top.saturating_sub(body_top).saturating_sub(MARGIN);

		place(
			controls.welcome_text,
			MARGIN,
			body_top,
			content_width,
			body_height,
		);

		let list_height = body_height
			.saturating_sub(BUTTON_HEIGHT)
			.saturating_sub(MARGIN.saturating_mul(2));
		place(controls.list, MARGIN, body_top, content_width, list_height);
		place(
			controls.refresh,
			MARGIN,
			body_top
				.saturating_add(list_height)
				.saturating_add(MARGIN.saturating_div(2)),
			BUTTON_WIDTH,
			BUTTON_HEIGHT,
		);
		place(
			controls.list_hint,
			MARGIN.saturating_add(BUTTON_WIDTH).saturating_add(12),
			body_top
				.saturating_add(list_height)
				.saturating_add(MARGIN.saturating_div(2))
				.saturating_add(5),
			content_width
				.saturating_sub(BUTTON_WIDTH)
				.saturating_sub(12),
			40,
		);

		place(controls.verdict, MARGIN, body_top, content_width, 28);
		place(
			controls.details,
			MARGIN,
			body_top.saturating_add(44),
			content_width,
			104,
		);
		place(
			controls.advice,
			MARGIN,
			body_top.saturating_add(160),
			content_width,
			body_height.saturating_sub(160),
		);

		place(
			controls.install_intro,
			MARGIN,
			body_top,
			content_width,
			body_height.saturating_sub(60),
		);
		place(
			controls.install_status,
			MARGIN,
			body_top.saturating_add(body_height).saturating_sub(56),
			content_width,
			56,
		);

		place(
			controls.firmware_intro,
			MARGIN,
			body_top,
			content_width,
			body_height.saturating_sub(90),
		);
		place(
			controls.firmware_progress,
			MARGIN,
			body_top.saturating_add(body_height).saturating_sub(80),
			content_width,
			18,
		);
		place(
			controls.firmware_status,
			MARGIN,
			body_top.saturating_add(body_height).saturating_sub(54),
			content_width,
			54,
		);

		place(controls.footer_rule, 0, footer_top, width, 2);

		let button_y = footer_top.saturating_add(14);
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

		ui::show(controls.welcome_text, welcome);

		ui::show(controls.list, select);
		ui::show(controls.refresh, select);
		ui::show(controls.list_hint, select);

		ui::show(controls.verdict, result);
		ui::show(controls.details, result);
		ui::show(controls.advice, result);

		ui::show(controls.install_intro, install);
		ui::show(controls.install_status, install);

		let firmware = page == Page::Firmware;
		ui::show(controls.firmware_intro, firmware);
		ui::show(controls.firmware_status, firmware);
		ui::show(
			controls.firmware_progress,
			firmware && self.progress_shown.get(),
		);

		match page {
			Page::Welcome => {
				ui::set_text(controls.title, "Set up a device for ldnrs");
				ui::set_text(
					controls.subtitle,
					"Check that your USB adapter is bound to the WinUSB driver.",
				);
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
				ui::set_text(
					controls.subtitle,
					"This is the kernel driver Windows has bound to the device.",
				);
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
				let idle = !self.downloading.get();
				ui::enable(controls.back, idle);
				ui::enable(controls.next, idle);
			}
		}
	}

	fn refresh_devices(&self, hwnd: HWND) {
		let Some(controls) = self.controls() else {
			return;
		};

		let devices = match winusb::get_devices() {
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

		let selected = ui::list_selection(controls.list)
			.and_then(|index| self.devices.borrow().get(index).cloned());

		ui::list_clear(controls.list);

		for (index, device) in devices.iter().enumerate() {
			let vidpid = format!("{:04x}:{:04x}", device.vid, device.pid);
			let winusb = if is_winusb(device) { "Yes" } else { "No" };

			ui::list_add_row(
				controls.list,
				index as i32,
				&[&device.name, &vidpid, &device.driver, winusb],
			);
		}

		let reselect = selected.and_then(|previous| {
			devices
				.iter()
				.position(|device| device.path == previous.path)
		});

		*self.devices.borrow_mut() = devices;

		if let Some(index) = reselect {
			ui::list_select(controls.list, index);
		}

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

		ui::set_text(
			controls.advice,
			&if ok {
				format!(
					"ldnrs can open this device. Start the daemon with:\r\n\r\n    \
					 ldnd --usb {:04x}:{:04x} --socket \\\\.\\pipe\\ldnrs",
					device.vid, device.pid
				)
			} else {
				format!(
					"ldnrs talks to the adapter through WinUSB, so it cannot open this device \
					 while \"{}\" is bound to it.\r\n\r\nClick Install WinUSB and the wizard \
					 will bind WinUSB to it for you; a tool such as Zadig does the same \
					 job.",
					device.driver
				)
			},
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
				 using the current driver for this device.",
				device.name, device.vid, device.pid, device.driver
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

		unsafe {
			SendMessageW(
				controls.firmware_progress,
				PBM_SETRANGE32,
				Some(WPARAM(0)),
				Some(LPARAM(total as isize)),
			);
			SendMessageW(
				controls.firmware_progress,
				PBM_SETPOS,
				Some(WPARAM(done as usize)),
				None,
			);
		};
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
				ui::error_box(
					Some(hwnd),
					"ldnrs",
					&format!("Could not download the firmware:\r\n\r\n{err}"),
				);
			}
		}

		self.show_page(Page::Firmware);
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
				self.show_page(Page::Result);
			}
			Page::Result | Page::Install => {
				if self.verdict_ok.get() {
					self.show_firmware();
					self.show_page(Page::Firmware);
				} else if self.page.get() == Page::Result {
					self.show_install();
					self.show_page(Page::Install);
				} else {
					self.run_install(hwnd);
				}
			}
			Page::Firmware => {
				if self.firmware_ready.get() {
					let _ = unsafe { DestroyWindow(hwnd) };
				} else {
					self.start_download(hwnd);
				}
			}
		}
	}

	fn go_back(&self) {
		match self.page.get() {
			Page::Welcome => {}
			Page::Select => self.show_page(Page::Welcome),
			Page::Result => self.show_page(Page::Select),
			Page::Install => self.show_page(Page::Result),
			Page::Firmware => {
				self.show_page(Page::Result);
			}
		}
	}

	fn on_command(&self, hwnd: HWND, id: i32) {
		match id {
			ID_NEXT => self.go_next(hwnd),
			ID_BACK => self.go_back(),
			ID_REFRESH => self.refresh_devices(hwnd),
			ID_CANCEL | IDCANCEL_ID => {
				let _ = unsafe { DestroyWindow(hwnd) };
			}
			_ => {}
		}
	}

	fn on_notify(&self, hwnd: HWND, header: &NMHDR) {
		if header.idFrom != ID_LIST as usize {
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
			NM_DBLCLK => {
				if self.page.get() == Page::Select {
					self.go_next(hwnd);
				}
			}
			_ => {}
		}
	}

	fn on_ctl_color_static(&self, hdc: HDC, control: HWND) -> LRESULT {
		let color = if self.controls().is_some_and(|c| c.verdict == control) {
			if self.verdict_ok.get() { GREEN } else { RED }
		} else {
			COLORREF(unsafe { GetSysColor(COLOR_WINDOWTEXT) })
		};

		unsafe {
			SetTextColor(hdc, color);
			SetBkColor(hdc, COLORREF(GetSysColor(COLOR_WINDOW)));
		}

		LRESULT(unsafe { GetSysColorBrush(COLOR_WINDOW) }.0 as isize)
	}
}

const IDCANCEL_ID: i32 = IDCANCEL.0;

pub unsafe extern "system" fn wndproc(
	hwnd: HWND,
	msg: u32,
	wparam: WPARAM,
	lparam: LPARAM,
) -> LRESULT {
	if msg == WM_NCCREATE {
		let create = lparam.0 as *const CREATESTRUCTW;
		let wizard = unsafe { (*create).lpCreateParams }.cast::<Wizard>();
		unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, wizard as isize) };
		return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
	}

	let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const Wizard;
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

			wizard.layout(hwnd);
			LRESULT(0)
		}

		WM_SIZE => {
			wizard.layout(hwnd);
			LRESULT(0)
		}

		WM_COMMAND => {
			wizard.on_command(hwnd, (wparam.0 & 0xffff) as i32);
			LRESULT(0)
		}

		WM_NOTIFY => {
			let header = lparam.0 as *const NMHDR;
			if let Some(header) = unsafe { header.as_ref() } {
				wizard.on_notify(hwnd, header);
			}
			LRESULT(0)
		}

		WM_FIRMWARE_PROGRESS => {
			wizard.on_firmware_progress(wparam.0, lparam.0 as usize);
			LRESULT(0)
		}

		WM_FIRMWARE_DONE => {
			let outcome = lparam.0 as *mut firmware::Outcome;
			if !outcome.is_null() {
				let outcome = *unsafe { Box::from_raw(outcome) };
				wizard.on_firmware_done(hwnd, outcome);
			}
			LRESULT(0)
		}

		WM_CTLCOLORSTATIC => {
			wizard.on_ctl_color_static(HDC(wparam.0 as *mut c_void), HWND(lparam.0 as *mut c_void))
		}

		WM_DESTROY => {
			unsafe { PostQuitMessage(0) };
			LRESULT(0)
		}

		_ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
	}
}

const WELCOME_BODY: &str = "ldnrs drives your USB Wi-Fi adapter through WinUSB, so Windows has to \
have the WinUSB driver bound to the device instead of a vendor driver.\r\n\r\nThis wizard lists \
the USB devices attached to this PC and tells you which kernel driver each one is using, so you \
can confirm the adapter is ready before starting the daemon.\r\n\r\nNothing on your system is \
changed: the device list is only read.\r\n\r\nClick Next to continue.";

const LIST_HINT: &str = "Plugged something in? Click Refresh to enumerate again.";
