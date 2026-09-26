use core::slice;
use std::{
	ffi::{CStr, CString, c_void},
	ops::Deref,
	path::PathBuf,
	ptr::null_mut,
	sync::{Arc, OnceLock},
	time::{Duration, Instant},
};

use ::windows::{
	Win32::{
		Devices::Usb::{
			AUTO_CLEAR_STALL, PIPE_TRANSFER_TIMEOUT, USB_DEVICE_DESCRIPTOR_TYPE,
			USB_INTERFACE_DESCRIPTOR, WINUSB_INTERFACE_HANDLE, WINUSB_PIPE_INFORMATION,
			WINUSB_SETUP_PACKET, WinUsb_ControlTransfer, WinUsb_Free, WinUsb_GetDescriptor,
			WinUsb_Initialize, WinUsb_QueryInterfaceSettings, WinUsb_QueryPipe,
			WinUsb_SetPipePolicy,
		},
		Foundation::{GENERIC_READ, GENERIC_WRITE},
		Storage::FileSystem::{
			CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
			FILE_SHARE_WRITE, OPEN_EXISTING,
		},
		System::IO::CreateIoCompletionPort,
	},
	core::{Owned, PCSTR},
};
use windows::Win32::Devices::Usb::USB_DEVICE_DESCRIPTOR;

use crate::{
	generated::{ldn_lkl_find_driver, ldn_lkl_init},
	winusb::UsbDevice,
};

use crate::generated::{ldn_lkl_usb_attach, ldn_lkl_usb_completion_irq, ldn_lkl_usb_detach};
use crate::logs::{LogBroadcast, LogReceiver};
use crate::usb::{BridgeHandle, UsbBridge, run_completion_pump};

pub mod accesspoint;
pub mod advertisement;
pub mod authentication;
pub mod broadcast;
pub mod channel;
pub mod crypto;
#[allow(
	non_snake_case,
	non_camel_case_types,
	non_upper_case_globals,
	dead_code,
	unused_variables,
	unused_braces,
	clippy::all,
	clippy::pedantic,
	clippy::nursery,
	clippy::indexing_slicing,
	clippy::arithmetic_side_effects
)]
mod generated {
	include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
pub mod iface;
pub mod logs;
pub mod monitor;
pub mod network;
pub mod protocol;
pub mod radio;
pub mod scan;
pub mod station;
pub mod sys;
pub mod usb;
pub mod winusb;
pub mod wireless;
pub mod wlan;

#[derive(Debug, Clone)]
pub struct FirmwareProgress {
	pub done: usize,
	pub total: usize,
	pub file: &'static str,
}

pub type FirmwareProgressFn = Arc<dyn Fn(FirmwareProgress) + Send + Sync>;
pub type FirmwareFetchFn = Arc<dyn Fn(&str) -> anyhow::Result<Vec<u8>> + Send + Sync>;

/// # Errors
/// If there is no home directory.
pub fn firmware_dir() -> anyhow::Result<PathBuf> {
	let home_dir = std::env::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir :("))?;
	Ok(home_dir.join(".nintendo-local-networking").join("firmware"))
}

struct OwnedWinUsb {
	interface: WINUSB_INTERFACE_HANDLE,
}

impl OwnedWinUsb {
	pub const fn new(interface: WINUSB_INTERFACE_HANDLE) -> Self {
		Self { interface }
	}
}

impl Deref for OwnedWinUsb {
	type Target = WINUSB_INTERFACE_HANDLE;

	fn deref(&self) -> &Self::Target {
		&self.interface
	}
}

impl Drop for OwnedWinUsb {
	fn drop(&mut self) {
		let _ = unsafe { WinUsb_Free(self.interface) };
	}
}

struct LklInner {
	device: OnceLock<UsbDevice>,
	lkl_ctx: OnceLock<*mut c_void>,
	logs: LogBroadcast,
	usb: OnceLock<*mut UsbBridge>,
	firmware_fetch: OnceLock<FirmwareFetchFn>,
}

unsafe impl Send for LklInner {}
unsafe impl Sync for LklInner {}

const DEFAULT_KARGS: &str = "mem=128M mac80211_hwsim.radios=0 rtw88_usb.switch_usb_mode=0";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelOptions {
	pub extra: Option<String>,
}

impl KernelOptions {
	#[must_use]
	pub fn cmdline(&self) -> String {
		self.extra.as_ref().map_or_else(
			|| DEFAULT_KARGS.to_string(),
			|v| format!("{DEFAULT_KARGS} {v}"),
		)
	}
}

#[derive(Clone)]
pub struct Lkl {
	inner: Arc<LklInner>,
}

impl Default for Lkl {
	fn default() -> Self {
		Self::new()
	}
}

impl Lkl {
	#[must_use]
	pub fn new() -> Self {
		Self {
			inner: Arc::new(LklInner {
				device: OnceLock::new(),
				lkl_ctx: OnceLock::new(),
				logs: LogBroadcast::default(),
				usb: OnceLock::new(),
				firmware_fetch: OnceLock::new(),
			}),
		}
	}

	/// # Errors
	/// If the kernel has not been initialized.
	pub fn get_fw_list(&self, device: &UsbDevice) -> anyhow::Result<Vec<&'static str>> {
		let ctx = *self
			.inner
			.lkl_ctx
			.get()
			.ok_or_else(|| anyhow::anyhow!("the kernel is not running; call init first"))?;

		let mut v = Vec::<&'static str>::new();
		let v_ptr = &raw mut v;
		unsafe {
			ldn_lkl_find_driver(
				ctx,
				device.vid.into(),
				device.pid.into(),
				Some(firmware_vec_string_add),
				v_ptr.cast::<c_void>(),
			);
		};

		Ok(v)
	}

	/// # Errors
	/// If the kernel is not running or there is no home directory.
	pub fn missing_firmware(&self, device: &UsbDevice) -> anyhow::Result<Vec<&'static str>> {
		let fw_dir = firmware_dir()?;

		Ok(self
			.get_fw_list(device)?
			.into_iter()
			.chain(EXTRA_FIRMWARE)
			.filter(|fw| !fw_dir.join(fw).is_file())
			.collect())
	}

	/// Opens `device` over `WinUSB` and hands it to the kernel's USB host controller.
	///
	/// # Errors
	/// If the device cannot be opened or configured, the kernel is not running, or a device is
	/// already attached.
	pub fn attach(&self, device: UsbDevice) -> anyhow::Result<()> {
		let inner = self.inner.clone();

		if let Ok(round_trip) = control_round_trip(&device.path) {
			inner.logs.send(&describe_round_trip(round_trip));
		}

		let device_path = CString::new(device.path.as_str())?;
		let device_path = PCSTR::from_raw(device_path.as_ptr().cast());

		let handle = unsafe {
			CreateFileA(
				device_path,
				(GENERIC_READ | GENERIC_WRITE).0,
				FILE_SHARE_READ | FILE_SHARE_WRITE,
				None,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
				None,
			)
		}?;

		let iocp = unsafe { CreateIoCompletionPort(handle, None, 0, 0) }?;

		// `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` used to be set here, and it was why register
		// writes timed out: a transfer the USB stack could satisfy immediately queued no
		// completion, so the pump never ran and never raised the interrupt that is the only
		// thing telling the kernel to poll. The transfer had finished; the kernel just had no
		// way to find out, and waited out its own 500ms URB timeout instead. Every completion
		// goes to the port now, fast ones included.

		let mut interface_handle = WINUSB_INTERFACE_HANDLE::default();
		unsafe { WinUsb_Initialize(handle, &raw mut interface_handle) }?;

		let interface_handle = OwnedWinUsb::new(interface_handle);

		let mut interface = USB_INTERFACE_DESCRIPTOR::default();
		unsafe { WinUsb_QueryInterfaceSettings(*interface_handle, 0, &raw mut interface) }?;

		configure_pipes(*interface_handle, &interface)?;

		let superspeed = is_superspeed(*interface_handle);

		let ctx = inner
			.lkl_ctx
			.get()
			.copied()
			.ok_or_else(|| anyhow::anyhow!("the kernel is not running; call init first"))?;
		let ctx = crate::sys::KernelContext::new(ctx);

		let winusb = *interface_handle;
		core::mem::forget(interface_handle);

		let bridge = Box::into_raw(Box::new(UsbBridge::new(handle, winusb, iocp)));

		if inner.usb.set(bridge).is_err() {
			drop(unsafe { Box::from_raw(bridge) });
			anyhow::bail!("a device is already attached")
		}

		let ops = unsafe { &*bridge }.ops(superspeed);

		let ret = unsafe { ldn_lkl_usb_attach(ctx.raw_for_ffi(), &raw const ops) };
		anyhow::ensure!(
			ret >= 0,
			"lkl_usb_attach failed ({ret}); was liblkl built without CONFIG_USB_LKL_HCD?"
		);

		let irq = unsafe { ldn_lkl_usb_completion_irq(ctx.raw_for_ffi()) };
		if irq < 0 {
			println!("ldn: warning: no HCD completion irq ({irq}); transfers will not complete");
		}

		let pump = BridgeHandle::new(bridge);
		std::thread::Builder::new()
			.name("ldn-usb-completions".to_owned())
			.spawn(move || {
				unsafe { run_completion_pump(pump, ctx, irq) };
			})?;

		if inner.device.set(device).is_err() {
			anyhow::bail!("device already set")
		}

		Ok(())
	}
	/// # Errors
	/// As [`Lkl::init_with`].
	pub fn init(&self) -> anyhow::Result<()> {
		self.init_with(&KernelOptions::default())
	}

	/// # Errors
	/// If the command line contains a NUL, the kernel fails to boot, or it is already running.
	pub fn init_with(&self, options: &KernelOptions) -> anyhow::Result<()> {
		let cmdline = CString::new(options.cmdline())
			.map_err(|_| anyhow::anyhow!("the kernel command line contains a NUL"))?;

		let inner = self.inner.clone();
		let userdata = inner.clone();
		let userdata = Arc::into_raw(userdata);

		let mut ctx: *mut c_void = null_mut();
		let ret = unsafe {
			ldn_lkl_init(
				&raw mut ctx,
				userdata.cast_mut().cast::<c_void>(),
				cmdline.as_ptr(),
			)
		};
		if ret != 0 {
			anyhow::bail!("lkl init failed {}", ret);
		}

		if inner.lkl_ctx.set(ctx).is_err() {
			anyhow::bail!("Context already set");
		}

		Ok(())
	}
	/// Registers the fallback used when the kernel requests a firmware file that is not on disk.
	/// Only the first registration takes effect.
	pub fn set_firmware_fetch(&self, fetch: FirmwareFetchFn) {
		let _ = self.inner.firmware_fetch.set(fetch);
	}

	#[must_use]
	pub fn logs(&self) -> LogReceiver {
		self.inner.logs.subscribe()
	}

	#[must_use]
	pub fn is_running(&self) -> bool {
		self.inner.lkl_ctx.get().is_some()
	}

	#[must_use]
	pub fn context(&self) -> Option<crate::sys::KernelContext> {
		self.inner
			.lkl_ctx
			.get()
			.copied()
			.map(crate::sys::KernelContext::new)
	}

	pub fn shutdown(&self) {
		if let Some(bridge) = self.inner.usb.get().copied() {
			// Detach first, and only then stop the pump. Detaching runs the driver's disconnect
			// path, which powers the chip down over the control endpoint -- and those transfers
			// only finish because the pump is still turning completions into interrupts. Stopping
			// it first leaves the teardown half done and the adapter still powered and running its
			// firmware, which the next run cannot probe: it comes back as `failed to validate
			// firmware` and a device that needs replugging.
			if let Some(ctx) = self.inner.lkl_ctx.get().copied() {
				let _ = unsafe { ldn_lkl_usb_detach(ctx) };
			}

			unsafe { &*bridge }.stop_pump();
		}
	}
}

fn configure_pipes(
	winusb: WINUSB_INTERFACE_HANDLE,
	interface: &USB_INTERFACE_DESCRIPTOR,
) -> anyhow::Result<()> {
	const OUT_TIMEOUT_MS: u32 = 1000;
	const NO_TIMEOUT: u32 = 0;
	const YES: u8 = 1;

	unsafe {
		WinUsb_SetPipePolicy(
			winusb,
			0,
			PIPE_TRANSFER_TIMEOUT,
			u32::try_from(size_of::<u32>())?,
			std::ptr::from_ref(&OUT_TIMEOUT_MS).cast(),
		)
	}?;

	for index in 0..interface.bNumEndpoints {
		let mut pipe_info = WINUSB_PIPE_INFORMATION::default();
		if unsafe { WinUsb_QueryPipe(winusb, 0, index, &raw mut pipe_info) }.is_err() {
			continue;
		}

		let timeout = if pipe_info.PipeId & 0x80 == 0 {
			OUT_TIMEOUT_MS
		} else {
			NO_TIMEOUT
		};

		unsafe {
			WinUsb_SetPipePolicy(
				winusb,
				pipe_info.PipeId,
				PIPE_TRANSFER_TIMEOUT,
				u32::try_from(size_of::<u32>())?,
				std::ptr::from_ref(&timeout).cast(),
			)
		}?;

		unsafe {
			WinUsb_SetPipePolicy(
				winusb,
				pipe_info.PipeId,
				AUTO_CLEAR_STALL,
				u32::try_from(size_of::<u8>())?,
				std::ptr::from_ref(&YES).cast(),
			)
		}?;
	}

	Ok(())
}

fn is_superspeed(winusb: WINUSB_INTERFACE_HANDLE) -> bool {
	let mut descriptor = USB_DEVICE_DESCRIPTOR::default();
	let mut got = 0u32;
	let Ok(kind) = u8::try_from(USB_DEVICE_DESCRIPTOR_TYPE) else {
		return false;
	};

	unsafe {
		WinUsb_GetDescriptor(
			winusb,
			kind,
			0,
			0,
			Some(std::slice::from_raw_parts_mut(
				(&raw mut descriptor).cast(),
				size_of::<USB_DEVICE_DESCRIPTOR>(),
			)),
			&raw mut got,
		)
	}
	.is_ok()
		&& descriptor.bcdUSB >= 0x0300
}

const GET_STATUS: WINUSB_SETUP_PACKET = WINUSB_SETUP_PACKET {
	RequestType: 0x80,
	Request: 0x00,
	Value: 0,
	Index: 0,
	Length: 2,
};

const ROUND_TRIP_SAMPLES: usize = 16;
const SLOW_ROUND_TRIP: Duration = Duration::from_millis(1);

fn control_round_trip(path: &str) -> anyhow::Result<Duration> {
	let path = CString::new(path)?;

	let file = unsafe {
		Owned::new(CreateFileA(
			PCSTR::from_raw(path.as_ptr().cast()),
			(GENERIC_READ | GENERIC_WRITE).0,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			None,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			None,
		)?)
	};

	let mut interface = WINUSB_INTERFACE_HANDLE::default();
	unsafe { WinUsb_Initialize(*file, &raw mut interface) }?;

	let interface = OwnedWinUsb::new(interface);

	let mut status = [0u8; 2];
	let mut transferred = 0u32;
	let mut samples = Vec::with_capacity(ROUND_TRIP_SAMPLES);

	for _ in 0..ROUND_TRIP_SAMPLES {
		let started = Instant::now();

		unsafe {
			WinUsb_ControlTransfer(
				*interface,
				GET_STATUS,
				Some(&mut status),
				Some(&raw mut transferred),
				None,
			)
		}?;

		samples.push(started.elapsed());
	}

	samples.sort_unstable();

	samples
		.get(samples.len() / 2)
		.copied()
		.ok_or_else(|| anyhow::anyhow!("no control transfers were timed"))
}

fn describe_round_trip(round_trip: Duration) -> String {
	let ms = round_trip.as_secs_f64() * 1000.0;

	if round_trip < SLOW_ROUND_TRIP {
		return format!("usb: {ms:.2} ms per control transfer on this port\n");
	}

	format!("usb: WARNING: this port takes {ms:.1} ms per control transfer.\n")
}

/// # Safety
/// `name` must be a NUL-terminated string, `dest` and `size` valid for writes, and `userdata` the
/// `LklInner` pointer the kernel was booted with.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn impl_ldn_lkl_load_firmware(
	name: *const ::std::os::raw::c_char,
	dest: *mut *mut ::std::os::raw::c_void,
	size: *mut ::std::os::raw::c_ulonglong,
	userdata: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
	if name.is_null() || dest.is_null() || size.is_null() {
		return -1;
	}

	let userdata = unsafe { &*userdata.cast::<LklInner>() };
	let Ok(name) = (unsafe { CStr::from_ptr(name) }).to_str() else {
		let () = userdata
			.logs
			.send(&"Unable to convert name to str in ldn_lkl_load_firmware".to_string());
		return -1;
	};

	let Ok(fw_dir) = firmware_dir() else {
		userdata
			.logs
			.send(&"Unable to get fw dir in ldn_lkl_load_firmware".to_string());
		return -1;
	};
	let path = fw_dir.join(name);

	let bytes = if let Ok(bytes) = std::fs::read(&path) {
		bytes
	} else {
		userdata
			.logs
			.send(&format!("WARN: no firmware file: {}, downloading", name));
		let Some(fetch) = userdata.firmware_fetch.get() else {
			return -1;
		};
		let Ok(bytes) = fetch(name) else {
			return -1;
		};

		bytes
	};

	let len = bytes.len();

	// The kernel copies this into its own vmalloc before using it and never hands it back, so
	// there is no one to free it: it is leaked, as the malloc it replaces was.
	let buffer = Box::leak(bytes.into_boxed_slice());

	unsafe {
		*dest = buffer.as_mut_ptr().cast::<c_void>();
		*size = u64::try_from(len).unwrap_or(0);
	}

	println!("firmware: supplied {name} ({len} bytes)");

	0
}

#[unsafe(no_mangle)]
#[allow(clippy::cast_sign_loss, clippy::as_conversions)]
pub extern "C" fn impl_ldn_lkl_print(
	str_: *const ::std::os::raw::c_char,
	len: i32,
	userdata: *mut ::std::os::raw::c_void,
) {
	let userdata = unsafe { &*userdata.cast::<LklInner>() };

	let s = unsafe { slice::from_raw_parts(str_.cast::<std::os::raw::c_uchar>(), len as usize) };
	let s = unsafe { str::from_utf8_unchecked(s) };

	userdata.logs.send(&s.to_owned());
}

#[allow(clippy::all)]
unsafe extern "C" fn firmware_vec_string_add(
	fw: *const ::std::os::raw::c_char,
	userdata: *mut ::std::os::raw::c_void,
) {
	let v = unsafe { &mut *userdata.cast::<Vec<&'static str>>() };

	let s = unsafe { CStr::from_ptr::<'static>(fw) };

	if let Ok(s) = s.to_str() {
		v.push(s);
	}
}

/// Optional firmware files shared by the loader and downloader.
pub const EXTRA_FIRMWARE: [&str; 2] = ["regulatory.db", "regulatory.db.p7s"];
