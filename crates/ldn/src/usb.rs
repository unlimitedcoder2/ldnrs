use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};

use windows::Win32::Devices::Usb::WinUsb_Free;
use windows::Win32::Devices::Usb::{
	WINUSB_INTERFACE_HANDLE, WINUSB_SETUP_PACKET, WinUsb_ControlTransfer,
	WinUsb_GetOverlappedResult, WinUsb_ReadPipe, WinUsb_SetCurrentAlternateSetting,
	WinUsb_WritePipe,
};
use windows::Win32::Foundation::{CloseHandle, ERROR_IO_PENDING, GetLastError, HANDLE};
use windows::Win32::System::IO::{
	CancelIoEx, GetQueuedCompletionStatus, OVERLAPPED, PostQueuedCompletionStatus,
};

use crate::generated::{LdnLklUsbOps, ldn_lkl_trigger_irq};
use crate::sys::KernelContext;

fn tracing() -> bool {
	static ON: OnceLock<bool> = OnceLock::new();

	*ON.get_or_init(|| std::env::var_os("LDN_USB_TRACE").is_some())
}

const TRACE_BYTES: usize = 16;

fn hex(data: &[u8]) -> String {
	use core::fmt::Write as _;

	let shown = data.get(..TRACE_BYTES).unwrap_or(data);

	let mut out = String::with_capacity(shown.len() * 2 + 2);
	for byte in shown {
		let _ = write!(out, "{byte:02x}");
	}

	if data.len() > shown.len() {
		out.push_str("..");
	}

	out
}

fn at() -> u128 {
	static START: OnceLock<std::time::Instant> = OnceLock::new();

	START
		.get_or_init(std::time::Instant::now)
		.elapsed()
		.as_millis()
}

/// `overlapped` **must** stay first: a completion hands back a pointer to it, and the transfer is
/// recovered by casting that pointer back, the equivalent of the C `CONTAINING_RECORD`.
#[repr(C)]
struct Transfer {
	overlapped: OVERLAPPED,
	done: AtomicBool,
	result: AtomicI32,
	submit_failed: AtomicBool,
	traced: AtomicPtr<u8>,
	traced_len: AtomicI32,
}

impl Transfer {
	#[allow(
		clippy::unnecessary_box_returns,
		reason = "the address is the transfer handle"
	)]
	fn new() -> Box<Self> {
		Box::new(Self {
			overlapped: OVERLAPPED::default(),
			done: AtomicBool::new(false),
			result: AtomicI32::new(0),
			submit_failed: AtomicBool::new(false),
			traced: AtomicPtr::new(std::ptr::null_mut()),
			traced_len: AtomicI32::new(0),
		})
	}

	fn trace_buffer(&self, data: *mut u8, len: i32) {
		self.traced_len.store(len, Ordering::Relaxed);
		self.traced.store(data, Ordering::Release);
	}

	fn finish(&self, result: i32) {
		self.result.store(result, Ordering::Relaxed);
		self.done.store(true, Ordering::Release);
	}
}

pub struct UsbBridge {
	file: HANDLE,
	winusb: WINUSB_INTERFACE_HANDLE,
	iocp: HANDLE,
}

// Every field is an opaque OS handle, and the whole point is that the completion pump runs on its
// own thread while the kernel calls in from another.
unsafe impl Send for UsbBridge {}
unsafe impl Sync for UsbBridge {}

impl UsbBridge {
	#[must_use]
	pub const fn new(file: HANDLE, winusb: WINUSB_INTERFACE_HANDLE, iocp: HANDLE) -> Self {
		Self { file, winusb, iocp }
	}

	/// The shim copies this, so it need not outlive the call, but `self` must, because its
	/// address is the cookie every callback receives.
	#[must_use]
	pub fn ops(&self, superspeed: bool) -> LdnLklUsbOps {
		LdnLklUsbOps {
			submit_control: Some(submit_control),
			submit_transfer: Some(submit_transfer),
			poll: Some(poll),
			cancel: Some(cancel),
			release: Some(release),
			set_alt: Some(set_alt),
			cookie: std::ptr::from_ref(self).cast_mut().cast(),
			superspeed: i32::from(superspeed),
		}
	}

	#[must_use]
	pub const fn interface(&self) -> WINUSB_INTERFACE_HANDLE {
		self.winusb
	}

	pub fn stop_pump(&self) {
		// A completion with a null OVERLAPPED is the sentinel the pump stops on.
		// SAFETY: `iocp` is a live completion port for as long as this bridge exists.
		let _ = unsafe { PostQueuedCompletionStatus(self.iocp, 0, 0, None) };
	}

	/// Queues a completion for a transfer Windows rejected outright.
	///
	/// A submit that never started gets no completion of its own, so without this the kernel is
	/// never interrupted and waits out its own URB timeout for a transfer that already failed.
	fn post_failure(&self, transfer: &Transfer) {
		transfer.submit_failed.store(true, Ordering::Release);

		// SAFETY: `iocp` is live, and the OVERLAPPED belongs to a transfer the caller is about to
		// hand to the kernel, which cannot release it before it is marked done.
		let _ = unsafe {
			PostQueuedCompletionStatus(self.iocp, 0, 0, Some(&raw const transfer.overlapped))
		};
	}
}

/// A pointer to a leaked [`UsbBridge`], movable to the completion pump's thread.
#[derive(Debug, Clone, Copy)]
pub struct BridgeHandle(*const UsbBridge);

// The bridge is leaked for the life of the kernel, so the pointer stays valid, and every field it
// reaches is either an OS handle or atomic.
unsafe impl Send for BridgeHandle {}

impl BridgeHandle {
	#[must_use]
	pub const fn new(bridge: *const UsbBridge) -> Self {
		Self(bridge)
	}
}

/// # Safety
/// `bridge` must point at a live [`UsbBridge`] for the whole call.
pub unsafe fn run_completion_pump(bridge: BridgeHandle, ctx: KernelContext, irq: i32) {
	// SAFETY: the caller guarantees the bridge outlives the pump.
	let Some(bridge) = (unsafe { bridge.0.as_ref() }) else {
		return;
	};

	loop {
		let mut bytes = 0u32;
		let mut key = 0usize;
		let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();

		let ok = unsafe {
			GetQueuedCompletionStatus(
				bridge.iocp,
				&raw mut bytes,
				&raw mut key,
				&raw mut overlapped,
				u32::MAX,
			)
		}
		.is_ok();

		if overlapped.is_null() {
			return;
		}

		// SAFETY: `overlapped` is the first field of the Transfer that was submitted, so it is
		// also the address of the Transfer itself.
		let transfer = overlapped.cast::<Transfer>();
		let Some(transfer) = (unsafe { transfer.as_ref() }) else {
			continue;
		};

		let mut transferred = 0u32;
		// A submit that was rejected has a zeroed OVERLAPPED that was never given to Windows.
		// `GetOverlappedResult` would read that as a successful zero-byte transfer, so the failure
		// has to be taken from the flag instead of asked for.
		let got = !transfer.submit_failed.load(Ordering::Acquire)
			&& ok && unsafe {
			WinUsb_GetOverlappedResult(bridge.winusb, overlapped, &raw mut transferred, false)
		}
		.is_ok();

		if tracing() {
			let data = transfer.traced.load(Ordering::Acquire);
			let len = usize::try_from(transferred)
				.unwrap_or(0)
				.min(usize::try_from(transfer.traced_len.load(Ordering::Relaxed)).unwrap_or(0));

			let received = if got && !data.is_null() && len > 0 {
				// SAFETY: the buffer belongs to the transfer the kernel is still holding; it
				// releases it only after polling, which cannot happen before this completion is
				// published below.
				format!(
					" in={}",
					hex(unsafe { core::slice::from_raw_parts(data, len) })
				)
			} else {
				String::new()
			};

			println!(
				"[{:>6}] usb: done ok={ok} bytes={transferred} got={got}{received} xfer={:p}",
				at(),
				std::ptr::from_ref(transfer)
			);
		}

		transfer.finish(if got {
			i32::try_from(transferred).unwrap_or(i32::MAX)
		} else {
			-1
		});

		if irq >= 0 {
			unsafe { ldn_lkl_trigger_irq(ctx.raw_for_ffi(), irq) };
		}
	}
}

/// # Safety
/// `cookie` must be the pointer given to `ldn_lkl_usb_attach`.
const unsafe fn bridge<'a>(cookie: *mut core::ffi::c_void) -> Option<&'a UsbBridge> {
	unsafe { cookie.cast::<UsbBridge>().as_ref() }
}

unsafe extern "C" fn submit_control(
	cookie: *mut core::ffi::c_void,
	setup: *const u8,
	data: *mut core::ffi::c_void,
	len: i32,
) -> *mut core::ffi::c_void {
	let _ = len;

	let Some(bridge) = (unsafe { bridge(cookie) }) else {
		return std::ptr::null_mut();
	};

	// SAFETY: the kernel guarantees eight readable bytes of setup packet.
	let Some(setup) = (unsafe { setup.cast::<[u8; 8]>().as_ref() }) else {
		return std::ptr::null_mut();
	};

	let packet = WINUSB_SETUP_PACKET {
		RequestType: setup[0],
		Request: setup[1],
		Value: u16::from_le_bytes([setup[2], setup[3]]),
		Index: u16::from_le_bytes([setup[4], setup[5]]),
		Length: u16::from_le_bytes([setup[6], setup[7]]),
	};

	let transfer = Transfer::new();

	// A control transfer with no data stage passes a null pointer and a zero wLength. Rust
	// forbids building even an empty slice from null, so that case has to become `None`.
	let buffer = if data.is_null() || packet.Length == 0 {
		None
	} else {
		// SAFETY: the kernel guarantees `data` is writable for wLength bytes, and keeps it alive
		// until it releases the transfer.
		Some(unsafe {
			core::slice::from_raw_parts_mut(data.cast::<u8>(), usize::from(packet.Length))
		})
	};

	let inbound = packet.RequestType & 0x80 != 0;

	let sent = match buffer.as_deref() {
		Some(data) if tracing() && !inbound => Some(hex(data)),
		_ => None,
	};

	if tracing() && inbound && !data.is_null() {
		transfer.trace_buffer(data.cast::<u8>(), i32::from(packet.Length));
	}

	// SAFETY: as above. The transferred count is `None` on purpose: with an OVERLAPPED the call
	// returns before the transfer is done, so an out-parameter here would be written long after
	// this frame is gone. The count comes from `GetOverlappedResult` in the pump instead.
	let ok = unsafe {
		WinUsb_ControlTransfer(
			bridge.winusb,
			packet,
			buffer,
			None,
			Some(&raw const transfer.overlapped),
		)
	}
	.is_ok();

	let err = if ok { 0 } else { unsafe { GetLastError() }.0 };

	if tracing() {
		// Copied out one by one: the setup packet is `#[repr(packed)]`, so its fields cannot be
		// borrowed, and formatting borrows.
		let (rt, req) = (packet.RequestType, packet.Request);
		let (value, index, length) = (packet.Value, packet.Index, packet.Length);

		let started = if ok || err == ERROR_IO_PENDING.0 {
			"pending".to_owned()
		} else {
			format!("FAILED err={err}")
		};

		let sent = sent.map_or_else(String::new, |sent| format!(" out={sent}"));

		println!(
			"[{:>6}] usb: ctrl rt={rt:02x} req={req:02x} val={value:04x} idx={index:04x} len={length} \
			 -> {started}{sent} xfer={:p}",
			at(),
			std::ptr::from_ref(transfer.as_ref())
		);
	}

	if !ok && err != ERROR_IO_PENDING.0 {
		bridge.post_failure(&transfer);
	}

	Box::into_raw(transfer).cast()
}

unsafe extern "C" fn submit_transfer(
	cookie: *mut core::ffi::c_void,
	endpoint: u8,
	data: *mut core::ffi::c_void,
	len: i32,
) -> *mut core::ffi::c_void {
	let Some(bridge) = (unsafe { bridge(cookie) }) else {
		return std::ptr::null_mut();
	};

	let length = usize::try_from(len).unwrap_or(0);
	let transfer = Transfer::new();
	let overlapped = &raw const transfer.overlapped;

	// SAFETY: `data` is valid for `len` bytes for the transfer's lifetime. The direction bit
	// decides whether the kernel is asking us to read into it or write out of it.
	let empty = data.is_null() || length == 0;

	let ok = if endpoint & 0x80 == 0 {
		let buffer: &[u8] = if empty {
			&[]
		} else {
			// SAFETY: valid for `length` bytes until the kernel releases the transfer.
			unsafe { core::slice::from_raw_parts(data.cast::<u8>(), length) }
		};

		// SAFETY: as above. `None` for the count, for the reason given in `submit_control`.
		unsafe { WinUsb_WritePipe(bridge.winusb, endpoint, buffer, None, Some(overlapped)) }
	} else {
		let buffer = if empty {
			None
		} else {
			// SAFETY: writable for `length` bytes until the kernel releases the transfer.
			Some(unsafe { core::slice::from_raw_parts_mut(data.cast::<u8>(), length) })
		};

		unsafe { WinUsb_ReadPipe(bridge.winusb, endpoint, buffer, None, Some(overlapped)) }
	}
	.is_ok();

	let err = if ok { 0 } else { unsafe { GetLastError() }.0 };

	if tracing() {
		println!(
			"[{:>6}] usb: {} ep={endpoint:02x} len={len} -> ok={ok} err={err} xfer={:p}",
			at(),
			if endpoint & 0x80 == 0 { "out " } else { "in  " },
			std::ptr::from_ref(transfer.as_ref())
		);
	}

	if !ok && err != ERROR_IO_PENDING.0 {
		bridge.post_failure(&transfer);
	}

	Box::into_raw(transfer).cast()
}

unsafe extern "C" fn poll(
	_cookie: *mut core::ffi::c_void,
	handle: *mut core::ffi::c_void,
	result: *mut i32,
) -> i32 {
	// SAFETY: `handle` came from one of the submit callbacks.
	let Some(transfer) = (unsafe { handle.cast::<Transfer>().as_ref() }) else {
		return 0;
	};

	// `Acquire` pairs with the `Release` in `finish`, so the result is visible once `done` is.
	if !transfer.done.load(Ordering::Acquire) {
		return 0;
	}

	if let Some(result) = unsafe { result.as_mut() } {
		*result = transfer.result.load(Ordering::Relaxed);
	}

	1
}

unsafe extern "C" fn cancel(cookie: *mut core::ffi::c_void, handle: *mut core::ffi::c_void) {
	let Some(bridge) = (unsafe { bridge(cookie) }) else {
		return;
	};

	let Some(transfer) = (unsafe { handle.cast::<Transfer>().as_ref() }) else {
		return;
	};

	if !transfer.done.load(Ordering::Acquire) {
		if tracing() {
			println!(
				"[{:>6}] usb: cancel (still in flight) xfer={:p}",
				at(),
				std::ptr::from_ref(transfer)
			);
		}

		// SAFETY: the OVERLAPPED belongs to a transfer still in flight on this handle.
		let _ = unsafe { CancelIoEx(bridge.file, Some(&raw const transfer.overlapped)) };
	} else if tracing() {
		println!(
			"[{:>6}] usb: cancel (already done) xfer={:p}",
			at(),
			std::ptr::from_ref(transfer)
		);
	}
}

unsafe extern "C" fn release(_cookie: *mut core::ffi::c_void, handle: *mut core::ffi::c_void) {
	if handle.is_null() {
		return;
	}

	// SAFETY: the handle came from `Box::into_raw` in a submit callback, and the kernel releases
	// each one exactly once.
	drop(unsafe { Box::from_raw(handle.cast::<Transfer>()) });
}

unsafe extern "C" fn set_alt(cookie: *mut core::ffi::c_void, _interface: u8, alt: u8) -> i32 {
	let Some(bridge) = (unsafe { bridge(cookie) }) else {
		return -1;
	};

	if unsafe { WinUsb_SetCurrentAlternateSetting(bridge.winusb, alt) }.is_ok() {
		0
	} else {
		-1
	}
}

impl Drop for UsbBridge {
	fn drop(&mut self) {
		// SAFETY: each handle was created by `attach` and is closed exactly once, here.
		unsafe {
			let _ = WinUsb_Free(self.winusb);
			let _ = CloseHandle(self.iocp);
			let _ = CloseHandle(self.file);
		}
	}
}
