use core::slice;
use std::{
	ffi::{CStr, CString, c_void},
	io::ErrorKind,
	ops::Deref,
	ptr::null_mut,
	sync::{Arc, OnceLock},
};

use ::windows::{
	Win32::{
		Devices::Usb::{
			AUTO_CLEAR_STALL, PIPE_TRANSFER_TIMEOUT, USB_INTERFACE_DESCRIPTOR,
			WINUSB_INTERFACE_HANDLE, WINUSB_PIPE_INFORMATION, WinUsb_Free, WinUsb_Initialize,
			WinUsb_QueryInterfaceSettings, WinUsb_QueryPipe, WinUsb_SetPipePolicy,
		},
		Foundation::{GENERIC_READ, GENERIC_WRITE},
		Storage::FileSystem::{
			CreateFileA, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
			FILE_SHARE_WRITE, OPEN_EXISTING, SetFileCompletionNotificationModes,
		},
		System::{
			IO::CreateIoCompletionPort, WindowsProgramming::FILE_SKIP_COMPLETION_PORT_ON_SUCCESS,
		},
	},
	core::{Owned, PCSTR},
};
use tokio::{io::AsyncWriteExt, runtime::Handle, task::JoinSet};
use wrest::{Client, StatusCode};

use crate::{
	generated::{ldn_lkl_find_driver, ldn_lkl_init},
	winusb::UsbDevice,
};

use anyhow::Context;

mod generated;
pub mod winusb;

pub enum Mode {
	Lkl(Lkl),
	#[cfg(target_os = "linux")]
	Linux,
}

impl Mode {
	pub async fn shutdown(&self) -> anyhow::Result<()> {
		match self {
			Self::Lkl(lkl) => {
				lkl.shutdown().await?;

				Ok(())
			}
		}
	}

	#[must_use]
	pub fn logs(&self) -> tokio::sync::broadcast::Receiver<String> {
		match self {
			Self::Lkl(lkl) => {
				//
				lkl.inner.logs.subscribe()
			}
		}
	}
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
	logs: tokio::sync::broadcast::Sender<String>,
	_handle: Handle,
}

// fuck it we ball
unsafe impl Send for LklInner {}
unsafe impl Sync for LklInner {}

pub struct Lkl {
	inner: Arc<LklInner>,
}

impl Lkl {
	#[must_use]
	pub fn new(handle: Handle) -> Self {
		let (tx, _) = tokio::sync::broadcast::channel(100);

		Self {
			inner: Arc::new(LklInner {
				_handle: handle,
				device: OnceLock::new(),
				lkl_ctx: OnceLock::new(),
				logs: tx,
			}),
		}
	}

	fn get_fw_list(&self, device: &UsbDevice) -> anyhow::Result<Vec<&'static str>> {
		anyhow::ensure!(self.inner.lkl_ctx.get().is_some());

		let mut v = Vec::<&'static str>::new();
		let v_ptr = &raw mut v;
		unsafe {
			ldn_lkl_find_driver(
				*self.inner.lkl_ctx.get().unwrap(),
				device.vid.into(),
				device.pid.into(),
				Some(firmware_vec_string_add),
				v_ptr.cast::<c_void>(),
			);
		};

		Ok(v)
	}

	// TODO: https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git/ get regulatory.db too

	pub async fn download_firmware(
		&self,
		device: &UsbDevice,
		client: &Client,
	) -> anyhow::Result<()> {
		let firmware_files = self.get_fw_list(device)?;

		let home_dir = std::env::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir :("))?;
		let ldnrs_dir = home_dir.join(".ldnrs");
		let fw_dir = ldnrs_dir.join("firmware");
		tokio::fs::create_dir_all(&fw_dir).await?;

		let mut downloads = JoinSet::new();

		for fw in firmware_files {
			let fw_dir = fw_dir.clone();
			let client = client.clone();

			downloads.spawn(async move {
				async move {
					// TODO: Is this the best place to download from?
					const LINUX_FW_HOST: &str =
						"https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain";

					let fw_path = fw_dir.join(fw);

					if let Some(parent) = fw_path.parent() {
						tokio::fs::create_dir_all(parent).await?;
					}

					match tokio::fs::metadata(&fw_path).await {
						Ok(m) => {
							anyhow::ensure!(m.is_file());
							return anyhow::Ok(());
						}
						Err(e) if e.kind() == ErrorKind::NotFound => {}
						Err(e) => return Err(e.into()),
					}

					let mut res = client.get(format!("{LINUX_FW_HOST}/{fw}")).send().await?;

					anyhow::ensure!(res.status() == StatusCode::OK);

					let mut f = tokio::fs::File::create(&fw_path).await?;

					// TODO: Can we hint that we know the file size
					let len = res.content_length();
					let mut written = 0usize;

					while let Some(chunk) = res.chunk().await? {
						written += chunk.len();
						println!("{fw}: {written}/{len:?}");

						f.write_all(chunk.as_ref()).await?;
					}

					anyhow::Ok(())
				}
				.await
				.with_context(|| fw)
			});
		}

		let mut errors = Vec::new();

		while let Some(result) = downloads.join_next().await {
			if let Err(err) = result {
				errors.push(err);
			}
		}

		anyhow::ensure!(
			errors.is_empty(),
			"{} firmware download(s) failed:{}",
			errors.len(),
			errors
				.iter()
				.map(|err| format!("\n  - {err:#}"))
				.collect::<String>()
		);

		Ok(())
	}

	pub async fn attach(&self, device: UsbDevice) -> anyhow::Result<()> {
		let inner = self.inner.clone();

		tokio::task::spawn_blocking(move || {
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

			let handle = unsafe { Owned::new(handle) };

			let iocp = unsafe { CreateIoCompletionPort(*handle, None, 0, 0) }?;
			let iocp = unsafe { Owned::new(iocp) };
			// TODO
			_ = iocp;

			unsafe {
				SetFileCompletionNotificationModes(
					*handle,
					FILE_SKIP_COMPLETION_PORT_ON_SUCCESS as _,
				)
			}?;

			let mut interface_handle = WINUSB_INTERFACE_HANDLE::default();
			unsafe { WinUsb_Initialize(*handle, &raw mut interface_handle) }?;

			let interface_handle = OwnedWinUsb::new(interface_handle);

			let mut interface = USB_INTERFACE_DESCRIPTOR::default();
			unsafe { WinUsb_QueryInterfaceSettings(*interface_handle, 0, &raw mut interface) }?;

			const LDN_USB_TIMEOUT_MS: usize = 1000;
			// const LDN_USB_RX_TIMEOUT_MS: usize = 250;

			const LDN_USB_TIMEOUT_MS_PTR: *const std::ffi::c_void =
				std::ptr::from_ref::<usize>(&LDN_USB_TIMEOUT_MS).cast::<std::ffi::c_void>();

			const YES: bool = true;
			const YES_PTR: *const std::ffi::c_void =
				std::ptr::from_ref::<bool>(&YES).cast::<std::ffi::c_void>();

			unsafe {
				WinUsb_SetPipePolicy(
					*interface_handle,
					0,
					PIPE_TRANSFER_TIMEOUT,
					size_of_val(&LDN_USB_TIMEOUT_MS) as _,
					LDN_USB_TIMEOUT_MS_PTR,
				)
			}?;

			for i in 0..interface.bNumEndpoints {
				let mut pipe_info = WINUSB_PIPE_INFORMATION::default();
				if let Err(_) =
					unsafe { WinUsb_QueryPipe(*interface_handle, 0, i, &raw mut pipe_info) }
				{
					continue;
				}

				if pipe_info.PipeId & 0x80 != 0 {
					unsafe {
						WinUsb_SetPipePolicy(
							*interface_handle,
							pipe_info.PipeId,
							PIPE_TRANSFER_TIMEOUT,
							size_of_val(&LDN_USB_TIMEOUT_MS) as _,
							LDN_USB_TIMEOUT_MS_PTR,
						)
					}?;
				}

				unsafe {
					WinUsb_SetPipePolicy(
						*interface_handle,
						pipe_info.PipeId,
						AUTO_CLEAR_STALL,
						size_of_val(&YES) as _,
						YES_PTR,
					)
				}?;
			}

			if inner.device.set(device).is_err() {
				anyhow::bail!("device already set")
			}

			Ok(())
		})
		.await?
	}

	pub async fn init(&self) -> anyhow::Result<()> {
		let inner = self.inner.clone();
		tokio::task::spawn_blocking(move || {
			let userdata = inner.clone();
			let userdata = Arc::into_raw(userdata);

			let mut ctx: *mut c_void = null_mut();
			let ret = unsafe { ldn_lkl_init(&raw mut ctx, userdata as *mut c_void) };
			if ret != 0 {
				anyhow::bail!("lkl init failed {}", ret);
			}

			if inner.lkl_ctx.set(ctx).is_err() {
				anyhow::bail!("Context already set");
			}

			Ok(())
		})
		.await?
	}

	async fn shutdown(&self) -> anyhow::Result<()> {
		tokio::task::spawn_blocking(|| {});

		Ok(())
	}
}

#[unsafe(no_mangle)]
#[allow(clippy::cast_sign_loss, clippy::as_conversions)]
pub extern "C" fn impl_ldn_lkl_print(
	str_: *const ::std::os::raw::c_char,
	len: i32,
	userdata: *mut ::std::os::raw::c_void,
) {
	let userdata = unsafe { &mut *userdata.cast::<LklInner>() };

	let s = unsafe { slice::from_raw_parts(str_.cast::<std::os::raw::c_uchar>(), len as usize) };
	let s = unsafe { str::from_utf8_unchecked(s) };

	let _ = userdata.logs.send(s.to_string());
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
