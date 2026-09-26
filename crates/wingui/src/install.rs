use std::path::PathBuf;

use anyhow::Context;
use ldn::winusb::UsbDevice;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
	INSTALLFLAG_FORCE, UpdateDriverForPlugAndPlayDevicesW,
};
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HWND};
use windows::core::{BOOL, PCWSTR};

use crate::codesign;
use crate::ui::wide;

const LDNRS_INTERFACE_GUID: &str = "{a3d9b1f2-5c74-4e2a-9f31-6b8e0d4c77a1}";

const INF_NAME: &str = "ldnrs_winusb.inf";
const CATALOG_NAME: &str = "ldnrs_winusb.cat";

#[must_use]
pub fn hardware_id(device: &UsbDevice) -> String {
	format!("USB\\VID_{:04X}&PID_{:04X}", device.vid, device.pid)
}

fn sanitize(name: &str) -> String {
	let cleaned: String = name
		.chars()
		.filter(|c| c.is_ascii_graphic() || *c == ' ')
		.filter(|c| !matches!(c, '"' | '%' | ';'))
		.take(60)
		.collect();

	if cleaned.trim().is_empty() {
		"USB Device".to_owned()
	} else {
		cleaned
	}
}

fn inf_text(device: &UsbDevice) -> String {
	format!(
		"; winusb pog.\r\n\
		 \r\n\
		 [Version]\r\n\
		 Signature = \"$Windows NT$\"\r\n\
		 Class = USBDevice\r\n\
		 ClassGuid = {{88BAE032-5A81-49f0-BC3D-A4FF138216D6}}\r\n\
		 Provider = %ProviderName%\r\n\
		 CatalogFile = {catalog_name}\r\n\
		 DriverVer = 01/01/2026,1.0.0.0\r\n\
		 PnpLockDown = 1\r\n\
		 \r\n\
		 [Manufacturer]\r\n\
		 %ProviderName% = ldnrs, NTamd64\r\n\
		 \r\n\
		 [ldnrs.NTamd64]\r\n\
		 %DeviceName% = WinUSB_Install, {hardware_id}\r\n\
		 \r\n\
		 [WinUSB_Install]\r\n\
		 Include = winusb.inf\r\n\
		 Needs = WINUSB.NT\r\n\
		 \r\n\
		 [WinUSB_Install.Services]\r\n\
		 Include = winusb.inf\r\n\
		 Needs = WINUSB.NT.Services\r\n\
		 \r\n\
		 [WinUSB_Install.HW]\r\n\
		 AddReg = WinUSB_AddReg\r\n\
		 \r\n\
		 [WinUSB_AddReg]\r\n\
		 HKR,,DeviceInterfaceGUIDs,0x10000,\"{interface_guid}\"\r\n\
		 \r\n\
		 [Strings]\r\n\
		 ProviderName = \"ldnrs\"\r\n\
		 DeviceName = \"{device_name} (WinUSB)\"\r\n",
		catalog_name = CATALOG_NAME,
		hardware_id = hardware_id(device),
		interface_guid = LDNRS_INTERFACE_GUID,
		device_name = sanitize(&device.name),
	)
}

fn package_dir(device: &UsbDevice) -> anyhow::Result<PathBuf> {
	let dir = std::env::temp_dir()
		.join("ldnrs-winusb")
		.join(format!("{:04x}_{:04x}", device.vid, device.pid));

	std::fs::create_dir_all(&dir)?;

	Ok(dir)
}

pub fn write_inf(device: &UsbDevice) -> anyhow::Result<PathBuf> {
	let dir = package_dir(device)?;
	let path = dir.join(INF_NAME);
	std::fs::write(&path, inf_text(device))?;

	Ok(path)
}

pub struct Outcome {
	pub inf_path: PathBuf,
	pub reboot_required: bool,
}

pub fn install(parent: HWND, device: &UsbDevice) -> anyhow::Result<Outcome> {
	let inf_path = write_inf(device)?;
	let dir = package_dir(device)?;
	let id_string = hardware_id(device);

	codesign::sign_package(&dir, INF_NAME, CATALOG_NAME, &id_string)
		.context("could not sign the driver package")?;

	let inf = wide(
		inf_path
			.to_str()
			.ok_or_else(|| anyhow::anyhow!("inf path is not valid unicode"))?,
	);
	let id = wide(&id_string);

	let mut reboot_required = BOOL::default();

	let result = unsafe {
		UpdateDriverForPlugAndPlayDevicesW(
			Some(parent),
			PCWSTR(id.as_ptr()),
			PCWSTR(inf.as_ptr()),
			INSTALLFLAG_FORCE,
			Some(&raw mut reboot_required),
		)
	};

	if let Err(err) = result {
		let hint = if err.code() == ERROR_ACCESS_DENIED.into() {
			"\n\nRun the wizard as administrator and try again."
		} else {
			"\n\nThe package was signed before this call, so this is the PnP installer rejecting \
			 it rather than a signature problem. setupapi.dev.log in the Windows inf directory \
			 records the reason."
		};

		anyhow::bail!("{err}{hint}");
	}

	Ok(Outcome {
		inf_path,
		reboot_required: reboot_required.as_bool(),
	})
}
