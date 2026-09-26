use windows::Win32::Devices::DeviceAndDriverInstallation::{
	DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY,
	SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, SPDRP_CLASS,
	SPDRP_DEVICEDESC, SPDRP_FRIENDLYNAME, SPDRP_SERVICE, SetupDiDestroyDeviceInfoList,
	SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
	SetupDiGetDeviceRegistryPropertyW,
};
use windows::Win32::Devices::Usb::GUID_DEVINTERFACE_USB_DEVICE;
use windows::Win32::Foundation::{
	ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
};
use windows::core::PCWSTR;

#[derive(Debug, Clone)]
pub struct UsbDevice {
	pub vid: u16,
	pub pid: u16,
	pub name: String,
	pub driver: String,
	pub path: String,
	pub class: Option<String>,
}

const CLASS_NET: &str = "Net";
const CLASS_USB_DEVICE: &str = "USBDevice";

impl UsbDevice {
	#[must_use]
	pub fn might_be_a_wifi_adapter(&self) -> bool {
		let Some(class) = self.class.as_ref() else {
			return true;
		};

		class.is_empty()
			|| class.eq_ignore_ascii_case(CLASS_NET)
			|| class.eq_ignore_ascii_case(CLASS_USB_DEVICE)
	}
}

const VID: [u16; 4] = [0x0076, 0x0069, 0x0064, 0x005f];
const PID: [u16; 4] = [0x0070, 0x0069, 0x0064, 0x005f];

#[must_use]
pub fn find_vidpid(s: &[u16]) -> (u16, u16) {
	let mut vid: u16 = 0;
	let mut pid: u16 = 0;

	let mut i = 0;
	while let Some(window) = s.get(i..i + 8) {
		let (key, digits) = window.split_at(4);
		if key != VID && key != PID {
			i += 1;
			continue;
		}

		let mut buf = [0u8; 4];
		for (byte, &item) in buf.iter_mut().zip(digits) {
			let Ok(item) = u8::try_from(item) else {
				return (0, 0);
			};
			*byte = item;
		}

		let Ok(s) = str::from_utf8(&buf) else {
			return (0, 0);
		};
		let Ok(v) = u16::from_str_radix(s, 16) else {
			return (0, 0);
		};

		if key == VID {
			vid = v;
		} else {
			pid = v;
		}

		if vid != 0 && pid != 0 {
			break;
		}

		i += 8;
	}

	(vid, pid)
}

fn get_interface_detail(
	dev_info: HDEVINFO,
	interface: &SP_DEVICE_INTERFACE_DATA,
) -> anyhow::Result<(Vec<u16>, SP_DEVINFO_DATA)> {
	let mut needed: u32 = 0;
	let r = unsafe {
		SetupDiGetDeviceInterfaceDetailW(dev_info, interface, None, 0, Some(&raw mut needed), None)
	};

	if let Err(e) = r
		&& e.code() != ERROR_INSUFFICIENT_BUFFER.into()
	{
		return Err(e.into());
	}

	let mut buf = vec![0u32; usize::try_from(needed)?];
	let detail_ptr = buf.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
	unsafe {
		(*detail_ptr).cbSize = if cfg!(target_pointer_width = "64") {
			8
		} else {
			6
		};
	}

	let mut owner = SP_DEVINFO_DATA {
		cbSize: u32::try_from(size_of::<SP_DEVINFO_DATA>())?,
		..Default::default()
	};

	unsafe {
		SetupDiGetDeviceInterfaceDetailW(
			dev_info,
			interface,
			Some(detail_ptr),
			needed,
			None,
			Some(&raw mut owner),
		)
	}?;

	let wide_ptr = unsafe { (*detail_ptr).DevicePath.as_ptr() };
	let path = unsafe { PCWSTR(wide_ptr).as_wide().to_vec() };

	Ok((path, owner))
}

fn get_prop_str(
	dev_info: HDEVINFO,
	data: &SP_DEVINFO_DATA,
	prop: SETUP_DI_REGISTRY_PROPERTY,
) -> anyhow::Result<Option<String>> {
	let mut req_bufsize: u32 = 0;

	let r = unsafe {
		SetupDiGetDeviceRegistryPropertyW(
			dev_info,
			data,
			prop,
			None,
			None,
			Some(&raw mut req_bufsize),
		)
	};

	if let Err(e) = r
		&& e.code() != ERROR_INSUFFICIENT_BUFFER.into()
	{
		if e.code() == ERROR_INVALID_DATA.into() {
			return Ok(None);
		}

		return Err(e.into());
	}

	let elements = usize::try_from(req_bufsize).unwrap_or(0).div_ceil(2) + 1;
	let mut buf = vec![0u16; elements];

	unsafe {
		SetupDiGetDeviceRegistryPropertyW(
			dev_info,
			data,
			prop,
			None,
			Some(std::slice::from_raw_parts_mut(
				buf.as_mut_ptr().cast::<u8>(),
				elements * 2,
			)),
			None,
		)
	}?;

	let text = match buf.iter().position(|&c| c == 0) {
		Some(end) => buf.get(..end).unwrap_or(&buf),
		None => &buf,
	};

	Ok(Some(String::from_utf16(text)?))
}

struct DeviceInfoSet(HDEVINFO);

impl Drop for DeviceInfoSet {
	fn drop(&mut self) {
		let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
	}
}

/// # Errors
/// If the device list cannot be enumerated.
pub fn get_devices() -> anyhow::Result<Vec<UsbDevice>> {
	let set = DeviceInfoSet(unsafe {
		SetupDiGetClassDevsW(
			Some(&GUID_DEVINTERFACE_USB_DEVICE),
			None,
			None,
			DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
		)
	}?);
	let dev_info = set.0;

	let mut devices = Vec::<UsbDevice>::new();

	let mut interface_index = 0;
	loop {
		let mut interface = SP_DEVICE_INTERFACE_DATA {
			cbSize: u32::try_from(size_of::<SP_DEVICE_INTERFACE_DATA>())?,
			..Default::default()
		};

		if let Err(e) = unsafe {
			SetupDiEnumDeviceInterfaces(
				dev_info,
				None,
				&GUID_DEVINTERFACE_USB_DEVICE,
				interface_index,
				&raw mut interface,
			)
		} {
			if e.code() == ERROR_NO_MORE_ITEMS.into() {
				break;
			}

			return Err(e.into());
		}

		interface_index += 1;

		let (device_path, data) = get_interface_detail(dev_info, &interface)?;
		let vidpid = find_vidpid(&device_path);

		if vidpid.0 == 0 || vidpid.1 == 0 {
			continue;
		}

		let device_name = match get_prop_str(dev_info, &data, SPDRP_FRIENDLYNAME)? {
			Some(name) => Some(name),
			None => get_prop_str(dev_info, &data, SPDRP_DEVICEDESC)?,
		};
		let driver_name = get_prop_str(dev_info, &data, SPDRP_SERVICE)?;

		let class = get_prop_str(dev_info, &data, SPDRP_CLASS)?;

		if let Some(driver_name) = driver_name
			&& let Some(device_name) = device_name
		{
			let device_path = String::from_utf16(&device_path)?;
			devices.push(UsbDevice {
				vid: vidpid.0,
				pid: vidpid.1,
				name: device_name,
				driver: driver_name,
				path: device_path,
				class,
			});
		}
	}

	Ok(devices)
}
