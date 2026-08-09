use windows::Win32::Devices::DeviceAndDriverInstallation::{
	DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SETUP_DI_REGISTRY_PROPERTY,
	SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, SPDRP_DEVICEDESC,
	SPDRP_FRIENDLYNAME, SPDRP_SERVICE, SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW,
	SetupDiGetDeviceInterfaceDetailW, SetupDiGetDeviceRegistryPropertyW,
};
use windows::Win32::Devices::Usb::GUID_DEVINTERFACE_USB_DEVICE;
use windows::Win32::Foundation::{
	ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
};

// TODO: Check for memory leaks

#[derive(Debug, Clone)]
pub struct UsbDevice {
	pub vid: u16,
	pub pid: u16,
	pub name: String,
	pub driver: String,
	pub path: String,
}

// \\?\usb#vid_0e8d&pid_7610#1.0#{a5dcbf10-6530-11d2-901f-00c04fb951ed}

const VID: [u16; 4] = [0x0076, 0x0069, 0x0064, 0x005f];
const PID: [u16; 4] = [0x0070, 0x0069, 0x0064, 0x005f];

pub fn find_vidpid(s: &[u16]) -> (u16, u16) {
	let mut vid: u16 = 0;
	let mut pid: u16 = 0;

	let len = s.len();
	let mut i = 0;
	loop {
		if i + 8 > len {
			break;
		}

		let key = &s[i..i + 4];
		if key != &VID && key != &PID {
			i += 1;
			continue;
		}

		let mut buf = [0u8; 4];
		for x in 0..buf.len() {
			let item = s[i + 4 + x];
			if item > u8::MAX as _ {
				return (0, 0);
			}
			buf[x] = item as _;
		}

		let s = unsafe { str::from_utf8_unchecked(&buf) };
		let v = match u16::from_str_radix(s, 16) {
			Ok(v) => v,
			Err(_) => return (0, 0),
		};

		if key == &VID {
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
		SetupDiGetDeviceInterfaceDetailW(dev_info, interface, None, 0, Some(&mut needed), None)
	};

	if let Err(e) = r
		&& e.code() != ERROR_INSUFFICIENT_BUFFER.into()
	{
		return Err(e.into());
	}

	// TODO: We could stack allocate if its small
	let mut buf = vec![0u32; needed as usize];
	let detail_ptr = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
	unsafe {
		(*detail_ptr).cbSize = if cfg!(target_pointer_width = "64") {
			8
		} else {
			6
		};
	}

	let mut owner = SP_DEVINFO_DATA {
		cbSize: size_of::<SP_DEVINFO_DATA>() as _,
		..Default::default()
	};

	unsafe {
		SetupDiGetDeviceInterfaceDetailW(
			dev_info,
			interface,
			Some(detail_ptr),
			needed,
			None,
			Some(&mut owner),
		)
	}?;

	let wide_ptr = unsafe { (*detail_ptr).DevicePath.as_ptr() };
	let len = (0..)
		.take_while(|&i| unsafe { *wide_ptr.add(i) != 0 })
		.count();
	let path = unsafe { core::slice::from_raw_parts(wide_ptr, len) }.to_vec();

	Ok((path, owner))
}

fn get_prop_str(
	dev_info: HDEVINFO,
	data: &SP_DEVINFO_DATA,
	prop: SETUP_DI_REGISTRY_PROPERTY,
) -> anyhow::Result<Option<String>> {
	let mut req_bufsize: u32 = 0;

	let r = unsafe {
		SetupDiGetDeviceRegistryPropertyW(dev_info, data, prop, None, None, Some(&mut req_bufsize))
	};

	if let Err(e) = r {
		if e.code() != ERROR_INSUFFICIENT_BUFFER.into() {
			if e.code() == ERROR_INVALID_DATA.into() {
				return Ok(None);
			}

			return Err(e.into());
		}
	}

	let mut buf = [0u16; 1024];

	if req_bufsize > buf.len() as _ {
		anyhow::bail!("TODO")
	}

	unsafe {
		SetupDiGetDeviceRegistryPropertyW(
			dev_info,
			data,
			prop,
			None,
			Some(std::slice::from_raw_parts_mut(
				buf.as_mut_ptr() as *mut u8,
				buf.len() * 2,
			)),
			None,
		)
	}?;

	let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
	let s = String::from_utf16(&buf[..end])?;
	Ok(Some(s))
}

/**
 * This returns devices with a winusb driver only
 */
pub fn get_devices() -> anyhow::Result<Vec<UsbDevice>> {
	let dev_info = unsafe {
		SetupDiGetClassDevsW(
			Some(&GUID_DEVINTERFACE_USB_DEVICE),
			None,
			None,
			DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
		)
	}?;

	let mut devices = Vec::<UsbDevice>::new();

	let mut interface_index = 0;
	loop {
		let mut interface = SP_DEVICE_INTERFACE_DATA {
			cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as _,
			..Default::default()
		};

		if let Err(e) = unsafe {
			SetupDiEnumDeviceInterfaces(
				dev_info,
				None,
				&GUID_DEVINTERFACE_USB_DEVICE,
				interface_index,
				&mut interface,
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

		if let Some(driver_name) = driver_name
			&& let Some(device_name) = device_name
			&& driver_name.eq_ignore_ascii_case("winusb")
		{
			let device_path = String::from_utf16(&device_path)?;
			devices.push(UsbDevice {
				vid: vidpid.0,
				pid: vidpid.1,
				name: device_name,
				driver: driver_name,
				path: device_path,
			});
		}
	}

	Ok(devices)
}
