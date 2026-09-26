use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HWND;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Controls::Dialogs::{
	GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST,
	OPENFILENAMEW,
};
use windows::Win32::UI::Shell::{
	FOLDERID_Downloads, KF_FLAG_DEFAULT, SHGetKnownFolderPath, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{HSTRING, PCWSTR, PWSTR, w};

use crate::ui::wide;

const PATH_BUFFER: usize = 4096;

pub fn ask(name: &str, page: &str) -> Option<PathBuf> {
	println!("firmware: opening {page} for a manual download of {name}");
	let opened = unsafe {
		ShellExecuteW(
			None,
			w!("open"),
			&HSTRING::from(page),
			PCWSTR::null(),
			PCWSTR::null(),
			SW_SHOWNORMAL,
		)
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew#return-value
	// If the function succeeds, it returns a value greater than 32
	// ^- wtf
	if opened.0.addr() <= 32 {
		println!("firmware: could not open the browser; download {page} by hand");
	}

	open_dialog(name)
}

fn open_dialog(name: &str) -> Option<PathBuf> {
	let base = Path::new(name).file_name()?.to_string_lossy().into_owned();
	let filter = wide(&format!("{base}\0{base}\0All files (*.*)\0*.*\0"));
	let title = wide(&format!("Select the downloaded {base}"));
	let downloads = downloads_dir().map(|dir| wide(&dir.to_string_lossy()));

	let mut file = vec![0u16; PATH_BUFFER];

	let mut options = OPENFILENAMEW {
		lStructSize: u32::try_from(size_of::<OPENFILENAMEW>()).ok()?,
		hwndOwner: HWND::default(),
		lpstrFilter: PCWSTR(filter.as_ptr()),
		lpstrFile: PWSTR(file.as_mut_ptr()),
		nMaxFile: u32::try_from(file.len()).ok()?,
		lpstrInitialDir: downloads
			.as_ref()
			.map_or_else(PCWSTR::null, |dir| PCWSTR(dir.as_ptr())),
		lpstrTitle: PCWSTR(title.as_ptr()),
		Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR,
		..Default::default()
	};

	if !unsafe { GetOpenFileNameW(&raw mut options) }.as_bool() {
		return None;
	}

	let end = file
		.iter()
		.position(|unit| *unit == 0)
		.unwrap_or(file.len());
	let path = String::from_utf16(file.get(..end)?).ok()?;

	(!path.is_empty()).then(|| PathBuf::from(path))
}

fn downloads_dir() -> Option<PathBuf> {
	let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_Downloads, KF_FLAG_DEFAULT, None) }.ok()?;
	let dir = unsafe { raw.to_string() }.ok();
	unsafe { CoTaskMemFree(Some(raw.0.cast_const().cast())) };
	dir.map(PathBuf::from)
}
