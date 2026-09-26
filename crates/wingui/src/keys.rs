use std::path::{Path, PathBuf};

use ldn::crypto::Keys;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Controls::Dialogs::{
	GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_HIDEREADONLY, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::ui;

const PATH_BUFFER: usize = 4096;

pub fn ask_for_file(hwnd: HWND) -> Option<PathBuf> {
	let filter = ui::wide("Key files (*.keys)\0*.keys\0All files (*.*)\0*.*\0");
	let title = ui::wide("Select prod.keys");

	let mut file = vec![0u16; PATH_BUFFER];

	let mut options = OPENFILENAMEW {
		lStructSize: u32::try_from(size_of::<OPENFILENAMEW>()).ok()?,
		hwndOwner: hwnd,
		lpstrFilter: PCWSTR(filter.as_ptr()),
		lpstrFile: PWSTR(file.as_mut_ptr()),
		nMaxFile: u32::try_from(file.len()).ok()?,
		lpstrTitle: PCWSTR(title.as_ptr()),
		Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY,
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

pub struct Verdict {
	pub ok: bool,
	pub text: String,
}

#[must_use]
pub fn inspect(path: &Path) -> Verdict {
	match Keys::load(path) {
		Ok(_) => Verdict {
			ok: true,
			text: String::new(),
		},
		Err(err) => Verdict {
			ok: false,
			text: format!("Could not read this file: {err}"),
		},
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
	use super::*;

	const SOURCES: &str = "aes_kek_generation_source = 000102030405060708090a0b0c0d0e0f\n\
	                       aes_key_generation_source = 101112131415161718191a1b1c1d1e1f\n";

	fn written(name: &str, text: &str) -> PathBuf {
		let dir = std::env::temp_dir().join("ldnrs-keys-test");
		std::fs::create_dir_all(&dir).expect("a temp directory");

		let path = dir.join(name);
		std::fs::write(&path, text).expect("writing the test keys");

		path
	}

	#[test]
	fn a_complete_file_is_accepted() {
		let text = format!(
			"{SOURCES}master_key_00 = 202122232425262728292a2b2c2d2e2f\n\
			 master_key_12 = 303132333435363738393a3b3c3d3e3f\n"
		);

		let verdict = inspect(&written("complete.keys", &text));

		assert!(verdict.ok);
		assert!(verdict.text.is_empty());
	}

	#[test]
	fn an_incomplete_file_names_the_missing_key() {
		let text = format!("{SOURCES}master_key_00 = 202122232425262728292a2b2c2d2e2f\n");
		let verdict = inspect(&written("old.keys", &text));

		assert!(!verdict.ok);
		assert!(
			verdict.text.contains("prod.keys is missing master_key_12"),
			"{}",
			verdict.text
		);
	}

	#[test]
	fn an_empty_file_is_not_a_key_file() {
		let verdict = inspect(&written("empty.keys", "\n\n  \n"));

		assert!(!verdict.ok);
		assert!(verdict.text.contains("prod.keys is missing master_key_00"));
	}

	#[test]
	fn a_file_that_will_not_read_says_so() {
		let missing = std::env::temp_dir()
			.join("ldnrs-keys-test")
			.join("gone.keys");
		let _ = std::fs::remove_file(&missing);

		let verdict = inspect(&missing);

		assert!(!verdict.ok);
		assert!(
			verdict.text.starts_with("Could not read this file:"),
			"{}",
			verdict.text
		);
	}
}
