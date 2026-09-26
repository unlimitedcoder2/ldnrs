use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const KEYS: &str = "keys";

#[must_use]
pub fn path() -> Option<PathBuf> {
	Some(std::env::home_dir()?.join(".ldnrs").join("config"))
}

#[must_use]
pub fn keys_path() -> Option<PathBuf> {
	let text = std::fs::read_to_string(path()?).ok()?;

	value(&text, KEYS).map(PathBuf::from)
}

/// # Errors
/// If the directory cannot be created or the file cannot be written.
pub fn set_keys_path(keys: &Path) -> std::io::Result<()> {
	write_setting(KEYS, &keys.display().to_string())
}

fn write_setting(name: &str, value: &str) -> std::io::Result<()> {
	let config = path().ok_or_else(|| {
		std::io::Error::new(
			std::io::ErrorKind::NotFound,
			"there is no home directory to save the settings in",
		)
	})?;

	if let Some(parent) = config.parent() {
		std::fs::create_dir_all(parent)?;
	}

	let existing = std::fs::read_to_string(&config).unwrap_or_default();

	std::fs::write(&config, rewrite(&existing, name, value))
}

#[must_use]
fn value(text: &str, name: &str) -> Option<String> {
	text.lines().find_map(|line| {
		let (key, value) = line.split_once('=')?;

		(key.trim() == name).then(|| value.trim().to_owned())
	})
}

#[must_use]
fn rewrite(text: &str, name: &str, value: &str) -> String {
	let mut out = String::new();
	let mut written = false;

	for line in text.lines() {
		let is_name = line
			.split_once('=')
			.is_some_and(|(key, _)| key.trim() == name);

		if is_name {
			if !written {
				let _ = writeln!(out, "{name} = {value}");
				written = true;
			}
			continue;
		}

		out.push_str(line);
		out.push('\n');
	}

	if !written {
		let _ = writeln!(out, "{name} = {value}");
	}

	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_a_setting() {
		assert_eq!(
			value("keys = C:\\keys\\prod.keys\n", "keys").as_deref(),
			Some("C:\\keys\\prod.keys")
		);
		assert_eq!(value("keys=x\n", "keys").as_deref(), Some("x"));
		assert_eq!(value("other = x\n", "keys"), None);
		assert_eq!(value("", "keys"), None);
	}

	#[test]
	fn a_path_may_hold_an_equals_sign() {
		assert_eq!(
			value("keys = C:\\od=d\\prod.keys\n", "keys").as_deref(),
			Some("C:\\od=d\\prod.keys")
		);
	}

	#[test]
	fn replaces_in_place_and_keeps_the_rest() {
		let before = "adapter = 2357:0138\nkeys = old\ntheme = dark\n";

		assert_eq!(
			rewrite(before, "keys", "new"),
			"adapter = 2357:0138\nkeys = new\ntheme = dark\n"
		);
	}

	#[test]
	fn appends_when_absent() {
		assert_eq!(
			rewrite("theme = dark\n", "keys", "new"),
			"theme = dark\nkeys = new\n"
		);
		assert_eq!(rewrite("", "keys", "new"), "keys = new\n");
	}

	#[test]
	fn a_rewrite_round_trips() {
		let text = rewrite("", "keys", "C:\\keys\\prod.keys");

		assert_eq!(value(&text, "keys").as_deref(), Some("C:\\keys\\prod.keys"));
	}
}
