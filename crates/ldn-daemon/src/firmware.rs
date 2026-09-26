mod winhttp;

use anyhow::Context;
use ldn::{
	EXTRA_FIRMWARE, FirmwareProgress, FirmwareProgressFn, Lkl, firmware_dir, winusb::UsbDevice,
};
use std::{
	fmt::Write as _,
	io::{ErrorKind, Write as _},
	path::{Path, PathBuf},
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
};

pub type ManualFetchFn = Arc<dyn Fn(&str, &str) -> Option<PathBuf> + Send + Sync>;

/// # Errors
/// If the kernel is not running, the firmware directory cannot be made, or any required
/// download fails. A failed optional download is only logged.
pub fn download_firmware(
	lkl: &Lkl,
	device: &UsbDevice,
	progress: Option<&FirmwareProgressFn>,
	manual: Option<&ManualFetchFn>,
) -> anyhow::Result<()> {
	let fetch_manual = manual.cloned();
	lkl.set_firmware_fetch(Arc::new(move |name| {
		let fw_dir = firmware_dir()?;
		fetch_firmware(&fw_dir, name, fetch_manual.as_ref())?;
		Ok(std::fs::read(fw_dir.join(name))?)
	}));
	let firmware_files = lkl.get_fw_list(device)?;

	let total = firmware_files.len() + EXTRA_FIRMWARE.len();
	let done = AtomicUsize::new(0);

	if let Some(progress) = &progress {
		progress(FirmwareProgress {
			done: 0,
			total,
			file: "",
		});
	}

	let fw_dir = firmware_dir()?;
	std::fs::create_dir_all(&fw_dir)?;

	let results = std::thread::scope(|scope| -> anyhow::Result<Vec<_>> {
		let mut downloads = Vec::with_capacity(total);
		for (fw, required) in firmware_files
			.into_iter()
			.map(|fw| (fw, true))
			.chain(EXTRA_FIRMWARE.map(|fw| (fw, false)))
		{
			let fw_dir = &fw_dir;
			let progress = &progress;
			let done = &done;
			downloads.push(
				std::thread::Builder::new()
					.name("ldnd-firmware".to_owned())
					.spawn_scoped(scope, move || {
						let result = fetch_firmware(fw_dir, fw, manual).with_context(|| fw);
						if result.is_ok()
							&& let Some(progress) = progress
						{
							progress(FirmwareProgress {
								done: done.fetch_add(1, Ordering::Relaxed) + 1,
								total,
								file: fw,
							});
						}
						(required, result)
					})?,
			);
		}
		downloads
			.into_iter()
			.map(|download| {
				download
					.join()
					.map_err(|_| anyhow::anyhow!("firmware download thread panicked"))
			})
			.collect()
	})?;

	let mut errors = Vec::new();

	for (required, result) in results {
		if let Err(err) = result {
			if required {
				errors.push(err);
			} else {
				println!("firmware: optional download failed, continuing: {err:#}");
			}
		}
	}

	anyhow::ensure!(
		errors.is_empty(),
		"{} firmware download(s) failed:{}",
		errors.len(),
		errors.iter().fold(String::new(), |mut out, err| {
			let _ = write!(out, "\n  - {err:#}");
			out
		})
	);

	Ok(())
}

const KERNEL_ORG_HOST: &str = "git.kernel.org";
const LINUX_FW_PATH: &str = "/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain";
const REGDB_PATH: &str = "/pub/scm/linux/kernel/git/wens/wireless-regdb.git/plain";
const GITLAB_HOST: &str = "gitlab.com";
const GITLAB_FW_PATH: &str = "/kernel-firmware/linux-firmware/-/raw/main";
const REGDB_PAGE: &str =
	"https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git/tree";
const FIRMWARE_PAGE: &str = "https://gitlab.com/kernel-firmware/linux-firmware/-/blob/main";

const FIRMWARE_HOSTS: &[(&'static str, &'static str)] = &[
	(KERNEL_ORG_HOST, LINUX_FW_PATH),
	(GITLAB_HOST, GITLAB_FW_PATH),
];

fn fetch_firmware(fw_dir: &Path, name: &str, manual: Option<&ManualFetchFn>) -> anyhow::Result<()> {
	let fw_path = fw_dir.join(name);

	if let Some(parent) = fw_path.parent() {
		std::fs::create_dir_all(parent)?;
	}

	match std::fs::metadata(&fw_path) {
		Ok(metadata) => {
			anyhow::ensure!(metadata.is_file(), "{} is not a file", fw_path.display());
			return Ok(());
		}
		Err(err) if err.kind() == ErrorKind::NotFound => {}
		Err(err) => return Err(err.into()),
	}

	let mut errors = Vec::new();
	let partial = fw_path.with_extension("partial");

	if name.starts_with("regulatory.db") {
		match download(
			KERNEL_ORG_HOST,
			&format!("{}/{}", REGDB_PATH, name),
			&partial,
		) {
			Ok(written) => {
				std::fs::rename(&partial, &fw_path)?;
				println!("firmware: fetched {name} from {KERNEL_ORG_HOST} ({written} bytes)");
				return Ok(());
			}
			Err(err) => {
				let _ = std::fs::remove_file(&partial);
				println!("firmware: {name} from {KERNEL_ORG_HOST} failed: {err:#}");
				errors.push(format!("{KERNEL_ORG_HOST}: {err:#}"));
			}
		}
	} else {
		for (host, path) in FIRMWARE_HOSTS {
			match download(host, &format!("{}/{}", path, name), &partial) {
				Ok(written) => {
					std::fs::rename(&partial, &fw_path)?;
					println!("firmware: fetched {name} from {host} ({written} bytes)");
					return Ok(());
				}
				Err(err) => {
					let _ = std::fs::remove_file(&partial);
					println!("firmware: {name} from {host} failed: {err:#}");
					errors.push(format!("{host}: {err:#}"));
				}
			}
		}
	}

	let Some(manual) = manual else {
		anyhow::bail!("{name}: {}", errors.join("; "))
	};
	let page = if name.starts_with("regulatory.db") {
		REGDB_PAGE
	} else {
		FIRMWARE_PAGE
	};
	let Some(source) = manual(name, &format!("{page}/{name}")) else {
		anyhow::bail!("{name}: {}; no file was selected", errors.join("; "))
	};

	let copied =
		std::fs::copy(&source, &partial).with_context(|| format!("copying {}", source.display()));
	match copied {
		Ok(0) => {
			let _ = std::fs::remove_file(&partial);
			anyhow::bail!("{name}: {} is empty", source.display())
		}
		Ok(written) => {
			std::fs::rename(&partial, &fw_path)?;
			println!(
				"firmware: copied {name} from {} ({written} bytes)",
				source.display()
			);
			Ok(())
		}
		Err(err) => {
			let _ = std::fs::remove_file(&partial);
			Err(err)
		}
	}
}

fn download(host: &str, path: &str, partial: &Path) -> anyhow::Result<u64> {
	let mut response = winhttp::Response::get(host, path)?;
	anyhow::ensure!(
		response.status() == 200,
		"server said {}",
		response.status()
	);

	let announced = response.content_length();

	let mut file = std::fs::File::create(partial)?;
	let written = std::io::copy(&mut response, &mut file)?;
	file.flush()?;
	drop(file);

	match announced {
		Some(announced) if announced != written => {
			anyhow::bail!("got {written} bytes, but the server announced {announced}")
		}
		_ if written == 0 => anyhow::bail!("the server returned an empty file"),
		_ => Ok(written),
	}
}
