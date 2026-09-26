use anyhow::Context;
use compio::io::AsyncWriteAtExt;
use futures_util::future::join_all;
use ldn::{
	EXTRA_FIRMWARE, FirmwareProgress, FirmwareProgressFn, Lkl, firmware_dir, winusb::UsbDevice,
};
use std::{
	fmt::Write as _,
	io::ErrorKind,
	path::Path,
	sync::{
		Arc,
		atomic::{AtomicUsize, Ordering},
	},
};
use wrest::{Client, StatusCode};

/// # Errors
/// If the kernel is not running, the firmware directory cannot be made, or any required
/// download fails. A failed optional download is only logged.
pub async fn download_firmware(
	lkl: &Lkl,
	device: &UsbDevice,
	client: &Client,
	progress: Option<FirmwareProgressFn>,
) -> anyhow::Result<()> {
	lkl.set_firmware_fetch(Arc::new(|name| {
		let runtime = compio::runtime::Runtime::new()?;
		let fw_dir = firmware_dir()?;
		runtime.block_on(async {
			let client = Client::builder().build()?;
			fetch_firmware(&client, &fw_dir, name).await
		})?;
		Ok(std::fs::read(fw_dir.join(name))?)
	}));
	let firmware_files = lkl.get_fw_list(device)?;

	let total = firmware_files.len() + EXTRA_FIRMWARE.len();
	let done = Arc::new(AtomicUsize::new(0));

	if let Some(progress) = &progress {
		progress(FirmwareProgress {
			done: 0,
			total,
			file: "",
		});
	}

	let fw_dir = firmware_dir()?;
	compio::fs::create_dir_all(&fw_dir).await?;

	let mut downloads = Vec::with_capacity(total);

	for (fw, required) in firmware_files
		.into_iter()
		.map(|fw| (fw, true))
		.chain(EXTRA_FIRMWARE.map(|fw| (fw, false)))
	{
		let fw_dir = fw_dir.clone();
		let client = client.clone();
		let progress = progress.clone();
		let done = done.clone();

		downloads.push(async move {
			let result = fetch_firmware(&client, &fw_dir, fw)
				.await
				.with_context(|| fw);

			if result.is_ok()
				&& let Some(progress) = &progress
			{
				progress(FirmwareProgress {
					done: done.fetch_add(1, Ordering::Relaxed) + 1,
					total,
					file: fw,
				});
			}

			(required, result)
		});
	}

	let mut errors = Vec::new();

	for (required, result) in join_all(downloads).await {
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

const LINUX_FW_HOST: &str =
	"https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain";
const REGDB_HOST: &str =
	"https://git.kernel.org/pub/scm/linux/kernel/git/wens/wireless-regdb.git/plain";

fn firmware_url(name: &str) -> String {
	if name.starts_with("regulatory.db") {
		format!("{REGDB_HOST}/{name}")
	} else {
		format!("{LINUX_FW_HOST}/{name}")
	}
}

async fn fetch_firmware(client: &Client, fw_dir: &Path, name: &str) -> anyhow::Result<()> {
	let fw_path = fw_dir.join(name);

	if let Some(parent) = fw_path.parent() {
		compio::fs::create_dir_all(parent).await?;
	}

	match compio::fs::metadata(&fw_path).await {
		Ok(metadata) => {
			anyhow::ensure!(metadata.is_file(), "{} is not a file", fw_path.display());
			return Ok(());
		}
		Err(err) if err.kind() == ErrorKind::NotFound => {}
		Err(err) => return Err(err.into()),
	}

	let mut response = client.get(firmware_url(name)).send().await?;
	anyhow::ensure!(
		response.status() == StatusCode::OK,
		"{name}: server said {}",
		response.status()
	);

	let announced = response.content_length();

	let partial = fw_path.with_extension("partial");
	let mut file = compio::fs::File::create(&partial).await?;

	let mut written = 0u64;

	while let Some(chunk) = response.chunk().await? {
		let chunk_len = chunk.len();
		file.write_all_at(chunk, written).await.0?;

		written = u64::try_from(chunk_len)
			.ok()
			.and_then(|n| written.checked_add(n))
			.ok_or_else(|| anyhow::anyhow!("{name}: size overflow"))?;
	}

	file.close().await?;

	let bad = match announced {
		Some(announced) if announced != written => Some(format!(
			"got {written} bytes, but the server announced {announced}"
		)),
		_ if written == 0 => Some("the server returned an empty file".to_owned()),
		_ => None,
	};

	if let Some(reason) = bad {
		let _ = compio::fs::remove_file(&partial).await;
		anyhow::bail!("{name}: {reason}");
	}

	compio::fs::rename(&partial, &fw_path).await?;

	println!("firmware: fetched {name} ({written} bytes)");

	Ok(())
}
