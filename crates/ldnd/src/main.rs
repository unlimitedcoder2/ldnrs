use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use ldn::monitor::MonitorSource;
use ldn::protocol::RadioState;
use ldn::{FirmwareProgress, KernelOptions, Lkl, logs::LogEvent, winusb};
use ldn_daemon::daemon::{Daemon, Server};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use windows::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows::core::BOOL;

#[derive(Debug, Default, Clone)]
struct Args {
	vid: u16,
	pid: u16,
	socket: Option<String>,
	keys: Option<PathBuf>,
	kargs: Option<String>,
}

const USAGE: &str = concat!(
	"ldnd - the LDN daemon\n",
	"\n",
	"Usage: ldnd --socket <pipe> [options]\n",
	"\n",
	"  --socket <pipe>    Named pipe to serve on, e.g. \\\\.\\pipe\\ldnd. Required.\n",
	"  --usb <vid:pid>    The adapter to attach, in hex, e.g. 0bda:b812. Without it the\n",
	"                     daemon serves but reports NO_RADIO.\n",
	"  --keys <path>      prod.keys. Without it the daemon serves but reports NO_KEYS.\n",
	"  --log-devices      List the USB devices this machine can see, then exit.\n",
	"  --help             This text.\n",
	"  --kargs <args>     Extra kernel arguments\n",
	"\n",
	"There is no flag for joining or hosting. A client chooses per connection by sending\n",
	"Connect or CreateNetwork, so the daemon does not need to be told in advance.\n",
);

fn parse_args() -> anyhow::Result<Args> {
	let mut args = Args::default();

	let mut os_args = std::env::args();
	_ = os_args.next();

	if os_args.len() == 0 {
		print!("{USAGE}");
		anyhow::bail!("no args");
	}

	while let Some(arg) = os_args.next() {
		match arg.as_str() {
			"--usb" => {
				let vidpid = os_args
					.next()
					.ok_or_else(|| anyhow::anyhow!("no vid:pid arg after --usb"))?;

				let (vid, pid) = vidpid
					.split_once(':')
					.ok_or_else(|| anyhow::anyhow!("no ':', expected format vid:pid"))?;

				args.vid = u16::from_str_radix(vid, 16)?;
				args.pid = u16::from_str_radix(pid, 16)?;
			}
			"--socket" => {
				args.socket = Some(
					os_args
						.next()
						.ok_or_else(|| anyhow::anyhow!("no socket argument after --socket"))?,
				);
			}
			"--keys" => {
				let path = PathBuf::from(
					os_args
						.next()
						.ok_or_else(|| anyhow::anyhow!("no path after --keys"))?,
				);

				anyhow::ensure!(path.is_file(), "keys file not found: {}", path.display());
				args.keys = Some(path);
			}

			"--kargs" => {
				args.kargs = Some(
					os_args
						.next()
						.ok_or_else(|| anyhow::anyhow!("no kernel args after --kargs"))?,
				);
			}

			_ => {
				print!("{USAGE}");
				anyhow::bail!("Unrecognized arg \"{}\"", arg)
			}
		}
	}

	Ok(args)
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn console_handler(event: u32) -> BOOL {
	if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
		INTERRUPTED.store(true, Ordering::Release);
		true.into()
	} else {
		false.into()
	}
}

fn main() -> anyhow::Result<()> {
	let mut os_args = std::env::args();
	_ = os_args.next();
	for arg in os_args {
		match arg.as_str() {
			"--log-devices" => {
				for device in &winusb::get_devices()? {
					println!("{device:?}");
				}

				return Ok(());
			}

			"--help" | "-h" => {
				print!("{USAGE}");
				return Ok(());
			}

			_ => {}
		}
	}

	let args = parse_args()?;

	let daemon = Daemon::new(Lkl::new(), args.keys.as_deref())?;

	// Kernel calls can take seconds; print their logs from a separate thread.
	let mut logs = daemon.logs();
	let _log_pump = std::thread::Builder::new()
		.name("ldnd-logs".to_owned())
		.spawn(move || {
			while let Some(event) = logs.recv() {
				match event {
					LogEvent::Item(msg) => println!("lkl: {}", msg.trim_end()),
					LogEvent::Dropped(n) => println!("lkl: [{n} log lines dropped]"),
				}
			}
		})?;

	// Bind before starting slow adapter work so clients can observe its radio state.
	let mut server = Server::new(
		Rc::clone(&daemon),
		args.socket.unwrap_or_else(|| r"\\.\pipe\ldnd".to_owned()),
	)?;
	unsafe { SetConsoleCtrlHandler(Some(console_handler), true) }?;

	let bringup = if args.vid == 0 && args.pid == 0 {
		daemon.set_radio_state(
			RadioState::Idle,
			Some("no adapter selected; pass --usb vid:pid".to_owned()),
		);
		None
	} else {
		daemon.set_radio_state(RadioState::Attaching, None);
		let lkl = daemon.lkl().clone();
		Some(
			std::thread::Builder::new()
				.name("ldnd-bringup".to_owned())
				.spawn(move || {
					bring_up(
						&lkl,
						args.vid,
						args.pid,
						&KernelOptions { extra: args.kargs },
					)
				})?,
		)
	};
	let mut bringup = bringup;
	let result = (|| -> anyhow::Result<()> {
		while !INTERRUPTED.load(Ordering::Acquire) && !daemon.shutdown_requested() {
			if bringup
				.as_ref()
				.is_some_and(std::thread::JoinHandle::is_finished)
				&& let Some(task) = bringup.take()
			{
				match task
					.join()
					.map_err(|_| anyhow::anyhow!("adapter bring-up thread panicked"))?
				{
					Ok(monitor) => {
						daemon.set_phyname("phy0");
						daemon.set_frame_source(monitor.into_source());
						daemon.set_radio_state(RadioState::Ready, None);
					}
					Err(err) => {
						println!("ldnd: adapter bring-up failed: {err:#}");
						daemon.set_radio_state(RadioState::Failed, Some(format!("{err:#}")));
					}
				}
			}
			server.poll()?;
			std::thread::sleep(Duration::from_millis(10));
		}
		Ok(())
	})();
	println!("ldnd: stopping");
	INTERRUPTED.store(true, Ordering::Release);
	// Bring-up owns kernel resources too; finish it before shutting the kernel down.
	if let Some(task) = bringup {
		let _ = task.join();
	}
	drop(server);
	daemon.lkl().shutdown();
	unsafe { SetConsoleCtrlHandler(Some(console_handler), false) }?;
	result
}

fn bring_up(
	lkl: &Lkl,
	vid: u16,
	pid: u16,
	kernel: &KernelOptions,
) -> anyhow::Result<MonitorSource> {
	let device = winusb::get_devices()?
		.into_iter()
		.find(|d| d.vid == vid && d.pid == pid)
		.ok_or_else(|| anyhow::anyhow!("no USB device with id {vid:04x}:{pid:04x}"))?;

	anyhow::ensure!(
		device.driver.eq_ignore_ascii_case("winusb"),
		"{} is bound to the {} driver, not WinUSB",
		device.name,
		device.driver
	);

	ensure_running()?;
	lkl.init_with(kernel)?;
	ensure_running()?;
	let progress: ldn::FirmwareProgressFn = Arc::new(|progress: FirmwareProgress| {
		if !progress.file.is_empty() {
			println!(
				"firmware: {}/{} {}",
				progress.done, progress.total, progress.file
			);
		}
	});
	ldn_daemon::firmware::download_firmware(lkl, &device, Some(&progress), None)?;

	ensure_running()?;
	lkl.attach(device)?;

	let ctx = lkl
		.context()
		.ok_or_else(|| anyhow::anyhow!("the kernel is not running"))?;

	let mut last = None;
	for _ in 0..30 {
		ensure_running()?;
		match MonitorSource::create(ctx, "phy0", "ldn-mon") {
			Ok(monitor) => {
				println!(
					"ldnd: monitor {} up on ifindex {}",
					monitor.name(),
					monitor.ifindex()
				);
				return Ok(monitor);
			}
			Err(err) => last = Some(err),
		}

		std::thread::sleep(Duration::from_secs(1));
	}

	anyhow::bail!(
		"the adapter attached but no monitor interface could be created: {}",
		last.map_or_else(|| "no wiphy appeared".to_owned(), |err| format!("{err}"))
	)
}

fn ensure_running() -> anyhow::Result<()> {
	anyhow::ensure!(
		!INTERRUPTED.load(Ordering::Acquire),
		"adapter bring-up cancelled"
	);
	Ok(())
}
