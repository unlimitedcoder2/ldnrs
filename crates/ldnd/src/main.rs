use std::path::PathBuf;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;

use compio::signal::ctrl_c;
use futures_util::future::{Either, select};
use ldn::monitor::MonitorSource;
use ldn::protocol::RadioState;
use ldn::{FirmwareProgress, KernelOptions, Lkl, logs::LogEvent, winusb};
use ldn_daemon::daemon::{Daemon, serve};

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

#[compio::main]
async fn main() -> anyhow::Result<()> {
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

	// Its own thread, not a task: a join or a create holds this runtime inside the kernel for
	// seconds at a time, and a task here would sit on the kernel's log until that returned, which
	// is exactly when it is wanted, and never if the call hangs.
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

	// The pipe comes up before the adapter does. A client connecting during bring-up gets a
	// successful Hello with `radio_ready = false` and an EV_RADIO_STATE when that changes, rather
	// than a bare connection failure it cannot interpret.
	println!("ldnd: socket {:?}", args.socket);
	let listener = compio::runtime::spawn({
		let daemon = Rc::clone(&daemon);
		let socket = args.socket.clone();

		async move {
			if let Err(err) = serve(
				Rc::clone(&daemon),
				socket.unwrap_or_else(|| r"\\.\pipe\ldnd".to_string()),
			)
			.await
			{
				println!("ldnd: {err:#}");
				daemon.request_shutdown();
			}
		}
	});

	let bringup = compio::runtime::spawn({
		let daemon = Rc::clone(&daemon);

		async move {
			if args.vid == 0 && args.pid == 0 {
				daemon.set_radio_state(
					RadioState::Idle,
					Some("no adapter selected; pass --usb vid:pid".to_owned()),
				);
				return;
			}

			daemon.set_radio_state(RadioState::Attaching, None);

			match bring_up(
				&daemon,
				args.vid,
				args.pid,
				KernelOptions { extra: args.kargs },
			)
			.await
			{
				Ok(()) => daemon.set_radio_state(RadioState::Ready, None),
				Err(err) => {
					println!("ldnd: adapter bring-up failed: {err:#}");
					daemon.set_radio_state(RadioState::Failed, Some(format!("{err:#}")));
				}
			}
		}
	});

	let reason = match select(pin!(ctrl_c()), pin!(daemon.wait_for_shutdown())).await {
		Either::Left((result, _)) => {
			result?;
			"ctrl-c"
		}
		Either::Right(((), _)) => "a client's Shutdown request",
	};

	println!("ldnd: stopping ({reason})");

	drop(bringup);
	drop(listener);
	daemon.lkl().shutdown();

	Ok(())
}

async fn bring_up(
	daemon: &Rc<Daemon>,
	vid: u16,
	pid: u16,
	kernel: KernelOptions,
) -> anyhow::Result<()> {
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

	let lkl = daemon.lkl();

	let client = wrest::Client::builder().build()?;

	compio::runtime::spawn_blocking({
		let lkl = lkl.clone();
		move || lkl.init_with(&kernel)
	})
	.await
	.map_err(|err| anyhow::anyhow!("blocking task failed: {err}"))??;
	ldn_daemon::firmware::download_firmware(
		lkl,
		&device,
		&client,
		Some(Arc::new(|progress: FirmwareProgress| {
			if !progress.file.is_empty() {
				println!(
					"firmware: {}/{} {}",
					progress.done, progress.total, progress.file
				);
			}
		})),
	)
	.await?;
	compio::runtime::spawn_blocking({
		let lkl = lkl.clone();
		move || lkl.attach(device)
	})
	.await
	.map_err(|err| anyhow::anyhow!("blocking task failed: {err}"))??;

	let ctx = lkl
		.context()
		.ok_or_else(|| anyhow::anyhow!("the kernel is not running"))?;

	let mut last = None;
	for _ in 0..30 {
		match MonitorSource::create(ctx, "phy0", "ldn-mon") {
			Ok(monitor) => {
				println!(
					"ldnd: monitor {} up on ifindex {}",
					monitor.name(),
					monitor.ifindex()
				);
				daemon.set_phyname("phy0");
				daemon.set_frame_source(monitor.into_source());
				return Ok(());
			}
			Err(err) => last = Some(err),
		}

		compio::time::sleep(std::time::Duration::from_secs(1)).await;
	}

	anyhow::bail!(
		"the adapter attached but no monitor interface could be created: {}",
		last.map_or_else(|| "no wiphy appeared".to_owned(), |err| format!("{err}"))
	)
}
