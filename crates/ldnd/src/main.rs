use ldn::{Lkl, Mode, winusb};
use tokio::{io::AsyncReadExt, net::windows::named_pipe::ServerOptions, signal::ctrl_c};

#[derive(Debug, Default, Clone)]
struct Args {
	vid: u16,
	pid: u16,
	socket: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let mut args = Args::default();

	let mut os_args = std::env::args();
	os_args.next().unwrap();
	if os_args.len() == 0 {
		anyhow::bail!("no args");
	}

	while let Some(arg) = os_args.next() {
		match arg.as_str() {
			"--usb" => {
				let vidpid = os_args
					.next()
					.ok_or_else(|| anyhow::anyhow!("no vid:pid arg after --usb"))?;

				let index = vidpid
					.chars()
					.position(|c| c == ':')
					.ok_or_else(|| anyhow::anyhow!("no ':', expected format vid:pid"))?;

				let (vid, pid) = vidpid.split_at(index);

				args.vid = u16::from_str_radix(vid, 16)?;
				args.pid = u16::from_str_radix(&pid[1..], 16)?;
			}
			"--socket" => {
				let socket = os_args
					.next()
					.ok_or_else(|| anyhow::anyhow!("no socket argument after --socket"))?;
				args.socket = socket;
			}
			"--mode" => {
				anyhow::bail!("TODO")
			}

			"--log-devices" => {
				let usb_devices = winusb::get_devices()?;
				for dev in &usb_devices {
					println!("{:?}", dev);
				}

				return Ok(());
			}

			_ => {
				anyhow::bail!("Unrecognized arg \"{}\"", arg)
			}
		}
	}

	if args.vid == 0 || args.pid == 0 || args.socket.trim().is_empty() {
		anyhow::bail!("invalid args");
	}

	// 0e8d:7610 old one
	// 2357:0138 t3u
	// 2357:0120 t2u

	let usb_devices = winusb::get_devices()?;
	let device = usb_devices
		.into_iter()
		.find(|d| d.vid == args.vid && d.pid == args.pid)
		.ok_or_else(|| anyhow::anyhow!("Selected device not found"))?;

	let handle = tokio::runtime::Handle::current();
	let lkl = Lkl::new(handle);
	let mut mode = Mode::Lkl(lkl);

	let mut logs = mode.logs();

	let _ = tokio::spawn(async move {
		while let Ok(msg) = logs.recv().await {
			println!("lkl: {}", msg.trim_end());
		}
	});

	let client = wrest::Client::builder().build()?;

	match &mut mode {
		Mode::Lkl(lkl) => {
			lkl.init().await?;
			lkl.download_firmware(&device, &client).await?;
			lkl.attach(device).await?;
		}
	}

	// TODO: Unix socket on linux/bsd/macosx
	let opts = ServerOptions::new();
	let mut server = opts.create(args.socket)?;

	tokio::spawn(async move {
		loop {
			if let Err(e) = server.connect().await {
				println!("Failed to accept named pipe connection {}", e);
				continue;
			}

			let mut buf = vec![0u8; 4096];
			loop {
				match server.read(&mut buf).await {
					Ok(n) => {
						println!("Read {} bytes", n);
						continue;
					}
					Err(e) => {
						println!("Failed to read from named pipe {}", e);
						break;
					}
				}
			}

			if let Err(e) = server.disconnect() {
				println!("Failed to disconnect client {}", e);
			}
		}
	});

	let ctrlc = ctrl_c();
	tokio::select! {
		res = ctrlc => {
			res?;
			println!("Ctrl-c detected, stopping");
			mode.shutdown().await?;
			return Ok(());
		},
	}
}
