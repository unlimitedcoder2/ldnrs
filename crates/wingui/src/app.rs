use std::sync::Arc;

use ldn::Lkl;
use tokio::runtime::Runtime;
use wrest::Client;

pub struct App {
	pub runtime: Runtime,
	pub lkl: Arc<Lkl>,
	pub client: Client,
}

impl App {
	pub fn new() -> anyhow::Result<Self> {
		let runtime = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()?;

		let lkl = Arc::new(Lkl::new(runtime.handle().clone()));
		runtime.block_on(lkl.init())?;

		let client = Client::builder().build()?;

		Ok(Self {
			runtime,
			lkl,
			client,
		})
	}
}
