use ldn::Lkl;
use wrest::Client;

use crate::worker::Worker;

pub struct App {
	pub worker: Worker,
	pub lkl: Lkl,
	pub client: Client,
}

impl App {
	pub fn new() -> anyhow::Result<Self> {
		let worker = Worker::new()?;

		let lkl = Lkl::new();

		let client = Client::builder().build()?;

		Ok(Self {
			worker,
			lkl,
			client,
		})
	}
}
