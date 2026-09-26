use std::future::Future;
use std::thread;

use futures_channel::mpsc::{UnboundedSender, unbounded};
use futures_util::StreamExt;

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct Worker {
	jobs: UnboundedSender<Job>,
}

impl Worker {
	pub fn new() -> anyhow::Result<Self> {
		let (jobs, mut incoming) = unbounded::<Job>();
		let (started, ready) = std::sync::mpsc::channel::<Result<(), String>>();

		thread::Builder::new()
			.name("ldnrs-compio".to_owned())
			.spawn(move || {
				let runtime = match compio::runtime::Runtime::new() {
					Ok(runtime) => {
						let _ = started.send(Ok(()));
						runtime
					}
					Err(err) => {
						let _ = started.send(Err(format!("{err}")));
						return;
					}
				};

				runtime.block_on(async move {
					while let Some(job) = incoming.next().await {
						job();
					}
				});
			})?;

		match ready.recv() {
			Ok(Ok(())) => Ok(Self { jobs }),
			Ok(Err(err)) => anyhow::bail!("failed to start the compio runtime: {err}"),
			Err(err) => anyhow::bail!("worker thread died before starting: {err}"),
		}
	}

	pub fn spawn<F, Fut>(&self, build: F)
	where
		F: FnOnce() -> Fut + Send + 'static,
		Fut: Future<Output = ()> + 'static,
	{
		let job: Job = Box::new(move || {
			// Dropping a compio `JoinHandle` cancels the task, so detach it.
			compio::runtime::spawn(build()).detach();
		});

		let _ = self.jobs.unbounded_send(job);
	}
}
