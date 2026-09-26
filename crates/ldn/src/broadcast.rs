use std::sync::{
	Arc, Mutex, MutexGuard, PoisonError,
	atomic::{AtomicUsize, Ordering},
};

use std::sync::mpsc::{
	Receiver as ChannelReceiver, SyncSender, TryRecvError, TrySendError, sync_channel,
};

const CAPACITY: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<T> {
	Item(T),
	Dropped(usize),
}

struct Subscriber<T> {
	tx: SyncSender<T>,
	dropped: Arc<AtomicUsize>,
}

pub struct Broadcast<T> {
	subscribers: Mutex<Vec<Subscriber<T>>>,
}

impl<T> Default for Broadcast<T> {
	fn default() -> Self {
		Self {
			subscribers: Mutex::new(Vec::new()),
		}
	}
}

impl<T: Clone> Broadcast<T> {
	#[must_use]
	pub fn new() -> Self {
		Self::default()
	}

	pub fn subscribe(&self) -> Receiver<T> {
		let (tx, rx) = sync_channel(CAPACITY);
		let dropped = Arc::new(AtomicUsize::new(0));

		self.lock().push(Subscriber {
			tx,
			dropped: Arc::clone(&dropped),
		});

		Receiver { rx, dropped }
	}

	pub fn send(&self, item: &T) {
		self.lock()
			.retain_mut(|sub| match sub.tx.try_send(item.clone()) {
				Ok(()) => true,
				Err(TrySendError::Full(_)) => {
					sub.dropped.fetch_add(1, Ordering::Relaxed);
					true
				}
				Err(_) => false,
			});
	}

	fn lock(&self) -> MutexGuard<'_, Vec<Subscriber<T>>> {
		self.subscribers
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
	}
}

pub struct Receiver<T> {
	rx: ChannelReceiver<T>,
	dropped: Arc<AtomicUsize>,
}

impl<T> Receiver<T> {
	pub fn recv(&mut self) -> Option<Event<T>> {
		let dropped = self.dropped.swap(0, Ordering::Relaxed);
		if dropped != 0 {
			return Some(Event::Dropped(dropped));
		}
		self.rx.recv().ok().map(Event::Item)
	}

	/// # Errors
	/// `Empty` when no event is ready, or `Disconnected` when all senders are gone.
	pub fn try_recv(&mut self) -> Result<Event<T>, TryRecvError> {
		let dropped = self.dropped.swap(0, Ordering::Relaxed);
		if dropped != 0 {
			return Ok(Event::Dropped(dropped));
		}

		self.rx.try_recv().map(Event::Item)
	}
}

#[cfg(test)]
mod tests {
	use super::{Broadcast, CAPACITY, Event};
	use std::sync::mpsc::TryRecvError;

	#[test]
	fn reports_full_queue_then_delivers_buffered_events() {
		let broadcast = Broadcast::new();
		let mut receiver = broadcast.subscribe();
		for value in 0..CAPACITY + 2 {
			broadcast.send(&value);
		}
		assert_eq!(receiver.try_recv(), Ok(Event::Dropped(2)));
		assert_eq!(receiver.try_recv(), Ok(Event::Item(0)));
		for _ in 1..CAPACITY {
			let _ = receiver.try_recv();
		}
		assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
	}
}
