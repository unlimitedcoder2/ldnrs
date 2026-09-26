use crate::broadcast::{Broadcast, Event, Receiver};

pub(crate) type LogBroadcast = Broadcast<String>;
pub type LogReceiver = Receiver<String>;
pub type LogEvent = Event<String>;
