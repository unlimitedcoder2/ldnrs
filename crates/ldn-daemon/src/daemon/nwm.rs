use crate::daemon::codec::Frame;
use crate::daemon::session::{Outbound, queue_event, queue_status};
use ldn::protocol::messages::decode_data;
use ldn::protocol::{Event, Op, Status, StatusReply};

pub(super) fn dispatch(frame: &Frame, out: &Outbound) {
	let request_id = frame.header.request_id;

	if frame.header.op() == Some(Op::Data) {
		let handle = decode_data(&frame.body).map_or(0, |(handle, _)| handle);

		queue_event(
			out,
			&Event::ChannelError {
				handle,
				status: Status::InvalidHandle.value(),
				message: "not implemented".to_owned(),
			},
		);
		return;
	}

	let Some(op) = frame.header.nwm_op() else {
		queue_status(
			out,
			request_id,
			&StatusReply::error(
				Status::Unsupported,
				"this connection selected NWM in Hello".to_owned(),
			),
		);
		return;
	};

	match op {}
}
