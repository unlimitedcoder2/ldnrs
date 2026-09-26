use super::bytes::{DecodeError, Reader};
use super::tables::{LdnOp, NwmOp, Op};
use super::writer::Writer;

pub const FRAME_HEADER_LEN: usize = 10;

/// Largest body this daemon will read. Checked before allocating.
pub const MAX_BODY: u32 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
	pub op: u8,
	pub sub_op: u8,
	pub request_id: u32,
	pub body_length: u32,
}

impl Header {
	/// A header with no `sub_op`, which is every op but [`Op::Ldn`] and [`Op::Nwm`].
	#[must_use]
	pub const fn new(op: Op, request_id: u32, body_length: u32) -> Self {
		Self {
			op: op.value(),
			sub_op: 0,
			request_id,
			body_length,
		}
	}

	/// An unknown opcode is not a framing error; `body_length` still says how much to skip, so
	/// the connection stays in sync and the peer gets [`super::tables::Status::Unsupported`].
	#[must_use]
	pub const fn op(&self) -> Option<Op> {
		Op::from_value(self.op)
	}

	/// `None` unless the op is [`Op::Ldn`] and the `sub_op` is known.
	#[must_use]
	pub const fn ldn_op(&self) -> Option<LdnOp> {
		match self.op() {
			Some(Op::Ldn) => LdnOp::from_value(self.sub_op),
			_ => None,
		}
	}

	/// `None` unless the op is [`Op::Nwm`] and the `sub_op` is known.
	#[must_use]
	pub const fn nwm_op(&self) -> Option<NwmOp> {
		match self.op() {
			Some(Op::Nwm) => NwmOp::from_value(self.sub_op),
			_ => None,
		}
	}

	#[must_use]
	pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
		let mut writer = Writer::with_capacity(FRAME_HEADER_LEN);
		writer.u8(self.op);
		writer.u8(self.sub_op);
		writer.u32_le(self.request_id);
		writer.u32_le(self.body_length);

		let bytes = writer.into_vec();
		<[u8; FRAME_HEADER_LEN]>::try_from(bytes.as_slice()).unwrap_or([0; FRAME_HEADER_LEN])
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if `data` is short, or
	/// [`DecodeError::BodyTooLarge`] if the announced body exceeds [`MAX_BODY`].
	pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(data);

		let header = Self {
			op: reader.u8()?,
			sub_op: reader.u8()?,
			request_id: reader.u32_le()?,
			body_length: reader.u32_le()?,
		};

		if header.body_length > MAX_BODY {
			return Err(DecodeError::BodyTooLarge {
				length: header.body_length,
				limit: MAX_BODY,
			});
		}

		Ok(header)
	}
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
	use super::{FRAME_HEADER_LEN, Header, MAX_BODY};
	use crate::protocol::bytes::DecodeError;
	use crate::protocol::tables::{LdnOp, Op};

	#[test]
	fn round_trips() {
		let header = Header::new(Op::Hello, 42, 17);
		let decoded = Header::decode(&header.encode()).unwrap();

		assert_eq!(decoded, header);
		assert_eq!(decoded.op(), Some(Op::Hello));
	}

	#[test]
	fn header_is_ten_bytes() {
		assert_eq!(Header::new(Op::Reply, 1, 3).encode().len(), 10);
		assert_eq!(FRAME_HEADER_LEN, 10);
	}

	#[test]
	fn sub_op_is_only_read_under_its_op() {
		let mut header = Header::new(Op::Ldn, 1, 0);
		header.sub_op = LdnOp::Scan.value();

		let decoded = Header::decode(&header.encode()).unwrap();
		assert_eq!(decoded.ldn_op(), Some(LdnOp::Scan));
		assert_eq!(decoded.nwm_op(), None);

		header.op = Op::Hello.value();
		assert_eq!(
			header.ldn_op(),
			None,
			"a sub_op under another op is not an LdnOp"
		);
	}

	#[test]
	fn unknown_opcode_still_frames() {
		let mut bytes = Header::new(Op::Hello, 7, 4).encode();
		bytes[0] = 0xEE;

		let decoded = Header::decode(&bytes).unwrap();
		assert_eq!(decoded.op(), None);
		assert_eq!(decoded.body_length, 4, "body is still skippable");
		assert_eq!(decoded.request_id, 7, "so the peer can still be answered");
	}

	#[test]
	fn oversized_body_is_rejected_before_allocating() {
		let header = Header {
			op: Op::Hello.value(),
			sub_op: 0,
			request_id: 1,
			body_length: MAX_BODY + 1,
		};

		assert_eq!(
			Header::decode(&header.encode()),
			Err(DecodeError::BodyTooLarge {
				length: MAX_BODY + 1,
				limit: MAX_BODY,
			})
		);
	}

	#[test]
	fn short_header_is_an_error() {
		assert!(Header::decode(&[0x01, 0x02]).is_err());
	}
}
