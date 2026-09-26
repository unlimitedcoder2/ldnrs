use std::io::Read;

use ldn::protocol::{FRAME_HEADER_LEN, Header};

#[derive(Debug, Clone)]
pub struct Frame {
	pub header: Header,
	pub body: Vec<u8>,
}

/// Retains partial headers and bodies when a nonblocking read would block.
#[derive(Default)]
pub(super) struct FrameReader {
	header: Option<Header>,
	bytes: Vec<u8>,
}

impl FrameReader {
	pub(super) fn read(&mut self, reader: &mut impl Read) -> std::io::Result<Option<Frame>> {
		loop {
			let wanted = self
				.header
				.as_ref()
				.map_or(Ok(FRAME_HEADER_LEN), |header| {
					usize::try_from(header.body_length).map_err(|_| {
						std::io::Error::new(std::io::ErrorKind::InvalidData, "body length overflow")
					})
				})?;
			if self.bytes.len() == wanted {
				if let Some(header) = self.header.take() {
					return Ok(Some(Frame {
						header,
						body: std::mem::take(&mut self.bytes),
					}));
				}
				self.header =
					Some(Header::decode(&self.bytes).map_err(|err| {
						std::io::Error::new(std::io::ErrorKind::InvalidData, err)
					})?);
				self.bytes.clear();
				continue;
			}
			let mut buffer = [0; 8192];
			let length = (wanted - self.bytes.len()).min(buffer.len());
			let target = buffer.get_mut(..length).unwrap_or_default();
			match reader.read(target) {
				Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
				Ok(read) => self
					.bytes
					.extend_from_slice(target.get(..read).unwrap_or_default()),
				Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
				Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
				Err(err) => return Err(err),
			}
		}
	}
}
