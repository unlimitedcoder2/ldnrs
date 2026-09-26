use compio::buf::{BufResult, IntoInner, IoBuf};
use compio::fs::named_pipe::NamedPipeServer;
use compio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use ldn::protocol::{FRAME_HEADER_LEN, Header};

#[derive(Debug, Clone)]
pub struct Frame {
	pub header: Header,
	pub body: Vec<u8>,
}

pub async fn read_frame(
	pipe: &NamedPipeServer,
	mut body: Vec<u8>,
) -> std::io::Result<Option<Frame>> {
	let mut reader = pipe;

	let BufResult(result, header_buf) = reader.read([0u8; FRAME_HEADER_LEN]).await;
	let got = result?;

	if got == 0 {
		return Ok(None);
	}

	let header_buf = if got < FRAME_HEADER_LEN {
		let BufResult(result, rest) = reader.read_exact(header_buf.slice(got..)).await;
		result?;
		rest.into_inner()
	} else {
		header_buf
	};

	let header = Header::decode(&header_buf)
		.map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

	let wanted = usize::try_from(header.body_length).map_err(|_| {
		std::io::Error::new(std::io::ErrorKind::InvalidData, "body length overflow")
	})?;

	body.resize(wanted, 0);
	if wanted != 0 {
		let BufResult(result, buf) = reader.read_exact(body.slice(..wanted)).await;
		result?;
		body = buf.into_inner();
	}

	Ok(Some(Frame { header, body }))
}

pub async fn write_frame(pipe: &NamedPipeServer, bytes: Vec<u8>) -> std::io::Result<()> {
	let mut writer = pipe;
	let BufResult(result, _) = writer.write_all(bytes).await;
	result
}
