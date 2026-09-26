use std::ffi::c_void;
use std::io::{self, Read};
use std::ptr::{NonNull, null, null_mut};

use windows::Win32::Networking::WinHttp::{
	ERROR_WINHTTP_HEADER_NOT_FOUND, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE,
	WINHTTP_OPEN_REQUEST_FLAGS, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_FLAG_NUMBER,
	WINHTTP_QUERY_FLAG_NUMBER64, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
	WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
	WinHttpSendRequest, WinHttpSetTimeouts,
};
use windows::core::{HRESULT, HSTRING, PCWSTR, w};

const TIMEOUT_MS: i32 = 120_000;

struct Handle(NonNull<c_void>);

impl Handle {
	fn new(raw: *mut c_void) -> io::Result<Self> {
		NonNull::new(raw)
			.map(Self)
			.ok_or_else(io::Error::last_os_error)
	}
}

impl Drop for Handle {
	fn drop(&mut self) {
		let _ = unsafe { WinHttpCloseHandle(self.0.as_ptr()) };
	}
}

pub(super) struct Response {
	// Fields drop in declaration order, closing children before their parents.
	request: Handle,
	_connection: Handle,
	_session: Handle,
	status: u32,
	content_length: Option<u64>,
}

impl Response {
	pub(super) fn get(host: &str, path: &str) -> anyhow::Result<Self> {
		Self::open(host, 443, path, WINHTTP_FLAG_SECURE)
	}

	fn open(
		host: &str,
		port: u16,
		path: &str,
		flags: WINHTTP_OPEN_REQUEST_FLAGS,
	) -> anyhow::Result<Self> {
		let host = HSTRING::from(host);
		let path = HSTRING::from(path);
		let session = Handle::new(unsafe {
			WinHttpOpen(
				w!("ldnd"),
				WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
				PCWSTR::null(),
				PCWSTR::null(),
				0,
			)
		})?;
		unsafe {
			WinHttpSetTimeouts(
				session.0.as_ptr(),
				TIMEOUT_MS,
				TIMEOUT_MS,
				TIMEOUT_MS,
				TIMEOUT_MS,
			)
		}?;
		let connection =
			Handle::new(unsafe { WinHttpConnect(session.0.as_ptr(), &host, port, 0) })?;
		let request = Handle::new(unsafe {
			WinHttpOpenRequest(
				connection.0.as_ptr(),
				w!("GET"),
				&path,
				PCWSTR::null(),
				PCWSTR::null(),
				null(),
				flags,
			)
		})?;
		unsafe {
			WinHttpSendRequest(request.0.as_ptr(), None, None, 0, 0, 0)?;
			WinHttpReceiveResponse(request.0.as_ptr(), null_mut())?;
		}

		let mut status = 0u32;
		let mut size = u32::try_from(size_of_val(&status))?;
		unsafe {
			WinHttpQueryHeaders(
				request.0.as_ptr(),
				WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				PCWSTR::null(),
				Some((&raw mut status).cast()),
				&raw mut size,
				null_mut(),
			)?;
		}
		let mut length = 0u64;
		let mut size = u32::try_from(size_of_val(&length))?;
		let content_length = match unsafe {
			WinHttpQueryHeaders(
				request.0.as_ptr(),
				WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER64,
				PCWSTR::null(),
				Some((&raw mut length).cast()),
				&raw mut size,
				null_mut(),
			)
		} {
			Ok(()) => Some(length),
			Err(err) if err.code() == HRESULT::from_win32(ERROR_WINHTTP_HEADER_NOT_FOUND) => None,
			Err(err) => return Err(err.into()),
		};
		Ok(Self {
			request,
			_connection: connection,
			_session: session,
			status,
			content_length,
		})
	}

	pub(super) const fn status(&self) -> u32 {
		self.status
	}

	pub(super) const fn content_length(&self) -> Option<u64> {
		self.content_length
	}
}

impl Read for Response {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		if buffer.is_empty() {
			return Ok(0);
		}
		let mut read = 0;
		// The buffer stays alive until WinHttpReadData returns; no callback retains it.
		unsafe {
			WinHttpReadData(
				self.request.0.as_ptr(),
				buffer.as_mut_ptr().cast(),
				u32::try_from(buffer.len()).unwrap_or(u32::MAX),
				&raw mut read,
			)
		}
		.map_err(|err| io::Error::from_raw_os_error(err.code().0 & 0xffff))?;
		usize::try_from(read).map_err(io::Error::other)
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
	use super::*;
	use std::io::Write;
	use std::net::TcpListener;
	use std::time::{Duration, Instant};

	fn response(replies: &[&[u8]]) -> Response {
		let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
		listener.set_nonblocking(true).unwrap();
		let port = listener.local_addr().unwrap().port();
		std::thread::scope(|scope| {
			let server = scope.spawn(move || {
				for reply in replies {
					let started = Instant::now();
					let mut stream = loop {
						match listener.accept() {
							Ok((stream, _)) => break stream,
							Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
								assert!(
									started.elapsed() < Duration::from_secs(5),
									"HTTP client did not connect"
								);
								std::thread::sleep(Duration::from_millis(1));
							}
							Err(err) => panic!("accept failed: {err}"),
						}
					};
					stream
						.set_read_timeout(Some(Duration::from_secs(2)))
						.unwrap();
					stream
						.set_write_timeout(Some(Duration::from_secs(2)))
						.unwrap();
					let mut request = Vec::new();
					while !request.ends_with(b"\r\n\r\n") {
						let mut byte = [0];
						stream.read_exact(&mut byte).unwrap();
						request.extend(byte);
					}
					assert!(request.starts_with(b"GET /"));
					stream.write_all(reply).unwrap();
				}
			});
			let response = Response::open(
				"127.0.0.1",
				port,
				"/firmware",
				WINHTTP_OPEN_REQUEST_FLAGS(0),
			);
			server.join().unwrap();
			response.unwrap()
		})
	}

	#[test]
	fn reads_binary_response_and_content_length() {
		let mut response = response(&[
			b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n\x00\xff\x01\x80",
		]);
		assert_eq!(response.status(), 200);
		assert_eq!(response.content_length(), Some(4));
		assert_eq!(response.read(&mut []).unwrap(), 0);
		let mut bytes = Vec::new();
		response.read_to_end(&mut bytes).unwrap();
		assert_eq!(bytes, [0, 255, 1, 128]);
	}

	#[test]
	fn reads_chunked_response_without_content_length() {
		let mut response = response(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"]);
		assert_eq!(response.content_length(), None);
		let mut bytes = Vec::new();
		response.read_to_end(&mut bytes).unwrap();
		assert_eq!(bytes, b"abcde");
	}

	#[test]
	fn follows_redirects_and_reports_final_status() {
		let response = response(&[
			b"HTTP/1.1 302 Found\r\nLocation: /missing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		]);
		assert_eq!(response.status(), 404);
		assert_eq!(response.content_length(), Some(0));
	}
}
