use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};

use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
	ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
	PIPE_UNLIMITED_INSTANCES, PeekNamedPipe,
};
use windows::core::PCWSTR;

pub(super) struct Pipe(File);

impl Pipe {
	pub(super) fn create(name: &str, first: bool) -> io::Result<Self> {
		let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
		let mut flags = PIPE_ACCESS_DUPLEX;
		if first {
			flags |= FILE_FLAG_FIRST_PIPE_INSTANCE;
		}
		// Synchronous calls return immediately; the server retains partial reads and writes.
		let handle = unsafe {
			CreateNamedPipeW(
				PCWSTR(name.as_ptr()),
				flags,
				PIPE_TYPE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
				PIPE_UNLIMITED_INSTANCES,
				65536,
				65536,
				0,
				None,
			)
		};
		if handle.is_invalid() {
			return Err(io::Error::last_os_error());
		}
		// CreateNamedPipe transfers ownership of this handle to the file.
		Ok(Self(unsafe { File::from_raw_handle(handle.0) }))
	}

	pub(super) fn accept(&self) -> io::Result<bool> {
		match unsafe { ConnectNamedPipe(HANDLE(self.0.as_raw_handle()), None) } {
			// In NOWAIT mode success means the instance has started listening.
			Ok(()) => Ok(false),
			Err(err) if err.code() == ERROR_PIPE_CONNECTED.to_hresult() => Ok(true),
			Err(err) if err.code() == ERROR_PIPE_LISTENING.to_hresult() => Ok(false),
			Err(err) => Err(io::Error::from_raw_os_error(err.code().0 & 0xffff)),
		}
	}
}

impl Read for Pipe {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		if buffer.is_empty() {
			return Ok(0);
		}
		let mut available = 0;
		// std::fs::File maps ERROR_NO_DATA to EOF, so check availability before reading.
		unsafe {
			PeekNamedPipe(
				HANDLE(self.0.as_raw_handle()),
				None,
				0,
				None,
				Some(&raw mut available),
				None,
			)
		}
		.map_err(|err| io::Error::from_raw_os_error(err.code().0 & 0xffff))?;
		if available == 0 {
			return Err(io::ErrorKind::WouldBlock.into());
		}
		self.0.read(buffer)
	}
}

impl Write for Pipe {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
