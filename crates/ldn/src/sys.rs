use std::ffi::{CStr, CString, c_void};

use crate::generated::{
	LDN_LKL_AF_INET, LDN_LKL_EAGAIN, LDN_LKL_EINTR, LDN_LKL_SOCK_DGRAM, ldn_lkl_add_neighbor,
	ldn_lkl_bind, ldn_lkl_close, ldn_lkl_getsockname, ldn_lkl_if_add_ip, ldn_lkl_if_down,
	ldn_lkl_if_up, ldn_lkl_open_packet, ldn_lkl_recvfrom, ldn_lkl_sendto,
	ldn_lkl_set_recv_timeout_ms, ldn_lkl_sockaddr_in, ldn_lkl_sockaddr_in_parse,
	ldn_lkl_sockaddr_ll, ldn_lkl_socket, ldn_lkl_strerror, ldn_lkl_sysctl,
};

pub const ENETDOWN: i32 = 100;
const SOCKADDR_CAP: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysError {
	raw: i32,
}

impl SysError {
	#[must_use]
	pub const fn from_raw(raw: i32) -> Self {
		Self { raw }
	}

	#[must_use]
	pub const fn errno(&self) -> i32 {
		self.raw.saturating_abs()
	}

	#[must_use]
	pub const fn is_would_block(&self) -> bool {
		self.errno() == LDN_LKL_EAGAIN.cast_signed()
	}

	#[must_use]
	pub const fn is_network_down(&self) -> bool {
		self.errno() == ENETDOWN
	}

	#[must_use]
	pub const fn is_interrupted(&self) -> bool {
		self.errno() == LDN_LKL_EINTR.cast_signed()
	}

	#[must_use]
	pub fn description(&self) -> String {
		let text = unsafe { ldn_lkl_strerror(self.raw) };
		if text.is_null() {
			return format!("errno {}", self.errno());
		}

		unsafe { CStr::from_ptr(text) }
			.to_str()
			.map_or_else(|_| format!("errno {}", self.errno()), ToOwned::to_owned)
	}
}

impl core::fmt::Display for SysError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{} (errno {})", self.description(), self.errno())
	}
}

impl core::error::Error for SysError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelContext(*mut c_void);

impl KernelContext {
	pub(crate) const fn new(raw: *mut c_void) -> Self {
		Self(raw)
	}

	const fn raw(self) -> *mut c_void {
		self.0
	}

	pub(crate) const fn raw_for_ffi(self) -> *mut c_void {
		self.0
	}
}

unsafe impl Send for KernelContext {}
unsafe impl Sync for KernelContext {}

const fn check(value: i32) -> Result<i32, SysError> {
	if value < 0 {
		Err(SysError::from_raw(value))
	} else {
		Ok(value)
	}
}

pub struct Socket {
	ctx: KernelContext,
	fd: i32,
}

unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}

impl Socket {
	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn open_packet(ctx: KernelContext, eth_protocol: u16) -> Result<Self, SysError> {
		let fd = check(unsafe { ldn_lkl_open_packet(ctx.raw(), eth_protocol) })?;

		Ok(Self { ctx, fd })
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn open_udp(ctx: KernelContext) -> Result<Self, SysError> {
		let protocol = i32::try_from(LDN_LKL_SOCK_DGRAM).unwrap_or(2);
		let fd = check(unsafe {
			ldn_lkl_socket(ctx.raw(), LDN_LKL_AF_INET.cast_signed(), protocol, 0)
		})?;
		Ok(Self { ctx, fd })
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn bind_in(&self, address: [u8; 4], port: u16) -> Result<(), SysError> {
		let mut sockaddr = [0u8; SOCKADDR_CAP];
		let host_order = u32::from_be_bytes(address);

		let len = check(unsafe {
			ldn_lkl_sockaddr_in(
				sockaddr.as_mut_ptr().cast::<c_void>(),
				i32::try_from(SOCKADDR_CAP).unwrap_or(0),
				host_order,
				port,
			)
		})?;

		self.bind(&sockaddr, len)
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn bind_packet(&self, eth_protocol: u16, ifindex: i32) -> Result<(), SysError> {
		let mut address = [0u8; SOCKADDR_CAP];

		let len = check(unsafe {
			ldn_lkl_sockaddr_ll(
				address.as_mut_ptr().cast::<c_void>(),
				i32::try_from(SOCKADDR_CAP).unwrap_or(0),
				eth_protocol,
				ifindex,
			)
		})?;

		self.bind(&address, len)
	}

	fn bind(&self, address: &[u8], len: i32) -> Result<(), SysError> {
		check(unsafe {
			ldn_lkl_bind(
				self.ctx.raw(),
				self.fd,
				address.as_ptr().cast::<c_void>(),
				len,
			)
		})?;

		Ok(())
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn set_recv_timeout_ms(&self, timeout_ms: u32) -> Result<(), SysError> {
		check(unsafe { ldn_lkl_set_recv_timeout_ms(self.ctx.raw(), self.fd, timeout_ms) })?;
		Ok(())
	}

	/// # Errors
	/// The kernel's errno if the call fails, `EINVAL` if `data` is too long, or `EIO` for a
	/// short write.
	pub fn send(&self, data: &[u8]) -> Result<(), SysError> {
		let len = i32::try_from(data.len()).map_err(|_| SysError::from_raw(-22))?;

		let sent = unsafe {
			ldn_lkl_sendto(
				self.ctx.raw(),
				self.fd,
				data.as_ptr().cast::<c_void>(),
				len,
				0,
				core::ptr::null(),
				0,
			)
		};

		if sent < 0 {
			return Err(SysError::from_raw(i32::try_from(sent).unwrap_or(-1)));
		}

		if sent != i64::from(len) {
			return Err(SysError::from_raw(-5));
		}

		Ok(())
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn send_to(&self, data: &[u8], address: [u8; 4], port: u16) -> Result<(), SysError> {
		let len = i32::try_from(data.len()).map_err(|_| SysError::from_raw(-22))?;

		let mut sockaddr = [0u8; SOCKADDR_CAP];
		let host_order = u32::from_be_bytes(address);

		let addrlen = check(unsafe {
			ldn_lkl_sockaddr_in(
				sockaddr.as_mut_ptr().cast::<c_void>(),
				i32::try_from(SOCKADDR_CAP).unwrap_or(0),
				host_order,
				port,
			)
		})?;

		let sent = unsafe {
			ldn_lkl_sendto(
				self.ctx.raw(),
				self.fd,
				data.as_ptr().cast::<c_void>(),
				len,
				0,
				sockaddr.as_ptr().cast::<c_void>(),
				addrlen,
			)
		};

		if sent < 0 {
			return Err(SysError::from_raw(i32::try_from(sent).unwrap_or(-1)));
		}

		if sent != i64::from(len) {
			return Err(SysError::from_raw(-5));
		}

		Ok(())
	}

	/// # Errors
	/// The kernel's errno if the call fails.
	pub fn local_port(&self) -> Result<u16, SysError> {
		let mut sockaddr = [0u8; SOCKADDR_CAP];
		let mut addrlen = i32::try_from(SOCKADDR_CAP).unwrap_or(0);

		check(unsafe {
			ldn_lkl_getsockname(
				self.ctx.raw(),
				self.fd,
				sockaddr.as_mut_ptr().cast::<c_void>(),
				&raw mut addrlen,
			)
		})?;

		let mut port = 0u16;

		check(unsafe {
			ldn_lkl_sockaddr_in_parse(
				sockaddr.as_ptr().cast::<c_void>(),
				addrlen,
				core::ptr::null_mut(),
				&raw mut port,
			)
		})?;

		Ok(port)
	}

	/// # Errors
	/// The kernel's errno if the call fails, or `EINVAL` if the buffer is too long for one call.
	pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, SysError> {
		let len = i32::try_from(buffer.len()).map_err(|_| SysError::from_raw(-22))?;
		let got = unsafe {
			ldn_lkl_recvfrom(
				self.ctx.raw(),
				self.fd,
				buffer.as_mut_ptr().cast::<c_void>(),
				len,
				0,
				core::ptr::null_mut(),
				core::ptr::null_mut(),
			)
		};

		if got < 0 {
			return Err(SysError::from_raw(i32::try_from(got).unwrap_or(-1)));
		}

		Ok(usize::try_from(got).unwrap_or(0))
	}

	/// # Errors
	/// The kernel's errno if the call fails, or `EINVAL` if the buffer is too long for one call.
	pub fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, [u8; 4], u16), SysError> {
		let len = i32::try_from(buffer.len()).map_err(|_| SysError::from_raw(-22))?;

		let mut sockaddr = [0u8; SOCKADDR_CAP];
		let mut addrlen = i32::try_from(SOCKADDR_CAP).unwrap_or(0);

		let got = unsafe {
			ldn_lkl_recvfrom(
				self.ctx.raw(),
				self.fd,
				buffer.as_mut_ptr().cast::<c_void>(),
				len,
				0,
				sockaddr.as_mut_ptr().cast::<c_void>(),
				&raw mut addrlen,
			)
		};

		if got < 0 {
			return Err(SysError::from_raw(i32::try_from(got).unwrap_or(-1)));
		}

		let mut address = 0u32;
		let mut port = 0u16;

		check(unsafe {
			ldn_lkl_sockaddr_in_parse(
				sockaddr.as_ptr().cast::<c_void>(),
				addrlen,
				&raw mut address,
				&raw mut port,
			)
		})?;

		Ok((
			usize::try_from(got).unwrap_or(0),
			address.to_be_bytes(),
			port,
		))
	}
}

impl Drop for Socket {
	fn drop(&mut self) {
		let _ = unsafe { ldn_lkl_close(self.ctx.raw(), self.fd) };
	}
}

/// # Errors
/// The kernel's errno if the call fails.
pub fn if_add_ip(
	ctx: KernelContext,
	ifindex: i32,
	address: [u8; 4],
	prefix_len: u32,
) -> Result<(), SysError> {
	check(unsafe {
		ldn_lkl_if_add_ip(
			ctx.raw(),
			ifindex,
			LDN_LKL_AF_INET.cast_signed(),
			address.as_ptr().cast::<c_void>(),
			prefix_len,
		)
	})?;

	Ok(())
}

/// # Errors
/// The kernel's errno if the call fails.
pub fn add_neighbor(
	ctx: KernelContext,
	ifindex: i32,
	address: [u8; 4],
	mac: [u8; 6],
) -> Result<(), SysError> {
	check(unsafe {
		ldn_lkl_add_neighbor(
			ctx.raw(),
			ifindex,
			LDN_LKL_AF_INET.cast_signed(),
			address.as_ptr().cast::<c_void>(),
			mac.as_ptr().cast::<c_void>(),
		)
	})?;

	Ok(())
}

/// # Errors
/// The kernel's errno if the call fails, or `EINVAL` if either contains a NUL.
pub fn sysctl(ctx: KernelContext, path: &str, value: &str) -> Result<(), SysError> {
	let path = CString::new(path).map_err(|_| SysError::from_raw(-22))?;
	let value = CString::new(value).map_err(|_| SysError::from_raw(-22))?;

	check(unsafe { ldn_lkl_sysctl(ctx.raw(), path.as_ptr(), value.as_ptr()) })?;

	Ok(())
}

/// # Errors
/// The kernel's errno if the call fails.
pub fn if_up(ctx: KernelContext, ifindex: i32) -> Result<(), SysError> {
	check(unsafe { ldn_lkl_if_up(ctx.raw_for_ffi(), ifindex) })?;

	Ok(())
}

/// # Errors
/// The kernel's errno if the call fails.
pub fn if_down(ctx: KernelContext, ifindex: i32) -> Result<(), SysError> {
	check(unsafe { ldn_lkl_if_down(ctx.raw_for_ffi(), ifindex) })?;

	Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
	use crate::generated::LDN_LKL_EAGAIN;

	use super::SysError;

	#[test]
	fn errnos_are_reported_positive_however_they_arrive() {
		assert_eq!(SysError::from_raw(-22).errno(), 22);
		assert_eq!(SysError::from_raw(22).errno(), 22);
	}

	#[test]
	fn a_timeout_is_told_apart_from_a_failure() {
		assert!(SysError::from_raw(-LDN_LKL_EAGAIN.cast_signed()).is_would_block());
		assert!(!SysError::from_raw(-22).is_would_block());
		assert!(SysError::from_raw(-4).is_interrupted());
	}

	#[test]
	fn an_error_renders_with_its_number() {
		let text = SysError::from_raw(-22).to_string();
		assert!(text.contains("22"), "got {text}");
	}
}
