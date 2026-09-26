#![allow(
	clippy::indexing_slicing,
	reason = "only into fixed-size arrays, where the bound is a constant"
)]

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
	UnexpectedEof {
		wanted: usize,
		got: usize,
	},
	TruncatedTlv,
	BadFieldLength {
		tag: u16,
		expected: usize,
		got: usize,
	},
	BadUtf8,
	/// A `bool` or an `Option` flag was neither 0 nor 1.
	BadFlag {
		value: u8,
	},
	TrailingBytes {
		count: usize,
	},
	BodyTooLarge {
		length: u32,
		limit: u32,
	},
	InvalidVariant {
		enum_name: &'static str,
		val: usize,
	},
}

impl fmt::Display for DecodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnexpectedEof { wanted, got } => {
				write!(
					f,
					"unexpected end of input: wanted {wanted} bytes, {got} left"
				)
			}
			Self::TruncatedTlv => write!(f, "an element ran past the end of the frame"),
			Self::BadFieldLength { tag, expected, got } => write!(
				f,
				"element {tag:#06x} should carry {expected} bytes, carried {got}"
			),
			Self::BadUtf8 => write!(f, "a string is not valid UTF-8"),
			Self::BadFlag { value } => write!(f, "a flag byte is {value}, not 0 or 1"),
			Self::TrailingBytes { count } => {
				write!(f, "{count} bytes left over after the last field")
			}
			Self::BodyTooLarge { length, limit } => {
				write!(f, "body of {length} bytes exceeds the {limit} byte limit")
			}
			Self::InvalidVariant { enum_name, val } => {
				write!(f, "invalid enum variant {val} of enum {enum_name}")
			}
		}
	}
}

impl core::error::Error for DecodeError {}

pub struct Reader<'a> {
	data: &'a [u8],
}

impl<'a> Reader<'a> {
	#[must_use]
	pub const fn new(data: &'a [u8]) -> Self {
		Self { data }
	}

	#[must_use]
	pub const fn remaining(&self) -> usize {
		self.data.len()
	}

	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.data.is_empty()
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than `n` bytes remain.
	pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
		let (head, tail) = self
			.data
			.split_at_checked(n)
			.ok_or(DecodeError::UnexpectedEof {
				wanted: n,
				got: self.data.len(),
			})?;

		self.data = tail;
		Ok(head)
	}

	pub fn take_rest(&mut self) -> &'a [u8] {
		core::mem::take(&mut self.data)
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] at the end of the buffer.
	pub fn u8(&mut self) -> Result<u8, DecodeError> {
		let [value] = self.array()?;
		Ok(value)
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than two bytes remain.
	pub fn u16_le(&mut self) -> Result<u16, DecodeError> {
		Ok(u16::from_le_bytes(self.array()?))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than four bytes remain.
	pub fn u32_le(&mut self) -> Result<u32, DecodeError> {
		Ok(u32::from_le_bytes(self.array()?))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than eight bytes remain.
	pub fn u64_le(&mut self) -> Result<u64, DecodeError> {
		Ok(u64::from_le_bytes(self.array()?))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than `n` bytes remain.
	pub fn skip(&mut self, n: usize) -> Result<(), DecodeError> {
		self.take(n)?;
		Ok(())
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than two bytes remain.
	pub fn u16_be(&mut self) -> Result<u16, DecodeError> {
		Ok(u16::from_be_bytes(self.array()?))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than three bytes remain.
	pub fn u24_be(&mut self) -> Result<u32, DecodeError> {
		let bytes: [u8; 3] = self.array()?;
		Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than four bytes remain.
	pub fn u32_be(&mut self) -> Result<u32, DecodeError> {
		Ok(u32::from_be_bytes(self.array()?))
	}

	/// # Errors
	/// [`DecodeError::UnexpectedEof`] if fewer than eight bytes remain.
	pub fn u64_be(&mut self) -> Result<u64, DecodeError> {
		Ok(u64::from_be_bytes(self.array()?))
	}

	pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
		let bytes = self.take(N)?;
		<[u8; N]>::try_from(bytes).map_err(|_| DecodeError::UnexpectedEof {
			wanted: N,
			got: bytes.len(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{DecodeError, Reader};

	#[test]
	fn reads_little_endian_values() {
		let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		let mut reader = Reader::new(&data);

		assert_eq!(reader.u8(), Ok(0x01));
		assert_eq!(reader.u16_le(), Ok(0x0302));
		assert_eq!(reader.u32_le(), Ok(0x0706_0504));
		assert!(reader.is_empty());
	}

	#[test]
	fn short_input_is_an_error_not_a_panic() {
		let data = [0x01, 0x02];
		let mut reader = Reader::new(&data);

		assert_eq!(
			reader.u32_le(),
			Err(DecodeError::UnexpectedEof { wanted: 4, got: 2 })
		);
	}

	#[test]
	fn take_rest_drains() {
		let data = [1, 2, 3];
		let mut reader = Reader::new(&data);

		assert_eq!(reader.u8(), Ok(1));
		assert_eq!(reader.take_rest(), &[2, 3]);
		assert_eq!(reader.remaining(), 0);
	}
}
