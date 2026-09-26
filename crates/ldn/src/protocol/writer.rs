use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
	/// A field was longer than a `u32` length can describe.
	FieldTooLong { length: usize },
}

impl fmt::Display for EncodeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FieldTooLong { length } => {
				write!(f, "a field of {length} bytes is too long to encode")
			}
		}
	}
}

impl core::error::Error for EncodeError {}

#[derive(Debug, Default)]
pub struct Writer {
	buf: Vec<u8>,
}

impl Writer {
	#[must_use]
	pub const fn new() -> Self {
		Self { buf: Vec::new() }
	}

	#[must_use]
	pub fn with_capacity(capacity: usize) -> Self {
		Self {
			buf: Vec::with_capacity(capacity),
		}
	}

	#[must_use]
	pub fn into_vec(self) -> Vec<u8> {
		self.buf
	}

	pub fn u8(&mut self, value: u8) {
		self.buf.push(value);
	}

	pub fn u16_le(&mut self, value: u16) {
		self.buf.extend_from_slice(&value.to_le_bytes());
	}

	pub fn u32_le(&mut self, value: u32) {
		self.buf.extend_from_slice(&value.to_le_bytes());
	}

	pub fn u64_le(&mut self, value: u64) {
		self.buf.extend_from_slice(&value.to_le_bytes());
	}

	pub fn u16_be(&mut self, value: u16) {
		self.buf.extend_from_slice(&value.to_be_bytes());
	}

	pub fn u24_be(&mut self, value: u32) {
		let [_, a, b, c] = value.to_be_bytes();
		self.buf.extend_from_slice(&[a, b, c]);
	}

	pub fn u32_be(&mut self, value: u32) {
		self.buf.extend_from_slice(&value.to_be_bytes());
	}

	pub fn u64_be(&mut self, value: u64) {
		self.buf.extend_from_slice(&value.to_be_bytes());
	}

	pub fn pad(&mut self, n: usize) {
		self.buf.resize(self.buf.len() + n, 0);
	}

	pub fn slice(&mut self, value: &[u8]) {
		self.buf.extend_from_slice(value);
	}
}
