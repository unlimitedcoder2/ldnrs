use crate::wlan::MacAddress;

use super::bytes::{DecodeError, Reader};
use super::writer::{EncodeError, Writer};

pub trait WireWrite {
	/// # Errors
	/// [`EncodeError`] if a field is too long for its wire representation.
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError>;

	/// # Errors
	/// [`EncodeError`] if a field is too long for its wire representation.
	fn encode(&self) -> Result<Vec<u8>, EncodeError> {
		let mut writer = Writer::new();
		self.put(&mut writer)?;
		Ok(writer.into_vec())
	}
}

pub trait WireRead: Sized {
	/// # Errors
	/// [`DecodeError`] if the next value is truncated or malformed.
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError>;

	/// # Errors
	/// [`DecodeError`] if the body is truncated, malformed, or contains trailing bytes.
	fn decode(body: &[u8]) -> Result<Self, DecodeError> {
		let mut reader = Reader::new(body);
		let value = Self::get(&mut reader)?;

		expect_end(&reader)?;
		Ok(value)
	}
}

const fn expect_end(reader: &Reader<'_>) -> Result<(), DecodeError> {
	if reader.is_empty() {
		Ok(())
	} else {
		Err(DecodeError::TrailingBytes {
			count: reader.remaining(),
		})
	}
}

impl WireWrite for u8 {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u8(*self);
		Ok(())
	}
}

impl WireRead for u8 {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.u8()
	}
}

impl WireWrite for u16 {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u16_le(*self);
		Ok(())
	}
}

impl WireRead for u16 {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.u16_le()
	}
}

impl WireWrite for u32 {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u32_le(*self);
		Ok(())
	}
}

impl WireRead for u32 {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.u32_le()
	}
}

impl WireWrite for u64 {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u64_le(*self);
		Ok(())
	}
}

impl WireRead for u64 {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.u64_le()
	}
}

fn flag(reader: &mut Reader<'_>) -> Result<bool, DecodeError> {
	match reader.u8()? {
		0 => Ok(false),
		1 => Ok(true),
		value => Err(DecodeError::BadFlag { value }),
	}
}

impl WireWrite for bool {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.u8(u8::from(*self));
		Ok(())
	}
}

impl WireRead for bool {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		flag(reader)
	}
}

impl<const N: usize> WireWrite for [u8; N] {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		writer.slice(self);
		Ok(())
	}
}

impl<const N: usize> WireRead for [u8; N] {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		reader.array()
	}
}

impl WireWrite for MacAddress {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		self.octets().put(writer)
	}
}

impl WireRead for MacAddress {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self(WireRead::get(reader)?))
	}
}

fn put_length(writer: &mut Writer, length: usize) -> Result<(), EncodeError> {
	let length = u32::try_from(length).map_err(|_| EncodeError::FieldTooLong { length })?;
	writer.u32_le(length);

	Ok(())
}

fn get_length(reader: &mut Reader<'_>) -> Result<usize, DecodeError> {
	let length = reader.u32_le()?;
	usize::try_from(length).map_err(|_| DecodeError::UnexpectedEof {
		wanted: usize::MAX,
		got: reader.remaining(),
	})
}

impl<T: WireWrite> WireWrite for Vec<T> {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		put_length(writer, self.len())?;

		for item in self {
			item.put(writer)?;
		}

		Ok(())
	}
}

impl<T: WireRead> WireRead for Vec<T> {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let count = get_length(reader)?;

		// Not `with_capacity(count)`: the count is the peer's claim, and every element takes at
		// least a byte, so a lying count runs out of input long before it runs out of memory.
		let mut items = Self::new();
		for _ in 0..count {
			items.push(T::get(reader)?);
		}

		Ok(items)
	}
}

impl WireWrite for String {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		put_length(writer, self.len())?;
		writer.slice(self.as_bytes());

		Ok(())
	}
}

impl WireRead for String {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		let length = get_length(reader)?;
		let bytes = reader.take(length)?;

		core::str::from_utf8(bytes)
			.map(ToOwned::to_owned)
			.map_err(|_| DecodeError::BadUtf8)
	}
}

impl<T: WireWrite> WireWrite for Option<T> {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		match self {
			None => writer.u8(0),
			Some(value) => {
				writer.u8(1);
				value.put(writer)?;
			}
		}

		Ok(())
	}
}

impl<T: WireRead> WireRead for Option<T> {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		if flag(reader)? {
			Ok(Some(T::get(reader)?))
		} else {
			Ok(None)
		}
	}
}

impl<T: WireWrite> WireWrite for Box<T> {
	fn put(&self, writer: &mut Writer) -> Result<(), EncodeError> {
		(**self).put(writer)
	}
}

impl<T: WireRead> WireRead for Box<T> {
	fn get(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
		Ok(Self::new(T::get(reader)?))
	}
}
