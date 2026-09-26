use std::path::Path;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use sha2::{Digest, Sha256};

pub const CHALLENGE_KEY: [u8; 32] = [
	0xf8, 0x4b, 0x48, 0x7f, 0xb3, 0x72, 0x51, 0xc2, 0x63, 0xbf, 0x11, 0x60, 0x90, 0x36, 0x58, 0x92,
	0x66, 0xaf, 0x70, 0xca, 0x79, 0xb4, 0x4c, 0x93, 0xc7, 0x37, 0x0c, 0x57, 0x69, 0xc0, 0xf6, 0x02,
];

pub const CHALLENGE_KEY_DEV: [u8; 32] = [
	0x5a, 0x0f, 0xbf, 0xb5, 0xb5, 0xc5, 0xa2, 0x73, 0x34, 0x39, 0x40, 0x1b, 0x3d, 0x46, 0x93, 0x83,
	0x43, 0xf5, 0xd2, 0xf4, 0x94, 0x22, 0x4a, 0x7c, 0x00, 0x7b, 0x61, 0xea, 0xac, 0xbc, 0x1f, 0x20,
];

const SOURCE_AUTH_DATA: [u8; 16] = [
	0xf1, 0xe7, 0x01, 0x84, 0x19, 0xa8, 0x4f, 0x71, 0x1d, 0xa7, 0x14, 0xc2, 0xcf, 0x91, 0x9c, 0x9c,
];

const SOURCE_ADVERTISE: [u8; 16] = [
	0x19, 0x18, 0x84, 0x74, 0x3e, 0x24, 0xc7, 0x7d, 0x87, 0xc6, 0x9e, 0x42, 0x07, 0xd0, 0xc4, 0x38,
];

pub type Key = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
	UnsupportedProtocol {
		protocol: u8,
	},
	/// No `prod.keys` has been loaded; the daemon started without `--keys` and no
	/// `SetProdKeys` has arrived since.
	NotLoaded,
}

impl core::fmt::Display for KeyError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::UnsupportedProtocol { protocol } => {
				write!(f, "no key derivation for LDN protocol version {protocol}")
			}
			Self::NotLoaded => write!(f, "no prod.keys loaded"),
		}
	}
}

impl core::error::Error for KeyError {}

#[derive(Debug)]
pub enum LoadError {
	Io(std::io::Error),
	Malformed { line: usize },
	Missing { name: &'static str },
	WrongLength { name: String, length: usize },
}

impl core::fmt::Display for LoadError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Io(err) => write!(f, "could not read the keys file: {err}"),
			Self::Malformed { line } => write!(f, "line {line} is not `name = hex`"),
			Self::Missing { name } => write!(f, "prod.keys is missing {name}"),
			Self::WrongLength { name, length } => {
				write!(f, "{name} should be 16 bytes, is {length}")
			}
		}
	}
}

impl core::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
	fn from(err: std::io::Error) -> Self {
		Self::Io(err)
	}
}

#[derive(Debug, Clone, Default)]
pub struct Keys {
	pub master_key_00: Key,
	pub master_key_12: Key,
	pub aes_kek_generation_source: Key,
	pub aes_key_generation_source: Key,
}

impl Keys {
	/// # Errors
	/// [`LoadError::Io`] if the file cannot be read, otherwise as [`Keys::parse`].
	pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
		Self::parse(&std::fs::read_to_string(path)?)
	}

	/// # Errors
	/// [`LoadError::Malformed`] for a line that is not `name = hex`, [`LoadError::WrongLength`]
	/// for a wanted key that is not 16 bytes of hex, and [`LoadError::Missing`] if a required key
	/// is absent.
	pub fn parse(text: &str) -> Result<Self, LoadError> {
		const WANTED_KEYS: &[&str] = &[
			"master_key_00",
			"master_key_12",
			"aes_kek_generation_source",
			"aes_key_generation_source",
		];

		let mut keys = Self::default();

		for (index, raw) in text.lines().enumerate() {
			let line = raw.trim();
			if line.is_empty() {
				continue;
			}

			let line_number = index + 1;
			let (name, value) = line
				.split_once('=')
				.ok_or(LoadError::Malformed { line: line_number })?;

			let name = name.trim();
			if !WANTED_KEYS.contains(&name) {
				continue;
			}

			let value = value.trim();
			let key = decode_hex(value).ok_or_else(|| LoadError::WrongLength {
				name: name.to_string(),
				length: value.len(),
			})?;

			match name {
				"master_key_00" => keys.master_key_00 = key,
				"master_key_12" => keys.master_key_12 = key,
				"aes_kek_generation_source" => keys.aes_kek_generation_source = key,
				"aes_key_generation_source" => keys.aes_key_generation_source = key,
				_ => {}
			}
		}

		if keys.master_key_00.as_slice() == Key::default().as_slice() {
			return Err(LoadError::Missing {
				name: "master_key_00",
			});
		}

		if keys.master_key_12.as_slice() == Key::default().as_slice() {
			return Err(LoadError::Missing {
				name: "master_key_12",
			});
		}

		if keys.aes_kek_generation_source.as_slice() == Key::default().as_slice() {
			return Err(LoadError::Missing {
				name: "aes_kek_generation_source",
			});
		}

		if keys.aes_key_generation_source.as_slice() == Key::default().as_slice() {
			return Err(LoadError::Missing {
				name: "aes_key_generation_source",
			});
		}

		Ok(keys)
	}
}

fn decode_hex(text: &str) -> Option<Key> {
	if !text.len().is_multiple_of(2) {
		return None;
	}

	let bytes = text.as_bytes();
	let mut out = Vec::with_capacity(text.len().checked_div(2)?);

	for pair in bytes.chunks_exact(2) {
		let high = hex_digit(*pair.first()?)?;
		let low = hex_digit(*pair.get(1)?)?;
		out.push(high.checked_mul(16)?.checked_add(low)?);
	}

	out.try_into().ok()
}

const fn hex_digit(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
		b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
		b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
		_ => None,
	}
}

#[derive(Debug, Clone)]
pub struct KeyDerivation {
	master: Key,
	kek_generation_source: Key,
	key_generation_source: Key,
}

impl KeyDerivation {
	/// # Errors
	/// [`KeyError::UnsupportedProtocol`] for any version other than 1 or 3.
	pub const fn new(keys: &Keys, protocol: u8) -> Result<Self, KeyError> {
		let master = match protocol {
			1 => keys.master_key_00,
			3 => keys.master_key_12,
			other => return Err(KeyError::UnsupportedProtocol { protocol: other }),
		};

		Ok(Self {
			master,
			kek_generation_source: keys.aes_kek_generation_source,
			key_generation_source: keys.aes_key_generation_source,
		})
	}

	fn decrypt_block(block: &Key, kek: &Key) -> Key {
		let cipher = Aes128::new(kek.into());
		let mut out = *block;
		cipher.decrypt_block((&mut out).into());
		out
	}

	fn derive(&self, data: &[u8], source: &Key) -> Key {
		let key = Self::decrypt_block(&self.kek_generation_source, &self.master);
		let key = Self::decrypt_block(source, &key);
		let key = Self::decrypt_block(&self.key_generation_source, &key);

		let digest = Sha256::digest(data);
		let mut half = Key::default();
		if let Some(front) = digest.get(..16) {
			half.copy_from_slice(front);
		}

		Self::decrypt_block(&half, &key)
	}

	#[must_use]
	pub fn authentication_key(&self, client_random: &[u8]) -> Key {
		self.derive(client_random, &SOURCE_AUTH_DATA)
	}

	#[must_use]
	pub fn data_key(&self, server_random: &[u8], password: &[u8]) -> Key {
		let mut data = Vec::with_capacity(server_random.len() + password.len());
		data.extend_from_slice(server_random);
		data.extend_from_slice(password);

		self.derive(&data, &SOURCE_AUTH_DATA)
	}

	#[must_use]
	pub fn advertise_key(&self, network_id: &[u8]) -> Key {
		self.derive(network_id, &SOURCE_ADVERTISE)
	}

	#[must_use]
	pub const fn challenge_key(&self, dev: bool) -> [u8; 32] {
		if dev {
			CHALLENGE_KEY_DEV
		} else {
			CHALLENGE_KEY
		}
	}
}

#[cfg(test)]
#[allow(
	clippy::unwrap_used,
	clippy::expect_used,
	clippy::panic,
	clippy::indexing_slicing
)]
mod tests {
	use super::{KeyDerivation, KeyError, Keys};

	/// Not real keys; any 16 distinct bytes exercise the same code path.
	const SAMPLE: &str = "\
		master_key_00 = 000102030405060708090a0b0c0d0e0f\n\
		master_key_12 = 101112131415161718191a1b1c1d1e1f\n\
		aes_kek_generation_source = 202122232425262728292a2b2c2d2e2f\n\
		aes_key_generation_source = 303132333435363738393a3b3c3d3e3f\n\
	";

	#[test]
	fn rejects_a_malformed_line() {
		assert!(Keys::parse("this is not a key line").is_err());
		assert!(Keys::parse("name = nothex!!").is_err());
		assert!(Keys::parse("name = abc").is_err(), "odd digit count");
	}
	#[test]
	fn rejects_an_unsupported_protocol() {
		let keys = Keys::parse(SAMPLE).unwrap();

		assert_eq!(
			KeyDerivation::new(&keys, 2).unwrap_err(),
			KeyError::UnsupportedProtocol { protocol: 2 }
		);
	}

	#[test]
	fn protocol_1_and_3_derive_differently() {
		let keys = Keys::parse(SAMPLE).unwrap();

		let one = KeyDerivation::new(&keys, 1).unwrap();
		let three = KeyDerivation::new(&keys, 3).unwrap();

		assert_ne!(
			one.advertise_key(b"network"),
			three.advertise_key(b"network")
		);
	}

	#[test]
	fn derivation_is_deterministic_and_input_bound() {
		let keys = Keys::parse(SAMPLE).unwrap();
		let derivation = KeyDerivation::new(&keys, 1).unwrap();

		assert_eq!(
			derivation.advertise_key(b"a"),
			derivation.advertise_key(b"a")
		);
		assert_ne!(
			derivation.advertise_key(b"a"),
			derivation.advertise_key(b"b")
		);

		assert_ne!(
			derivation.advertise_key(b"same"),
			derivation.authentication_key(b"same")
		);
	}

	#[test]
	fn the_password_changes_the_data_key() {
		let keys = Keys::parse(SAMPLE).unwrap();
		let derivation = KeyDerivation::new(&keys, 1).unwrap();

		let server_random = [7u8; 16];
		assert_ne!(
			derivation.data_key(&server_random, b""),
			derivation.data_key(&server_random, b"hunter2"),
			"a wrong passphrase must produce a different link key"
		);
	}

	#[test]
	fn challenge_key_selects_retail_or_dev() {
		let keys = Keys::parse(SAMPLE).unwrap();
		let derivation = KeyDerivation::new(&keys, 1).unwrap();

		assert_eq!(derivation.challenge_key(false), super::CHALLENGE_KEY);
		assert_eq!(derivation.challenge_key(true), super::CHALLENGE_KEY_DEV);
	}
}
