//! Fixed-size identity types: device id, public key, signature, challenge nonce.
//!
//! This module holds sizes and encodings only. Hashing and signing live in `core`.

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::marker::PhantomData;

/// Length of a device id in bytes.
pub const DEVICE_ID_LEN: usize = 16;
/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Length of the registration challenge in bytes.
pub const CHALLENGE_LEN: usize = 32;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Length of the base32 text form of a device id (128 bits, no padding).
pub const DEVICE_ID_TEXT_LEN: usize = 26;

/// Fixed-size byte array that serializes as a tuple, so any length works with serde.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for Bytes<N> {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		let mut t = s.serialize_tuple(N)?;
		for b in &self.0 {
			t.serialize_element(b)?;
		}
		t.end()
	}
}

impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		struct V<const N: usize>(PhantomData<[u8; N]>);
		impl<'de, const N: usize> Visitor<'de> for V<N> {
			type Value = Bytes<N>;
			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "{N} bytes")
			}
			fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Bytes<N>, A::Error> {
				let mut out = [0u8; N];
				for (i, slot) in out.iter_mut().enumerate() {
					*slot = seq
						.next_element()?
						.ok_or_else(|| de::Error::invalid_length(i, &self))?;
				}
				Ok(Bytes(out))
			}
		}
		d.deserialize_tuple(N, V::<N>(PhantomData))
	}
}

/// Ed25519 public key.
pub type PublicKey = Bytes<PUBLIC_KEY_LEN>;
/// Ed25519 signature.
pub type Signature = Bytes<SIGNATURE_LEN>;
/// Random challenge issued by the relay.
pub type Challenge = Bytes<CHALLENGE_LEN>;

impl<const N: usize> fmt::Debug for Bytes<N> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Bytes<{N}>(..)")
	}
}

/// A device id: the first 16 bytes of SHA-256 of the device's Ed25519 public key.
///
/// Text form is lowercase base32 without padding, 26 characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; DEVICE_ID_LEN]);

impl DeviceId {
	/// Parses the base32 text form. Accepts upper case.
	pub fn parse(text: &str) -> Option<Self> {
		if text.len() != DEVICE_ID_TEXT_LEN {
			return None;
		}
		let mut out = [0u8; DEVICE_ID_LEN];
		let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
		for c in text.bytes() {
			let v = match c.to_ascii_lowercase() {
				c @ b'a'..=b'z' => c - b'a',
				c @ b'2'..=b'7' => c - b'2' + 26,
				_ => return None,
			};
			acc = (acc << 5) | u32::from(v);
			bits += 5;
			if bits >= 8 {
				bits -= 8;
				if n < DEVICE_ID_LEN {
					out[n] = (acc >> bits) as u8;
					n += 1;
				}
				acc &= (1 << bits) - 1;
			}
		}
		// 26 chars carry 130 bits; the 2 trailing bits must be zero (canonical form).
		if acc != 0 {
			return None;
		}
		Some(Self(out))
	}
}

impl fmt::Display for DeviceId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let mut text = String::with_capacity(DEVICE_ID_TEXT_LEN);
		let (mut acc, mut bits) = (0u32, 0u32);
		for b in self.0 {
			acc = (acc << 8) | u32::from(b);
			bits += 8;
			while bits >= 5 {
				bits -= 5;
				text.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
			}
			acc &= (1 << bits) - 1;
		}
		// 128 bits leave 3 over; pad them with zero bits to a full character.
		text.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
		f.write_str(&text)
	}
}

impl fmt::Debug for DeviceId {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "DeviceId({self})")
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn base32_known_answers() {
		// RFC 4648 vectors, lowercase and unpadded, for the 16 byte case.
		assert_eq!(DeviceId([0; 16]).to_string(), "a".repeat(26));
		assert_eq!(
			DeviceId([0xff; 16]).to_string(),
			format!("{}4", "7".repeat(25))
		);
		let id = DeviceId(*b"foobarfoobarfoob");
		assert_eq!(id.to_string(), "mzxw6ytbojtg633cmfzgm33pmi");
	}

	#[test]
	fn text_roundtrip_and_case() {
		for seed in 0..=255u8 {
			let id = DeviceId([seed; 16]);
			let text = id.to_string();
			assert_eq!(text.len(), DEVICE_ID_TEXT_LEN);
			assert_eq!(DeviceId::parse(&text), Some(id));
			assert_eq!(DeviceId::parse(&text.to_uppercase()), Some(id));
		}
		assert!(format!("{:?}", DeviceId([0; 16])).starts_with("DeviceId(aaaa"));
	}

	#[test]
	fn parse_rejects_bad_input() {
		assert_eq!(DeviceId::parse(""), None);
		assert_eq!(DeviceId::parse(&"a".repeat(25)), None);
		assert_eq!(DeviceId::parse(&"a".repeat(27)), None);
		assert_eq!(DeviceId::parse(&format!("{}1", "a".repeat(25))), None);
		assert_eq!(DeviceId::parse(&format!("{}!", "a".repeat(25))), None);
		// Non-canonical trailing bits.
		assert_eq!(DeviceId::parse(&format!("{}b", "a".repeat(25))), None);
	}

	#[test]
	fn bytes_serde_and_debug() {
		let k: PublicKey = Bytes([7; 32]);
		let enc = bincode::serialize(&k).unwrap();
		assert_eq!(enc.len(), 32);
		assert_eq!(bincode::deserialize::<PublicKey>(&enc).unwrap(), k);
		assert!(bincode::deserialize::<PublicKey>(&enc[..31]).is_err());
		assert_eq!(format!("{k:?}"), "Bytes<32>(..)");
		// bincode reports short input as an io error, so reach the visitor with a short sequence.
		use serde::de::value::{Error, SeqDeserializer};
		let short = SeqDeserializer::<_, Error>::new(vec![1u8; 3].into_iter());
		let err = PublicKey::deserialize(short).unwrap_err();
		assert!(err.to_string().contains("32 bytes"), "{err}");
		let id = DeviceId([5; 16]);
		let enc = bincode::serialize(&id).unwrap();
		assert_eq!(enc, vec![5; 16]);
		assert_eq!(bincode::deserialize::<DeviceId>(&enc).unwrap(), id);
	}
}
