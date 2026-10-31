//! Kabuk wire protocol.
//!
//! Every message on any path (LAN, P2P, relay, bridge) travels inside an [`Envelope`].
//! The payload is opaque here: relays and bridges only read the version and the kind,
//! never the contents.

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible wire change.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest encoded envelope, in bytes. Keeps one envelope inside a safe datagram size.
pub const MAX_ENVELOPE_LEN: usize = 1400;

/// Which part of the system owns a message kind.
///
/// Kinds are partitioned into fixed ranges so that new messages never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
	/// Device to device traffic handled by `core`.
	Core,
	/// Rendezvous and forwarding handled by `relay`.
	Relay,
	/// Byte bridging handled by `bridge`.
	Bridge,
	/// Reserved for the closed enterprise servers.
	Enterprise,
	/// Not allocated yet.
	Unassigned,
}

/// First and last kind of the core range.
pub const CORE_RANGE: (u16, u16) = (0x0000, 0x0FFF);
/// First and last kind of the relay range.
pub const RELAY_RANGE: (u16, u16) = (0x1000, 0x1FFF);
/// First and last kind of the bridge range.
pub const BRIDGE_RANGE: (u16, u16) = (0x2000, 0x2FFF);
/// First and last kind of the enterprise range.
pub const ENTERPRISE_RANGE: (u16, u16) = (0xF000, 0xFFFF);

/// Returns the range a message kind belongs to.
pub fn range_of(kind: u16) -> Range {
	match kind {
		0x0000..=0x0FFF => Range::Core,
		0x1000..=0x1FFF => Range::Relay,
		0x2000..=0x2FFF => Range::Bridge,
		0xF000..=0xFFFF => Range::Enterprise,
		_ => Range::Unassigned,
	}
}

/// Why an envelope could not be decoded or encoded.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// The bytes are not a valid envelope.
	Malformed,
	/// The sender speaks another protocol version.
	VersionMismatch {
		/// Version found on the wire.
		got: u16,
	},
	/// The encoded envelope would exceed [`MAX_ENVELOPE_LEN`].
	TooLarge,
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Malformed => write!(f, "malformed envelope"),
			Error::VersionMismatch { got } => {
				write!(
					f,
					"protocol version {got} not supported (expected {PROTOCOL_VERSION})"
				)
			}
			Error::TooLarge => write!(f, "envelope too large"),
		}
	}
}

impl std::error::Error for Error {}

/// A versioned message container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
	/// Protocol version of the sender.
	pub version: u16,
	/// Message kind, see the range constants.
	pub kind: u16,
	/// Opaque payload, already encrypted where the path requires it.
	pub payload: Vec<u8>,
}

impl Envelope {
	/// Creates an envelope at the current protocol version.
	pub fn new(kind: u16, payload: Vec<u8>) -> Self {
		Self {
			version: PROTOCOL_VERSION,
			kind,
			payload,
		}
	}

	/// Encodes the envelope.
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		let bytes = bincode::serialize(self).map_err(|_| Error::Malformed)?;
		if bytes.len() > MAX_ENVELOPE_LEN {
			return Err(Error::TooLarge);
		}
		Ok(bytes)
	}

	/// Decodes an envelope and rejects any other protocol version.
	pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() > MAX_ENVELOPE_LEN {
			return Err(Error::TooLarge);
		}
		let envelope: Self = bincode::deserialize(bytes).map_err(|_| Error::Malformed)?;
		if envelope.version != PROTOCOL_VERSION {
			return Err(Error::VersionMismatch {
				got: envelope.version,
			});
		}
		Ok(envelope)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn roundtrip() {
		let e = Envelope::new(0x1001, vec![1, 2, 3]);
		assert_eq!(Envelope::decode(&e.encode().unwrap()).unwrap(), e);
	}

	#[test]
	fn rejects_wrong_version() {
		let e = Envelope {
			version: PROTOCOL_VERSION + 1,
			kind: 0,
			payload: vec![],
		};
		let bytes = bincode::serialize(&e).unwrap();
		assert_eq!(
			Envelope::decode(&bytes),
			Err(Error::VersionMismatch {
				got: PROTOCOL_VERSION + 1
			})
		);
	}

	#[test]
	fn rejects_garbage_and_truncation() {
		assert_eq!(Envelope::decode(&[]), Err(Error::Malformed));
		let mut bytes = Envelope::new(1, vec![9; 10]).encode().unwrap();
		bytes.truncate(bytes.len() - 1);
		assert_eq!(Envelope::decode(&bytes), Err(Error::Malformed));
	}

	#[test]
	fn rejects_oversize() {
		let big = Envelope::new(1, vec![0; MAX_ENVELOPE_LEN]);
		assert_eq!(big.encode(), Err(Error::TooLarge));
		assert_eq!(
			Envelope::decode(&vec![0; MAX_ENVELOPE_LEN + 1]),
			Err(Error::TooLarge)
		);
	}

	#[test]
	fn max_size_payload_fits() {
		// 2 + 2 + 8 (length prefix) bytes of overhead.
		let e = Envelope::new(1, vec![0; MAX_ENVELOPE_LEN - 12]);
		assert_eq!(e.encode().unwrap().len(), MAX_ENVELOPE_LEN);
	}

	#[test]
	fn ranges_cover_boundaries() {
		assert_eq!(range_of(CORE_RANGE.0), Range::Core);
		assert_eq!(range_of(CORE_RANGE.1), Range::Core);
		assert_eq!(range_of(RELAY_RANGE.0), Range::Relay);
		assert_eq!(range_of(RELAY_RANGE.1), Range::Relay);
		assert_eq!(range_of(BRIDGE_RANGE.0), Range::Bridge);
		assert_eq!(range_of(BRIDGE_RANGE.1), Range::Bridge);
		assert_eq!(range_of(ENTERPRISE_RANGE.0), Range::Enterprise);
		assert_eq!(range_of(ENTERPRISE_RANGE.1), Range::Enterprise);
		assert_eq!(range_of(0x3000), Range::Unassigned);
		assert_eq!(range_of(0xEFFF), Range::Unassigned);
	}

	#[test]
	fn error_messages() {
		assert_eq!(Error::Malformed.to_string(), "malformed envelope");
		assert_eq!(Error::TooLarge.to_string(), "envelope too large");
		assert!(Error::VersionMismatch { got: 9 }.to_string().contains('9'));
		let _: &dyn std::error::Error = &Error::Malformed;
	}
}
