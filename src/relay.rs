//! Relay messages (range `0x1000..=0x1FFF`).
//!
//! Flow: a client registers its public key, signs the relay's challenge and gets its
//! [`DeviceId`](crate::id::DeviceId) confirmed. It can then ask to connect to another device,
//! exchange candidates, punch, or fall back to forwarding opaque frames. The end to end
//! session protocol is owned by `core`; here it is only bytes.

use crate::id::{Challenge, DeviceId, PublicKey, Signature};
use crate::{Envelope, Error, RELAY_RANGE};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Most candidates in one message.
pub const MAX_CANDIDATES: usize = 8;
/// Largest WebRTC signalling blob (SDP or ICE), in bytes. Larger ones must be split by the caller.
pub const MAX_SIGNAL_LEN: usize = 1024;
/// Largest ciphertext carried by one [`Message::Forward`], in bytes.
pub const MAX_FORWARD_LEN: usize = 1200;

/// Opaque rendezvous token proving the caller was given permission to connect (for example by pairing).
pub type Token = crate::id::Bytes<32>;

/// Identifies one forwarded or punched session between two devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// A network address a peer may be reachable at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Candidate {
	/// Address on the local network.
	Lan(SocketAddr),
	/// Public address as seen from outside (server reflexive).
	Public(SocketAddr),
}

/// Why the relay refused or failed a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
	/// The request was malformed or violated a limit.
	BadRequest,
	/// Registration proof failed.
	Unauthorized,
	/// The sender has not completed registration.
	NotRegistered,
	/// The target device is not connected.
	PeerOffline,
	/// The token is wrong or expired.
	BadToken,
	/// The sender is going too fast.
	RateLimited,
	/// The session id is not known.
	UnknownSession,
	/// The relay failed internally.
	Internal,
}

/// Every relay message. The envelope kind selects the variant, see [`Message::kind`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
	/// Client to relay: start registration with this public key.
	Register {
		/// The device's Ed25519 public key.
		public_key: PublicKey,
	},
	/// Relay to client: sign this to prove you own the key.
	Challenge {
		/// Random bytes, fresh per registration attempt.
		challenge: Challenge,
	},
	/// Client to relay: Ed25519 signature over the challenge.
	Proof {
		/// Signature of the challenge by the registered key.
		signature: Signature,
	},
	/// Relay to client: registration succeeded.
	Registered {
		/// The id the relay derived from the public key.
		device_id: DeviceId,
	},
	/// Client to relay: ask to reach a device.
	Connect {
		/// Device to reach.
		target: DeviceId,
		/// Rendezvous token.
		token: Token,
		/// Addresses the caller can be reached at.
		candidates: Vec<Candidate>,
	},
	/// Relay to target: someone wants to connect.
	Incoming {
		/// Device that asked.
		from: DeviceId,
		/// Session to use for this attempt.
		session: SessionId,
		/// Rendezvous token supplied by the caller.
		token: Token,
		/// Addresses the caller can be reached at.
		candidates: Vec<Candidate>,
	},
	/// Target to relay: accept the attempt and share its own candidates.
	Accept {
		/// Session from [`Message::Incoming`].
		session: SessionId,
		/// Addresses the target can be reached at.
		candidates: Vec<Candidate>,
	},
	/// Relay to both peers: the other side's candidates.
	Peer {
		/// Session this belongs to.
		session: SessionId,
		/// The other device.
		peer: DeviceId,
		/// The other device's addresses.
		candidates: Vec<Candidate>,
	},
	/// Relay to both peers: start sending hole punch packets after this delay.
	Punch {
		/// Session to punch for.
		session: SessionId,
		/// Milliseconds from receipt until both sides send, so the two start together.
		delay_ms: u32,
	},
	/// Either direction: opaque WebRTC signalling for a browser peer.
	/// Sent with `peer` = target, delivered with `peer` = sender.
	Signal {
		/// Session this belongs to.
		session: SessionId,
		/// Target when sent, sender when delivered.
		peer: DeviceId,
		/// Opaque SDP or ICE data.
		blob: Vec<u8>,
	},
	/// Either direction: opaque ciphertext between two connected devices.
	Forward {
		/// Session this belongs to.
		session: SessionId,
		/// Ciphertext produced by the E2E session. Never inspected.
		data: Vec<u8>,
	},
	/// Liveness probe.
	Ping {
		/// Echoed in the matching [`Message::Pong`].
		nonce: u64,
	},
	/// Reply to [`Message::Ping`].
	Pong {
		/// The nonce from the ping.
		nonce: u64,
	},
	/// Relay to client: a request failed.
	Error {
		/// What went wrong.
		code: ErrorCode,
		/// Session involved, if any.
		session: Option<SessionId>,
	},
}

/// Envelope kinds of the relay messages.
pub mod kind {
	/// [`Message::Register`](super::Message::Register).
	pub const REGISTER: u16 = 0x1001;
	/// [`Message::Challenge`](super::Message::Challenge).
	pub const CHALLENGE: u16 = 0x1002;
	/// [`Message::Proof`](super::Message::Proof).
	pub const PROOF: u16 = 0x1003;
	/// [`Message::Registered`](super::Message::Registered).
	pub const REGISTERED: u16 = 0x1004;
	/// [`Message::Connect`](super::Message::Connect).
	pub const CONNECT: u16 = 0x1010;
	/// [`Message::Incoming`](super::Message::Incoming).
	pub const INCOMING: u16 = 0x1011;
	/// [`Message::Accept`](super::Message::Accept).
	pub const ACCEPT: u16 = 0x1012;
	/// [`Message::Peer`](super::Message::Peer).
	pub const PEER: u16 = 0x1013;
	/// [`Message::Punch`](super::Message::Punch).
	pub const PUNCH: u16 = 0x1014;
	/// [`Message::Signal`](super::Message::Signal).
	pub const SIGNAL: u16 = 0x1020;
	/// [`Message::Forward`](super::Message::Forward).
	pub const FORWARD: u16 = 0x1030;
	/// [`Message::Ping`](super::Message::Ping).
	pub const PING: u16 = 0x1040;
	/// [`Message::Pong`](super::Message::Pong).
	pub const PONG: u16 = 0x1041;
	/// [`Message::Error`](super::Message::Error).
	pub const ERROR: u16 = 0x10FF;
}

impl Message {
	/// The envelope kind of this message.
	pub fn kind(&self) -> u16 {
		match self {
			Message::Register { .. } => kind::REGISTER,
			Message::Challenge { .. } => kind::CHALLENGE,
			Message::Proof { .. } => kind::PROOF,
			Message::Registered { .. } => kind::REGISTERED,
			Message::Connect { .. } => kind::CONNECT,
			Message::Incoming { .. } => kind::INCOMING,
			Message::Accept { .. } => kind::ACCEPT,
			Message::Peer { .. } => kind::PEER,
			Message::Punch { .. } => kind::PUNCH,
			Message::Signal { .. } => kind::SIGNAL,
			Message::Forward { .. } => kind::FORWARD,
			Message::Ping { .. } => kind::PING,
			Message::Pong { .. } => kind::PONG,
			Message::Error { .. } => kind::ERROR,
		}
	}

	fn check_limits(&self) -> Result<(), Error> {
		let ok = match self {
			Message::Connect { candidates, .. }
			| Message::Incoming { candidates, .. }
			| Message::Accept { candidates, .. }
			| Message::Peer { candidates, .. } => candidates.len() <= MAX_CANDIDATES,
			Message::Signal { blob, .. } => blob.len() <= MAX_SIGNAL_LEN,
			Message::Forward { data, .. } => data.len() <= MAX_FORWARD_LEN,
			_ => true,
		};
		if ok {
			Ok(())
		} else {
			Err(Error::LimitExceeded)
		}
	}

	/// Encodes into an envelope. Fails if a field limit or the envelope size is exceeded.
	pub fn to_envelope(&self) -> Result<Envelope, Error> {
		self.check_limits()?;
		let payload = crate::codec()
			.serialize(self)
			.map_err(|_| Error::Malformed)?;
		// The variant is chosen by the envelope kind, so drop the 4 byte enum tag.
		let envelope = Envelope::new(self.kind(), payload[4..].to_vec());
		envelope.encode()?;
		Ok(envelope)
	}

	/// Decodes from an envelope, enforcing every field limit and rejecting trailing bytes.
	pub fn from_envelope(envelope: &Envelope) -> Result<Self, Error> {
		let index = match envelope.kind {
			kind::REGISTER => 0,
			kind::CHALLENGE => 1,
			kind::PROOF => 2,
			kind::REGISTERED => 3,
			kind::CONNECT => 4,
			kind::INCOMING => 5,
			kind::ACCEPT => 6,
			kind::PEER => 7,
			kind::PUNCH => 8,
			kind::SIGNAL => 9,
			kind::FORWARD => 10,
			kind::PING => 11,
			kind::PONG => 12,
			kind::ERROR => 13,
			other => return Err(Error::UnknownKind(other)),
		};
		debug_assert!((RELAY_RANGE.0..=RELAY_RANGE.1).contains(&envelope.kind));
		let mut bytes = Vec::with_capacity(4 + envelope.payload.len());
		bytes.extend_from_slice(&(index as u32).to_le_bytes());
		bytes.extend_from_slice(&envelope.payload);
		let message: Self = crate::codec_limited()
			.deserialize(&bytes)
			.map_err(|_| Error::Malformed)?;
		message.check_limits()?;
		Ok(message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::id::Bytes;
	use bincode::Options;

	fn id(n: u8) -> DeviceId {
		DeviceId([n; 16])
	}
	fn cands(n: usize) -> Vec<Candidate> {
		let v4: SocketAddr = "192.168.1.5:21216".parse().unwrap();
		let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
		(0..n)
			.map(|i| {
				if i % 2 == 0 {
					Candidate::Lan(v4)
				} else {
					Candidate::Public(v6)
				}
			})
			.collect()
	}
	fn session() -> SessionId {
		SessionId(0x0102_0304_0506_0708)
	}

	fn all() -> Vec<Message> {
		vec![
			Message::Register {
				public_key: Bytes([1; 32]),
			},
			Message::Challenge {
				challenge: Bytes([2; 32]),
			},
			Message::Proof {
				signature: Bytes([3; 64]),
			},
			Message::Registered { device_id: id(4) },
			Message::Connect {
				target: id(5),
				token: Bytes([6; 32]),
				candidates: cands(3),
			},
			Message::Incoming {
				from: id(5),
				session: session(),
				token: Bytes([6; 32]),
				candidates: cands(MAX_CANDIDATES),
			},
			Message::Accept {
				session: session(),
				candidates: cands(0),
			},
			Message::Peer {
				session: session(),
				peer: id(7),
				candidates: cands(2),
			},
			Message::Punch {
				session: session(),
				delay_ms: 250,
			},
			Message::Signal {
				session: session(),
				peer: id(8),
				blob: vec![9; MAX_SIGNAL_LEN],
			},
			Message::Forward {
				session: session(),
				data: vec![10; MAX_FORWARD_LEN],
			},
			Message::Ping { nonce: 11 },
			Message::Pong { nonce: 12 },
			Message::Error {
				code: ErrorCode::PeerOffline,
				session: Some(session()),
			},
			Message::Error {
				code: ErrorCode::RateLimited,
				session: None,
			},
		]
	}

	#[test]
	fn every_message_roundtrips_through_wire_bytes() {
		for m in all() {
			let wire = m.to_envelope().unwrap().encode().unwrap();
			let env = Envelope::decode(&wire).unwrap();
			assert_eq!(env.kind, m.kind());
			assert_eq!(crate::range_of(env.kind), crate::Range::Relay);
			assert_eq!(Message::from_envelope(&env).unwrap(), m);
		}
	}

	#[test]
	fn kinds_are_unique() {
		let mut kinds: Vec<u16> = all().iter().map(Message::kind).collect();
		kinds.sort_unstable();
		kinds.dedup();
		assert_eq!(kinds.len(), 14);
	}

	#[test]
	fn known_answer_ping() {
		let env = Message::Ping { nonce: 0x0102 }.to_envelope().unwrap();
		assert_eq!(env.payload, vec![2, 1, 0, 0, 0, 0, 0, 0]);
		assert_eq!(env.kind, 0x1040);
	}

	#[test]
	fn encode_enforces_limits() {
		let big_blob = Message::Signal {
			session: session(),
			peer: id(1),
			blob: vec![0; MAX_SIGNAL_LEN + 1],
		};
		assert_eq!(big_blob.to_envelope(), Err(Error::LimitExceeded));
		let big_fwd = Message::Forward {
			session: session(),
			data: vec![0; MAX_FORWARD_LEN + 1],
		};
		assert_eq!(big_fwd.to_envelope(), Err(Error::LimitExceeded));
		let many = Message::Accept {
			session: session(),
			candidates: cands(MAX_CANDIDATES + 1),
		};
		assert_eq!(many.to_envelope(), Err(Error::LimitExceeded));
	}

	#[test]
	fn largest_messages_fit_in_one_envelope() {
		// Worst cases by size must still encode within MAX_ENVELOPE_LEN.
		for m in all() {
			assert!(m.to_envelope().unwrap().encode().unwrap().len() <= crate::MAX_ENVELOPE_LEN);
		}
		let worst = Message::Incoming {
			from: id(1),
			session: session(),
			token: Bytes([0; 32]),
			candidates: vec![Candidate::Public("[::1]:1".parse().unwrap()); MAX_CANDIDATES],
		};
		assert!(worst.to_envelope().is_ok());
	}

	#[test]
	fn decode_enforces_limits_not_just_encode() {
		// Forge an oversize candidate list directly on the wire.
		let forged = Message::Accept {
			session: session(),
			candidates: cands(MAX_CANDIDATES + 1),
		};
		let mut bytes = crate::codec().serialize(&forged).unwrap();
		let payload = bytes.split_off(4);
		let env = Envelope::new(kind::ACCEPT, payload);
		assert_eq!(Message::from_envelope(&env), Err(Error::LimitExceeded));
	}

	#[test]
	fn decode_rejects_bad_input() {
		let ping = Message::Ping { nonce: 1 }.to_envelope().unwrap();
		let mut trailing = ping.clone();
		trailing.payload.push(0);
		assert_eq!(Message::from_envelope(&trailing), Err(Error::Malformed));
		let mut short = ping.clone();
		short.payload.pop();
		assert_eq!(Message::from_envelope(&short), Err(Error::Malformed));
		// Unknown error code and unknown candidate tag.
		let bad_code = Envelope::new(kind::ERROR, vec![99, 0, 0, 0, 0]);
		assert_eq!(Message::from_envelope(&bad_code), Err(Error::Malformed));
		// Huge claimed vector length must fail cleanly, not allocate.
		let mut huge = vec![0u8; 8];
		huge.extend_from_slice(&u64::MAX.to_le_bytes());
		assert_eq!(
			Message::from_envelope(&Envelope::new(kind::FORWARD, huge)),
			Err(Error::Malformed)
		);
		assert_eq!(
			Message::from_envelope(&Envelope::new(0x1FFF, vec![])),
			Err(Error::UnknownKind(0x1FFF))
		);
		assert_eq!(
			Message::from_envelope(&Envelope::new(0x0001, vec![])),
			Err(Error::UnknownKind(1))
		);
	}

	#[test]
	fn debug_never_prints_key_material() {
		let m = Message::Proof {
			signature: Bytes([0xAB; 64]),
		};
		assert!(!format!("{m:?}").to_lowercase().contains("ab"));
	}
}
