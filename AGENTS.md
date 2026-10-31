# proto

`kabuk-proto`: wire protocol crate. Versioned `Envelope` (bincode), reserved message ranges
(core, relay, bridge, enterprise). Git dependency of core, relay and bridge.

Umbrella index: [../AGENTS.md](../AGENTS.md).

## API

- `id`: `DeviceId` (16 bytes, SHA-256 prefix of the Ed25519 key, base32 text via `Display`/`DeviceId::parse`),
  `PublicKey`, `Signature`, `Challenge` (fixed size, sizes only, no crypto here).
- `relay::Message`: `to_envelope()` / `from_envelope()`. Flow: `Register` -> `Challenge` -> `Proof` -> `Registered`;
  `Connect` -> `Incoming` -> `Accept` -> `Peer` + `Punch`; `Signal` (WebRTC blobs, `MAX_SIGNAL_LEN` 1024);
  `Forward` (`MAX_FORWARD_LEN` 1200); `Ping`/`Pong`; `Error(ErrorCode)`. Kinds in `relay::kind`.
- Limits are enforced on both encode and decode (`Error::LimitExceeded`, `MAX_CANDIDATES` 8). Payload carries no
  enum tag, the envelope kind selects the variant. SDP larger than 1024 bytes must be split by the caller.

## Commands

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo llvm-cov --fail-under-lines 100`

## Rules

- Any incompatible wire change bumps `PROTOCOL_VERSION`.
- Never reuse or move a range. Enterprise `0xF000..=0xFFFF` stays reserved for the closed servers.
- Status: [docs/agents/status.md](docs/agents/status.md)
