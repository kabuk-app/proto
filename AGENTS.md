# proto

`kabuk-proto`: wire protocol crate. Versioned `Envelope` (bincode), reserved message ranges
(core, relay, bridge, enterprise). Git dependency of core, relay and bridge.

Umbrella index: [../AGENTS.md](../AGENTS.md).

## Commands

- `cargo fmt --all --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo llvm-cov --fail-under-lines 100`

## Rules

- Any incompatible wire change bumps `PROTOCOL_VERSION`.
- Never reuse or move a range. Enterprise `0xF000..=0xFFFF` stays reserved for the closed servers.
- Status: [docs/agents/status.md](docs/agents/status.md)
