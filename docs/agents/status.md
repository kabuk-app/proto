# Status

- Done: `Envelope` encode/decode (trailing bytes rejected), version check, size limit, range table.
- Done: relay messages in `src/relay.rs` (range `0x1000..=0x1FFF`) and identity types in `src/id.rs`. 100% line coverage.
- Not done: core (`0x0000..`) and bridge (`0x2000..`) message types. Add them when those crates need them.
