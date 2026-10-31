# Kabuk protocol

The message format that Kabuk devices, relays and bridges use to talk to each other.

You do not need this repository to use Kabuk. It is a small Rust crate for people who build or
host parts of the system, such as the relay and the bridge. Every message is wrapped in a
versioned envelope, and a peer that speaks another version is rejected.

Kabuk is early and not released yet. Nothing here is ready for everyday use.

To use it from Rust, add it as a git dependency:

```toml
kabuk-proto = { git = "https://github.com/kabuk-app/proto" }
```

Licensed under the GNU General Public License v3.0 or later. See `LICENSE`.
