# emulebb-rust

`emulebb-rust` is the Rust headless client for the eMuleBB product family. It
implements the eMuleBB `/api/v1` controller shape for aMuTorrent and keeps local
client state plus indexing data in SQLite.

This repository was bootstrapped from the Kad and ED2K work in
`p2p-overlord-agents`, but it is intentionally a local client product. The MVP
does not expose a coordinator API.

## MVP Shape

- `emulebb-daemon`: CLI, config, logging, and REST listener.
- `emulebb-rest`: eMuleBB-compatible `/api/v1` routes, envelopes, and API-key
  auth.
- `emulebb-core`: local app state, capabilities, searches, and transfer
  summaries.
- `emulebb-index`: SQLite + FTS5 local file index.
- `emulebb-kad-*`: copied and renamed Kad protocol/runtime crates.

Indexing is a capability in the MVP, not a separate public API. It improves
search results returned through the eMuleBB search resources.

## Binding Contract

Run the daemon with `--config <path>`. The daemon does not read machine-local
environment variables for product binding decisions, and it does not invent
listener addresses when config is missing. REST `bindAddr` is required in the
TOML file. When ED2K servers are configured, `p2pBindIp`, `ed2k.listenPort`,
and `kad.listenPort` are also required so the peer listener and Kad UDP surface
bind to the configured address.

Harnesses may use operator-local inputs to generate that TOML file, but the
Rust client itself only consumes the configured addresses.
