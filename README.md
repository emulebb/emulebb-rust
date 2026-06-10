# emulebb-rust

`emulebb-rust` is the Rust headless client for the eMuleBB product family. It
implements the eMuleBB `/api/v1` controller shape for aMuTorrent and keeps local
client state plus indexing data in SQLite.

This repository was bootstrapped from the Kad and ED2K work in
`p2p-overlord-agents`, but it is intentionally a local client product. The
0.0.x line does not expose a coordinator API.

The 0.0.3 scope is core eMule client parity: configured binding, ED2K/Kad
interoperability, search, sharing, transfers, uploads, queues, persistence,
local SQLite/FTS indexing, and REST controller visibility. It is not legacy
HTML WebServer parity, a qBittorrent/Torznab adapter host, a coordinator, or a
remote indexer fleet.

## 0.0.x Shape

- `emulebb-daemon`: CLI, config, logging, and REST listener.
- `emulebb-rest`: eMuleBB-compatible `/api/v1` routes, envelopes, and API-key
  auth.
- `emulebb-core`: local app state, capabilities, searches, and transfer
  summaries.
- `emulebb-index`: SQLite + FTS5 local file index plus Kad harvest/store
  scheduling components.
- `emulebb-kad-*`: copied and renamed Kad protocol/runtime crates.

Indexing is a client capability, not a separate public API. It improves
search results returned through the eMuleBB search resources.

Compatibility proof for this line is local and deterministic first: Rust to
Rust, Rust to eMuleBB through the common REST contract, and Rust to aMule as a
short-path compatibility witness. Public hide.me live-wire proof is a future
nonblocking smoke lane until Rust has first-class configured VPN evidence.

## Binding Contract

Run the daemon with `--config <path>`. The daemon does not read machine-local
environment variables for product binding decisions, and it does not invent
listener addresses when config is missing. REST `bindAddr` is required in the
TOML file. When ED2K servers are configured, `p2pBindIp`, `ed2k.listenPort`,
and `kad.listenPort` are also required so the peer listener and Kad UDP surface
bind to the configured address.

Harnesses may use operator-local inputs to generate that TOML file, but the
Rust client itself only consumes the configured addresses.
