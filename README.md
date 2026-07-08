# emulebb-rust

`emulebb-rust` is the Rust headless client for the eMuleBB product family and the
forward eD2K/Kad core. It owns the Rust-forward `/api/v1` contract and is driven
by **TrackMuleBB**, the forward eMuleBB Suite controller; it keeps local client
state plus indexing data in SQLite.

The repository began from earlier Kad and ED2K work, but it is intentionally a
local client product. The 0.0.x line does not expose a coordinator API.

The 0.0.3 scope is core eMule client parity: configured binding, ED2K/Kad
interoperability, search, sharing, transfers, uploads, queues, persistence,
local SQLite/FTS indexing, and REST controller visibility. It is not legacy
HTML WebServer parity, a qBittorrent/Torznab adapter host, a coordinator, or a
remote indexer fleet.

Active product docs, backlog, design notes, release scope, and the Rust OpenAPI
contract live in
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust`.
The repo-local `docs` directory is only a pointer.

## 0.0.x Shape

- `emulebb-daemon`: CLI, config, logging, and REST listener.
- `emulebb-rest`: Rust-native `/api/v1` routes, envelopes, and API-key
  auth.
- `emulebb-core`: local app state, capabilities, searches, and transfer
  summaries.
- `emulebb-index`: SQLite + FTS5 local file index plus Kad harvest/store
  scheduling components.
- `emulebb-kad-*`: copied and renamed Kad protocol/runtime crates.

Indexing is a client capability, not a separate public API. It improves
search results returned through the eMuleBB search resources.

## Rust Client Policy

The Rust client is multi-platform by tiered proof: Windows, Linux, and macOS
must stay compile/test viable where practical, while platform runtime claims
require smoke or live evidence for that platform. Platform-specific behavior
belongs behind narrow adapters.

The protocol surface is IPv4-only and stock-compatible for implemented eD2K and
Kad behavior. Historic or niche behavior may be omitted only when it is recorded
in `policy/rust-client-omissions.toml`, is not advertised on the wire, and does
not change the semantics of supported stock interactions.

Rust source should stay split by subsystem and responsibility. The guardrail in
`policy/rust-client.toml` sets file-size budgets, names current legacy oversized
files as refactor debt, and prevents new oversized modules from appearing
without an explicit rationale. During the parity push, source caps are
engineering guardrails rather than refactor triggers; raise an allowlist cap
when the touched behavior is one cohesive function or protocol decision surface
and the policy rationale explains why splitting it would make the code harder to
reason about.

Run the local policy guard before policy-sensitive protocol or architecture
changes:

```powershell
python tools\check_rust_client_policy.py
```

Compatibility proof for this line is local and deterministic first: Rust to
Rust, stock-compatible eD2K/Kad interop witnesses, and REST conformance against
the Rust OpenAPI contract. Public hide.me live-wire proof is a smoke lane layered
on top of the fail-closed VPN gates.

## Binding Contract

Run the daemon with `--config <path>`. The daemon does not read machine-local
environment variables for product binding decisions, and it does not invent
listener addresses when config is missing. REST `bindAddr` is required in the
TOML file. When ED2K servers are configured, `p2pBindIp`, `ed2k.listenPort`,
and `kad.listenPort` are also required so the peer listener and Kad UDP surface
bind to the configured address.

Harnesses may use operator-local inputs to generate that TOML file, but the
Rust client itself only consumes the configured addresses.
