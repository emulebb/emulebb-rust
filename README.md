# emulebb-rust

`emulebb-rust` is the Rust headless client for the eMuleBB product family and the
forward eD2K/Kad core. It owns the Rust-forward `/api/v1` contract and is driven
by **TrackMuleBB**, the forward eMuleBB Suite controller; it keeps local client
state plus indexing data in SQLite.

The repository began from earlier Kad and ED2K work, but it is intentionally a
local client product. The 0.0.x line does not expose a coordinator API.

Rust development uses the exact toolchain declared in `rust-toolchain.toml`.
Update that pin, the workspace `rust-version`, and CI together in a dedicated
toolchain commit after each stable Rust release has passed the full quality
gate; normal development must not float independently on `stable`.

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

Rust source is split by subsystem and responsibility, not by a mechanical line
limit. Substantial tests stay outside production modules; small white-box tests
may remain beside private helpers when proximity improves understanding. The
authoritative rules live in
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust\reference\CODE-QUALITY.md`.
The policy checker reports maintainability signals as advisories while retaining
hard failures for objective protocol, omission, binding, and release-safety
violations.

Run the local policy guard before policy-sensitive protocol or architecture
changes:

```powershell
python tools\rust_quality_gate.py policy
```

Run the build gate after code changes. It runs normal Cargo debug and release
builds for the daemon and UI, builds the release diagnostics binary, and stages
freshly copied release executables under
`%EMULEBB_WORKSPACE_OUTPUT_ROOT%\tools\emulebb-rust\bin`.

```powershell
python tools\rust_quality_gate.py build
```

Use `--force-rebuild` only when intentionally clearing Cargo state, for example
after a toolchain or native dependency investigation.

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

## Licensing

The emulebb-rust workspace is licensed under `GPL-2.0-only`. Third-party
components retain their own licenses; see `THIRD-PARTY-LICENSES.md` for the
dependency policy and required notices.

[![Made with Slint](https://raw.githubusercontent.com/slint-ui/slint/master/logo/MadeWithSlint-logo-whitebg.png)](https://slint.dev)
