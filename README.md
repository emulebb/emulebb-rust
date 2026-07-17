# emulebb-rust

`emulebb-rust` is the Rust client for the eMuleBB product family and the forward
eD2K/Kad core. It owns the Rust-forward `/api/v1` contract, runs as a headless
daemon, and serves the embedded browser SPA WebUI from packaged static assets.
It keeps local client state plus indexing data in SQLite.

The repository began from earlier Kad and ED2K work, but it is intentionally a
local client product. The 0.0.x line does not expose a coordinator API.

Rust development uses the exact toolchain declared in `rust-toolchain.toml`.
Update that pin, the workspace `rust-version`, and CI together in a dedicated
toolchain commit after each stable Rust release has passed the full quality
gate; normal development must not float independently on `stable`.

The 0.0.3 scope is eD2K/Kad protocol-operational parity: configured binding,
interoperability, search, sharing, transfers, uploads, queues, persistence,
local SQLite/FTS indexing, REST controller visibility, and embedded SPA WebUI
operation. Local API, UI, settings, diagnostics, and scheduling surfaces are
Rust-native async daemon design. Broadband-oriented async IO is the default
runtime model, not a compatibility toggle.

Active product docs, backlog, design notes, release scope, and the Rust OpenAPI
contract live in
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust`.
The repo-local `docs` directory is only a pointer.

## 0.0.x Shape

- `emulebb-daemon`: CLI, config, logging, and REST listener.
- `emulebb-rest`: Rust-native `/api/v1` routes, envelopes, and API-key
  auth plus the packaged browser WebUI static surface.
- `webui`: embedded Vite/Preact SPA WebUI packaged beside the daemon.
- `emulebb-core`: local app state, capabilities, searches, and transfer
  summaries.
- `emulebb-index`: SQLite + FTS5 local file index plus Kad harvest/store
  scheduling components.
- `emulebb-kad-*`: copied and renamed Kad protocol/runtime crates.

Indexing is a client capability, not a separate public API. It improves
search results returned through the eMuleBB search resources.

`crates/emulebb-rust-ui` is frozen legacy Slint UI work. It remains in the
workspace until a later code/build cleanup removes or repurposes it, but it is
not the forward beta UI target.

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
builds for the daemon, builds the release diagnostics binary, and stages freshly
copied release executables under
`%EMULEBB_WORKSPACE_OUTPUT_ROOT%\tools\emulebb-rust\bin`. The browser WebUI is
staged beside the executable as `webui`.

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

Run the daemon with `--profile <dir>`. The daemon reads REST bootstrap settings
from `<dir>\emulebb-rust-settings.toml` and opens its SQLite repository at
`<dir>\emulebb-rust-metadata.db`. The TOML file is control-plane bootstrap only:
REST `bindAddr` is required there, while runtime/network settings live in the
database and are exposed through `/api/v1/app/settings`.

The daemon serves the browser WebUI from a `webui` directory beside
`emulebb-rust.exe` when that directory exists. Set `[rest].webRootDir` to an
explicit asset directory to override that default; relative override paths are
resolved from the profile directory. Browser API calls use the existing
`X-API-Key` header.

Harnesses may use operator-local inputs to create the profile directory and
write those fixed files, but the Rust client itself only consumes the profile.

## Licensing

The emulebb-rust workspace is licensed under `GPL-2.0-only`. Third-party
components retain their own licenses; see `THIRD-PARTY-LICENSES.md` for the
dependency policy and required notices.
