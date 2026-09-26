# emulebb-rust

`emulebb-rust` is the Rust client for the eMuleBB product family and the forward
eD2K/Kad core. It owns the Rust-forward `/api/v1` contract, runs as a headless
daemon, and serves the embedded browser SPA WebUI from packaged static assets.
It keeps local client state plus indexing data in SQLite.

This is a Rust-native successor to the Windows eMuleBB MFC fork, not a
line-by-line port or an MFC REST-contract mirror. Stock/community eMule peers
are the primary wire-compatibility target. The separate maintained aMule client
is a cross-platform source and offline-fixture reference in this workspace.

The repository began from earlier Kad and ED2K work, but it is intentionally a
local client product. The `0.1.0-beta.1` line does not expose a coordinator API.

Rust development uses the exact toolchain declared in `rust-toolchain.toml`.
Update that pin, the workspace `rust-version`, and CI together in a dedicated
toolchain commit after each stable Rust release has passed the full quality
gate; normal development must not float independently on `stable`.

The `0.1.0-beta.1` scope is eD2K/Kad protocol-operational parity: configured binding,
interoperability, search, sharing, transfers, uploads, queues, persistence,
local SQLite/FTS indexing, REST controller visibility, and embedded SPA WebUI
operation. Local API, UI, settings, diagnostics, and scheduling surfaces are
Rust-native async daemon design. Broadband-oriented async IO is the default
runtime model, not a compatibility toggle.

Active product docs, backlog, design notes, release scope, and the Rust OpenAPI
contract live in
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust`.
The repo-local `docs` directory is only a pointer.

New contributors should start with [`CONTRIBUTING.md`](CONTRIBUTING.md), the
public eMuleBB Suite board, and starter issues labeled `good first issue` or
`help wanted`.

## 0.1.0-beta.1 Shape

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

Run the WebUI test gate after embedded SPA changes. It installs the locked npm
dependencies, runs Vitest unit tests, runs the mocked Playwright Chromium smoke
suite, and verifies the production Vite build.

```powershell
python tools\rust_quality_gate.py webui-test
```

Use `--force-rebuild` only when intentionally clearing Cargo state, for example
after a toolchain or native dependency investigation.

Compatibility proof for this line is local and deterministic first: Rust to
Rust, stock-compatible eD2K/Kad interop witnesses, and REST conformance against
the Rust OpenAPI contract. Public-network diagnostics may use a direct
connection; VPN use is optional. An explicit interface bind is fail-closed, but
the beta does not claim native VPN leak safety without separate platform proof.

## Binding Contract

Run the daemon directly or pass `--profile <dir>`. Without `--profile`, the
daemon creates a local-only profile under `$XDG_CONFIG_HOME/emulebb-rust` on
Linux (falling back to `~/.config/emulebb-rust`), the platform application-data
directory on Windows, or `~/Library/Application Support/emulebb-rust` on macOS.
It prints the generated WebUI API key on first launch. An explicit profile must
already contain `emulebb-rust-settings.toml`; its SQLite repository is
`emulebb-rust-metadata.db`. The TOML file is control-plane bootstrap only: REST
`bindAddr` is required there, while runtime/network settings live in the
database and are exposed through `/api/v1/app/settings`.

When an enabled server list or persisted Kad bootstrap file is empty, startup
downloads and validates the same trusted defaults used by eMuleBB MFC. Existing
server data and non-empty `nodes.dat` files are never replaced. An offline or
failed bootstrap does not prevent the daemon and WebUI from starting.

The daemon serves the browser WebUI from a `webui` directory beside
`emulebb-rust.exe` when that directory exists. Set `[rest].webRootDir` to an
explicit asset directory to override that default; relative override paths are
resolved from the profile directory. Browser API calls use the existing
`X-API-Key` header.

Harnesses may use operator-local inputs to create the profile directory and
write those fixed files, but the Rust client itself only consumes the profile.

## Beta.1 candidate artifacts

The public [release notes](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-0.1.0-beta.1-NOTES.md),
[changelog](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-0.1.0-beta.1-CHANGELOG.md),
and [release scope](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-SCOPE.md)
are the version-specific operator and compatibility references.

The manual [release workflow](.github/workflows/release.yml) retains unsigned
candidate artifacts for Windows, Linux, and macOS on x64 and ARM64. Native ZIP,
DEB/AppImage, and app-in-DMG packages include the daemon and browser WebUI. It
also builds a Linux amd64/arm64 OCI image without publishing it. An approved
`rust-v0.1.0-beta.1` tag is required to publish versioned GitHub Release and
GHCR assets; the workflow does not publish a `latest` image.

The image uses LinuxServer's s6 base and supports `PUID`/`PGID`, `/config` for
profile state, and `/data/ed2k` for completed downloads. It serves the WebUI
and REST API on port 4711. The optional
[Gluetun Compose example](packaging/docker/compose.gluetun.example.yaml) uses
an independent tunnel and read-only operator credentials; it binds Rust P2P to
`tun0` through `EMULEBB_RUST_P2P_INTERFACE`. It is not a requirement for direct
internet beta testing and does not alter an existing P2P Compose stack.

## Licensing

The emulebb-rust workspace is licensed under `GPL-2.0-only`. Third-party
components retain their own licenses; see `THIRD-PARTY-LICENSES.md` for the
dependency policy and required notices.
