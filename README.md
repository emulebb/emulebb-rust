# emulebb-rust

`emulebb-rust` is the active experimental Rust eD2K/Kad client in the eMuleBB
organization. It owns the Rust-forward `/api/v1` contract, runs as a headless
daemon, and serves the embedded browser SPA WebUI from packaged static assets.
It keeps local client state plus indexing data in SQLite.

This is a Rust-native successor to the Windows eMuleBB MFC fork, not a
line-by-line port or an MFC REST-contract mirror. Stock/community eMule peers
are the primary wire-compatibility target. The separate maintained aMule client
is a cross-platform source and offline-fixture reference in this workspace.

The repository began from earlier Kad and ED2K work, but it is intentionally a
local client product. The `0.1.0-beta.2` line does not expose a coordinator API.

> **Public beta:** [`rust-v0.1.0-beta.2`](https://github.com/emulebb/emulebb-rust/releases/tag/rust-v0.1.0-beta.2)
> is published for Windows, Linux, and macOS. It is experimental software and
> is not presented as production-ready. The release decision and retained
> evidence are tracked in
> [RUST-BUG-101 / issue 19](https://github.com/emulebb/emulebb-rust/issues/19).

> **Nightly beta channel:** Automated builds from `main` are enabled. A
> scheduled run publishes a new prerelease only when the exact commit has
> passed normal CI and differs from the previous nightly. See
> [Nightly beta builds](#nightly-beta-builds) for downloads, container tags,
> versioning, and generated changelog details.

Rust development uses the exact toolchain declared in `rust-toolchain.toml`.
Update that pin, the workspace `rust-version`, and CI together in a dedicated
toolchain commit after each stable Rust release has passed the full quality
gate; normal development must not float independently on `stable`.

The `0.1.0-beta.2` scope is eD2K/Kad protocol-operational parity: configured binding,
interoperability, search, sharing, transfers, uploads, queues, persistence,
local SQLite/FTS indexing, REST controller visibility, and embedded SPA WebUI
operation. Local API, UI, settings, diagnostics, and scheduling surfaces are
Rust-native async daemon design. Broadband-oriented async IO is the default
runtime model, not a compatibility toggle.

Active product docs, backlog, design notes, release scope, and the Rust OpenAPI
contract live in
`EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust`.
The repo-local `docs` directory is only a pointer.

New contributors should start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
public [eMuleBB Roadmap](https://github.com/orgs/emulebb/projects/3). The beta
is published; new work should be scoped through the normal issue and validation
process rather than the former pre-release freeze.

## 0.1.0-beta.2 Shape

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

The former native Slint client has been removed. The supported product shape is
the headless daemon plus its REST API and embedded SPA WebUI; release cleanup
still rejects stale `emulebb-rust-ui` artifacts from older build directories.

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
violations. Normal CI also validates every GitHub Actions workflow with a pinned
actionlint revision so expression and context errors fail before release use.

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
dependencies, runs Vitest unit tests, runs the stateful Playwright Chromium
suite, checks types, and verifies the production Vite build. The release
orchestrator stages all generated npm/test/build content below
`EMULEBB_WORKSPACE_OUTPUT_ROOT`:

```powershell
Push-Location ..\emulebb-build
python -m emule_workspace test rust-webui
Pop-Location
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

`apiKey` is also required. Startup rejects blank, known placeholder,
whitespace-padded, non-printable, and shorter-than-32-byte values. The implicit
first-run profile generates a 32-character random key and, on Unix, creates the
profile directory and bootstrap file with modes `0700` and `0600`. Existing
Unix bootstrap files with group or other access are rejected with a `chmod 600`
remediation message because the file contains the REST credential.

The daemon serves plain HTTP. Keep direct listeners on loopback whenever
possible. A non-loopback listener is intended for a container network or a
trusted TLS reverse proxy and emits a startup warning; independently restrict
host/firewall exposure. The WebUI keeps its API key in per-tab session storage,
so closing the tab clears the browser copy.

`GET /healthz` is an unauthenticated operational readiness probe outside the
versioned `/api/v1` contract. It returns an empty `204` only while the daemon is
running and `503` during graceful shutdown; it exposes no profile, peer,
network, or credential data. The OCI image uses this loopback-only probe for its
built-in healthcheck.

### Upload queue settings migration

The beta settings contract has one owner for each upload scheduling input. The
following former `ed2k.uploadQueue` fields are no longer accepted; update saved
API payloads or profile automation to use their `core` equivalents:

| Removed field | Replacement |
| --- | --- |
| `ed2k.uploadQueue.activeSlots` | `core.maxUploadSlots` |
| `ed2k.uploadQueue.elasticPercent` | `core.uploadSlotElasticPercent` |
| `ed2k.uploadQueue.uploadLimitBytesPerSec` | `core.uploadLimitKiBps` |
| `ed2k.uploadQueue.elasticUnderfillBytesPerSec` | `core.uploadClientDataRate` |
| `ed2k.uploadQueue.waitingCapacity` | `core.queueSize` |

The two rate replacements use KiB/s, while the removed fields used bytes/s.
Because this is a beta contract cleanup, stale fields are rejected as unknown
rather than silently migrated. Fresh profiles use a 5-second drained/zero-rate
grace and a 30-second accumulated slow-rate grace after a 30-second warm-up.

## Logging

Regular daemon builds log `INFO` and above by default to the console, the
bounded `GET /api/v1/logs` buffer, and daily JSON Lines files under
`<profile>/logs`. The file logger retains the newest eight files. If its
directory cannot be created or opened, startup continues with console and REST
logging and reports a warning there.

Set `RUST_LOG` to change all three outputs together. Standard tracing filter
directives are supported, for example `RUST_LOG=warn` or
`RUST_LOG=info,emulebb_core=debug`. The REST buffer keeps the newest 2,000
entries and truncates individual rendered messages at 4 KiB; clearing the REST
buffer does not delete the retained files.

When an enabled server list or persisted Kad bootstrap file is empty, startup
downloads and validates the same trusted defaults used by eMuleBB MFC. Existing
server data and non-empty `nodes.dat` files are never replaced. An offline or
failed bootstrap does not prevent the daemon and WebUI from starting.

The daemon serves the browser WebUI from a `webui` directory beside
`emulebb-rust.exe` when that directory exists. Set `[rest].webRootDir` to an
explicit asset directory to override that default; relative override paths are
resolved from the profile directory. The WebUI is mounted at the REST origin
root: primary views use clean history paths such as `/transfers` and selected
search sessions use `/searches/<id>`, while production assets are served from
`/assets`. Reverse-proxy subpath mounting is not part of the current deployment
contract. Browser API calls use the existing `X-API-Key` header.

Harnesses may use operator-local inputs to create the profile directory and
write those fixed files, but the Rust client itself only consumes the profile.

## Security

Report suspected vulnerabilities privately; do not place credentials, private
peer data, or exploit details in a public issue. Supported versions, the private
reporting link, and response expectations are in the [security policy](SECURITY.md).
Committed CodeQL analysis covers the Rust daemon, browser WebUI, Python release
tooling, and GitHub Actions workflows on every `main` change and on a weekly
schedule using the extended security query suite.

## Beta.2 artifacts

The public [release notes](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-0.1.0-beta.2-NOTES.md),
[changelog](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-0.1.0-beta.2-CHANGELOG.md),
and [release scope](https://github.com/emulebb/emulebb-tooling/blob/main/docs/products/emulebb-rust/RELEASE-SCOPE.md)
are the version-specific operator and compatibility references.

The manual [release workflow](.github/workflows/release.yml) retains unsigned
candidate artifacts for Windows, Linux, and macOS on x64 and ARM64. Native ZIP,
DEB/AppImage, and app-in-DMG packages include the daemon and browser WebUI. It
also builds and smoke-tests a Linux amd64/arm64 OCI image without publishing it.
The container base is digest-pinned, and both variants must pass a scan for
fixable high or critical vulnerabilities. Per-platform SPDX JSON SBOMs, scan
reports, and their checksums are retained and attached to a published release.
An approved `rust-v0.1.0-beta.2` tag is required to publish versioned GitHub
Release and GHCR assets; the workflow does not publish a `latest` image.

## Nightly beta builds

The scheduled [nightly workflow](.github/workflows/nightly.yml) runs daily at
02:17 UTC, with a 05:47 UTC fallback because GitHub schedules are best-effort.
It considers the latest `main` commit, verifies that the normal CI checks passed
for that exact SHA, and skips publishing when that commit already has a nightly,
so the fallback does not duplicate a successful publication. A manual run builds
candidates without publishing unless the operator explicitly enables its
`publish` input.

Published nightlies appear as prereleases on the
[GitHub Releases page](https://github.com/emulebb/emulebb-rust/releases). Each
one has an immutable version and tag derived from the promoted beta, date, and
source commit:

```text
0.1.0-beta.2.nightly.YYYYMMDD.g<8-character-commit>
rust-v0.1.0-beta.2.nightly.YYYYMMDD.g<8-character-commit>
```

Nightlies use the same Windows, Linux, macOS, x64, ARM64, and
multi-architecture container matrix as a formal beta. Download the native
package for the target platform from its prerelease. Container users can pin
the immutable `ghcr.io/emulebb/emulebb-rust:<version>` tag or follow the moving
`ghcr.io/emulebb/emulebb-rust:nightly` tag. The workflow never publishes a
`latest` tag, and formal betas remain version-only.

The small changelog on each nightly is automatic. It groups commit subjects
since the previous successful nightly into `Added`, `Fixed`, `Changed`, and
`Engineering`, links every listed commit, and includes the full GitHub source
comparison. It also compares the current-only metadata schema with the previous
successful nightly and explicitly calls out when a fresh profile is required.
No separate nightly changelog needs manual maintenance. Clear commit subjects
therefore produce better release notes; see
[`CONTRIBUTING.md`](CONTRIBUTING.md#nightly-release-notes).

Nightly binaries remain experimental and are not code-signed. Verify downloads
against the published `SHA256SUMS`; GitHub build-provenance attestations are
also published. The newest 14 nightly prereleases are retained, so use an
immutable version rather than the moving container tag when reproducibility
matters.

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
