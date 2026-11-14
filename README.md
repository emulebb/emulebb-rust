<p align="center">
  <img src="https://emulebb.github.io/assets/brand/rust-social-preview.png" alt="eMuleBB Rust: eD2K and Kad with browser control on Windows, Linux and macOS" width="960" height="480" />
</p>

<h1 align="center">eMuleBB Rust</h1>

<p align="center">
  <strong>eD2K and Kad. Browser control. REST automation.</strong><br />
  Search, download and share with one headless IPv4 daemon.
</p>

<p align="center">
  <a href="https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-GETTING-STARTED.md"><strong>Use eMuleBB Rust</strong></a> &nbsp;&middot;&nbsp;
  <a href="https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/"><strong>Develop with eMuleBB Rust</strong></a>
</p>
<p align="center">
  <a href="https://github.com/emulebb/emulebb-rust/releases">Nightly downloads</a> &middot;
  <a href="#downloads-and-platforms">Platforms</a> &middot;
  <a href="https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/GUIDE-API-CONSUMERS/">REST API</a> &middot;
  <a href="https://github.com/orgs/emulebb/projects/3">Roadmap</a> &middot;
  <a href="#help-and-security">Help</a>
</p>
<p align="center">
  <a href="https://github.com/emulebb/emulebb-rust/actions/workflows/ci.yml"><img src="https://github.com/emulebb/emulebb-rust/actions/workflows/ci.yml/badge.svg?branch=main" alt="Rust CI" /></a>
  <a href="https://github.com/emulebb/emulebb-rust/actions/workflows/codeql.yml"><img src="https://github.com/emulebb/emulebb-rust/actions/workflows/codeql.yml/badge.svg?branch=main" alt="CodeQL workflow" /></a>
  <a href="LICENSE">GPL-2.0-only</a>
</p>

**Active beta.** Dated nightly prereleases are the current public testing
channel. Prebuilt packages need no Rust toolchain.

## What you can do

<table>
<tr>
<td width="50%" valign="top">
<h3>Search and transfer</h3>
<p>Search eD2K/Kad, add downloads and follow transfer progress from the packaged browser console.</p>
</td>
<td width="50%" valign="top">
<h3>Share chosen folders</h3>
<p>Monitor recursive folder trees, review hashing and manage sharing settings.</p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<h3>Automate through REST</h3>
<p>Connect integrations to an authenticated API with a documented OpenAPI contract.</p>
</td>
<td width="50%" valign="top">
<h3>Inspect your client</h3>
<p>Review network status, diagnostics, logs and source-bound package checksums.</p>
</td>
</tr>
</table>

## Downloads and platforms

Choose a runnable asset from the [nightly releases](https://github.com/emulebb/emulebb-rust/releases),
then compare its exact filename against that release's `SHA256SUMS`.
The [platform run guide](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md)
owns installation commands, profile paths, requirements and qualification scope.

| Platform | Choose | Install and run |
| --- | --- | --- |
| Windows | x64 or ARM64 ZIP | [Extract and launch](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#windows-x64-and-arm64) |
| Linux | x64 or ARM64 DEB, AppImage or static-musl tar/zstd | [Choose a Linux variant](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#linux) |
| macOS | Intel or Apple Silicon DMG | [Copy and launch the app](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#macos-intel-and-apple-silicon) |
| Docker / OCI | Linux amd64 or arm64; Ubuntu or Alpine | [Run with persistent volumes](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#containers) |
| Android APK | Universal ARM64 + x86_64; Android 14+ | [Permissions, manual Start and WebUI](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#android-application) |
| Android / Termux native | Experimental `android-arm64-v8a.tar.zst` or `android-x86_64.tar.zst` | [Extract under private HOME and launch](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md#termux-native-shell) |

The macOS app is unsigned and not notarized. For containers, both
[`ghcr.io/emulebb/emulebb-rust`](https://github.com/emulebb/emulebb-rust/pkgs/container/emulebb-rust)
variants publish versioned tags and moving `nightly` / `nightly-ubuntu` /
`nightly-alpine` aliases; there is no `latest` tag.

**Android remains experimental.** Use the signed APK only when the selected
published release includes it after qualification. Both native ABI archives
remain separate public nightly assets alongside that APK. Their API 28 binary
floor and compile/ELF evidence do not qualify Termux runtime, the full Android
API matrix, Fire OS or 24-hour continuous operation. The APK minimum is Android
14/API 34; its foreground service starts manually and has no boot-resume option.
See [Android evidence and remaining acceptance](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/active/items/RUST-FEAT-056.md).

## Get started

1. Follow your [platform's run instructions](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS.md).
   Keep the complete extracted archive layout, including `webui`.
2. Open **<http://127.0.0.1:20017/>** on the daemon host. The default listener
   is **`0.0.0.0:20017`**. Native packages use the ready key
   **`change_me_123change_me_123change_me_123`**; the APK supplies a generated
   key through **Copy API key** and **Open WebUI**.
3. Review network, incoming and shared-folder settings, then search or add a
   download. Default P2P ports are TCP **20019** and UDP **20020**.

Direct daemon launches keep the profile beside the executable, independently
of the working directory. Select another writable profile with `--profile`.
Desktop launchers, containers and the APK explicitly choose their documented
profile paths. The private `emulebb-rust-settings.toml` owns REST bootstrap
settings; mutable client settings live in the profile database.

Startup may fetch discovery inputs and start configured networking. During beta,
an incompatible database requires an entirely fresh profile; preserve the
stopped old profile, payloads and matching binary for rollback. The
[getting-started guide](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-GETTING-STARTED.md)
covers everyday operation, shutdown and troubleshooting.

## Use the API

All `/api/v1` routes use the **`X-API-Key`** header. Start with read-only
`GET /api/v1/capabilities` and `GET /api/v1/status`; keep credentials in headers.

- [API consumer guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/GUIDE-API-CONSUMERS/)
- [OpenAPI contract](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/REST-API-OPENAPI.yaml)

The beta API is still evolving; use the contract for your selected build.

<details>
<summary>Android native HTTPS trust</summary>

Native CLI bundles verify certificates and hostnames with packaged Mozilla CA
roots, without a JVM. Android/Termux CA stores and `SSL_CERT_FILE` do not extend
this trust set. Updated roots arrive with new client builds.

</details>

## Develop and contribute

<table>
<tr>
<td width="50%" valign="top">
<h3>Work on the client</h3>
<p>Improve the daemon, browser console, tests or documentation.</p>
<a href="https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/">Build and validation guide</a> &middot; <a href="CONTRIBUTING.md">Contributing</a>
</td>
<td width="50%" valign="top">
<h3>Find the next change</h3>
<p>Review current work and coordinate an actionable issue before implementation.</p>
<a href="https://github.com/orgs/emulebb/projects/3">Roadmap</a> &middot; <a href="https://github.com/emulebb/emulebb-rust/issues">Issues</a>
</td>
</tr>
</table>

## Help and security

- [Troubleshoot startup, listeners and logs](https://github.com/emulebb/emulebb-tooling/blob/efe57c9408953c61a2dda4373d6c006ce688fadd/docs/products/emulebb-rust/reference/GUIDE-GETTING-STARTED.md#common-problems).
- [Report a bug](https://github.com/emulebb/emulebb-rust/issues) with the package
  version and sanitized reproduction steps.
- Follow [private security reporting](SECURITY.md) for vulnerabilities.

Diagnostic bundles are private operator evidence and can contain credentials,
paths, identifiers and logs. Review them before sharing publicly.

## License

[GPL-2.0-only](LICENSE). Dependencies retain their own licenses; see
[third-party notices](THIRD-PARTY-LICENSES.md).
