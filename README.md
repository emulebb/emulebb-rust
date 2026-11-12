<p align="center">
  <img src="https://raw.githubusercontent.com/emulebb/emulebb.github.io/d247a016170b97cde00eb4659a2fe7ecd0766087/assets/brand/emulebb-logo-256.png" alt="eMuleBB pixel donkey" width="160" height="160">
</p>

# eMuleBB Rust

An IPv4 eD2K/Kad client for Windows, Linux and macOS. Search, download and share
from one headless daemon, with a browser console for everyday control and a REST
API for automation.

**Active beta.** Dated nightly prereleases are the current public testing channel.

| ↓ Use eMuleBB Rust | ⌘ Develop with eMuleBB Rust |
| --- | --- |
| [Download a nightly](https://github.com/emulebb/emulebb-rust/releases) | [Build and contribute](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/) |
| [Get started](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-GETTING-STARTED/) | [Connect to the API](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/GUIDE-API-CONSUMERS/) |

## Contents

- [What you can do](#what-you-can-do)
- [Downloads and platforms](#downloads-and-platforms)
- [Get started](#get-started)
- [Use the API](#use-the-api)
- [Develop and contribute](#develop-and-contribute)
- [Help and security](#help-and-security)
- [License](#license)

## What you can do

- Search eD2K/Kad and manage downloads from the browser console.
- Share monitored folder trees and choose network and sharing settings.
- Automate client operations through an authenticated, documented REST API.
- Inspect transfer and log state, and identify packages by source revision and
  published checksums.

## Downloads and platforms

Choose the matching runnable package from the
[nightly releases](https://github.com/emulebb/emulebb-rust/releases).
Verify it against that release's `SHA256SUMS` before launch. No Rust toolchain is
needed to use a prebuilt package.

| Platform | Architecture | Distribution |
| --- | --- | --- |
| Windows | x64 / ARM64 | ZIP |
| Linux | x64 / ARM64 | DEB, AppImage, static-musl tar/zstd |
| macOS | Intel / Apple Silicon | DMG; unsigned and not notarized |
| Docker / OCI | Linux amd64 / arm64 | GHCR Ubuntu and Alpine images |
| Android developers | arm64-v8a / x86_64 | Experimental native CLI bundles; **not an APK** |

Container images are published at
[`ghcr.io/emulebb/emulebb-rust`](https://github.com/emulebb/emulebb-rust/pkgs/container/emulebb-rust).
Use `nightly` or `nightly-ubuntu` for Ubuntu, and `nightly-alpine` for Alpine.
Versioned tags are available; pin a verified digest for a repeatable deployment.
There is no `latest` tag.

Native macOS package smoke runs on Intel and Apple Silicon. Android bundles
have compile/ELF checks; device runtime, completed-file delivery, route discovery
and VPN behavior remain unqualified. Linux musl bundles are separate from Android.

See [downloads and platforms](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-DOWNLOADS-PLATFORMS/)
for requirements, installation, container mounts and the scope of package checks.

## Get started

1. Install or extract the package for your system. Keep the complete layout,
   including the adjacent `webui` directory when using an archive.
2. Run `emulebb-rust.exe` on Windows, `./emulebb-rust` from a Linux archive, or
   the copied macOS app. Direct daemon launches use the directory containing
   the executable for TOML and database files, regardless of the shell working
   directory. Use `--profile <writable-directory>` to select another profile;
   missing profiles are created. `--profile .` selects the shell working
   directory, so it matches the default only when that is the executable folder.
   Desktop app launchers and Docker explicitly select the documented writable
   profile paths; the daemon never silently falls back to a home directory.
3. Open **<http://127.0.0.1:20017/>** and enter
   **`change_me_123change_me_123change_me_123`**. Review network and sharing
   settings before starting transfers.

The shipped API key is a shared starter value. Change `rest.api_key` in your
private bootstrap file before exposing the API outside this computer. The
default P2P ports are TCP **20019** and UDP **20020**; mutable client settings
remain in the profile database.

The default REST address is local control, not an offline-P2P guarantee: startup
may fetch discovery inputs and start configured networking.

**Profiles during beta:** an incompatible database requires an entirely fresh
profile. Keep the stopped old profile, payloads and matching binary intact for
explicit rollback; automatic unfinished-transfer continuation is not promised.

The [getting-started guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-GETTING-STARTED/)
covers profile locations, discovery, search, downloads, sharing and troubleshooting.

## Use the API

All `/api/v1` routes use the **`X-API-Key`** header. The daemon serves HTTP;
keep control on loopback or use a trusted TLS reverse proxy with restricted
access. Keep the key out of URLs, committed scripts and public logs.

Start with authenticated, read-only requests such as
`GET /api/v1/capabilities` and `GET /api/v1/status`.
The [API guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/GUIDE-API-CONSUMERS/)
includes private-key prompts, request examples and response handling. The
[OpenAPI contract](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/REST-API-OPENAPI.yaml)
defines the routes and schemas. The beta API is still evolving; check the
contract for the version you use.

## Develop and contribute

The [contributor guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/)
walks through prerequisites, managed workspace setup, source orientation and
supported checks. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution details
and the [roadmap](https://github.com/orgs/emulebb/projects/3) for current work.

Contributions can improve the client, browser console, integrations, tests or
documentation. Coordinate an actionable issue before implementation.

## Help and security

- **Troubleshooting:** [startup, listeners and logs](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-GETTING-STARTED/#common-problems).
- **Bug reports:** [open an issue](https://github.com/emulebb/emulebb-rust/issues)
  with the package version and sanitized reproduction steps.
- **Vulnerabilities:** follow the [private security reporting policy](SECURITY.md).

Diagnostic bundles are private operator evidence and can contain API keys,
paths, identifiers and logs. Never attach them unreviewed to a public report.

## License

[GPL-2.0-only](LICENSE). Dependencies retain their own licenses; see
[third-party notices](THIRD-PARTY-LICENSES.md).
