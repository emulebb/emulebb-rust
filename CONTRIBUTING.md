# Contributing To emulebb-rust

Start with the canonical
[contributor guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/)
for repository roles, pinned prerequisites, managed workspace setup, supported
checks and subsystem orientation. API users can instead follow the
[API-consumer journey](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/api/GUIDE-API-CONSUMERS/).

## Change Policy

The public beta is compatibility-unstable. Every actionable change needs a stable
work-item ID and a public issue on the [eMuleBB Roadmap](https://github.com/orgs/emulebb/projects/3)
before implementation. Keep each commit to one coherent change and include the
stable ID in its subject.

Changes must preserve the stock-compatible wire protocol, the Rust-native async
runtime model, and the current-only profile policy described in `AGENTS.md` and
the routed product documentation. Minimal TOML bootstrap stability is separate
from the explicitly unstable beta API/database. Do not add migration, repair, or reset paths
for older Rust metadata schemas; an incompatible profile must fail with a clear
fresh-profile instruction.

Large refactors, new integrations, and protocol changes remain separately
scoped work. Do not fold unrelated cleanup into a bug fix, documentation
change, test/evidence update, or packaging change.

## Start Here

- Read `README.md` for the product and user/developer entry points.
- Read `AGENTS.md` for repo-local policy, especially Rust API, schema, and build
  output rules.
- Use the public suite board for workflow state:
  <https://github.com/orgs/emulebb/projects/3>
- Confirm the issue's intended compatibility and validation scope before
  implementation, and keep the change within that scope.

## Local Checks

Use `python -m emule_workspace` from the supported Builder checkout with the
assigned `--workstream`. The
[contributor guide](https://emulebb.github.io/emulebb-tooling/products/emulebb-rust/reference/GUIDE-CONTRIBUTING/#run-supported-checks)
shows scoped Rust and WebUI commands. Inherit the operator's valid workspace,
output and Cargo variables; never create repo-local targets or repair variables
inline.

Normal commit/push hooks and hosted checks remain required. The parent assigns
one worker per checkout, reserves shared files and allocates the single heavy
local owner. Parallel editing does not authorize a competing native/Docker/live
run. Resolve a failing check before continuing; a cache hit is not qualification
for a different source revision.

## Nightly Release Notes

Automated nightly beta builds use commit subjects as their changelog source.
Every commit added to `main` since the previous successful nightly can appear
in the next prerelease notes, with a link to the exact commit and the full
source comparison.

Write a concise, user-readable subject that says what changed. The release-note
generator understands work-item prefixes such as
`RUST-CI-007: publish immutable nightly builds` and conventional prefixes such
as `fix: reject an invalid server address`. It groups entries into `Added`,
`Fixed`, `Changed`, and `Engineering`; contributors do not maintain a separate
nightly changelog.

See [downloads and platforms](README.md#downloads-and-platforms) for current
packages and verification, and the contributor guide for supported delivery.

## Security And Licensing

Use [private vulnerability reporting](SECURITY.md) for suspected security defects.
Keep credentials, private peer data and raw diagnostic bundles out of public
issues. Contributions follow [GPL-2.0-only](LICENSE) and the
[third-party notice requirements](THIRD-PARTY-LICENSES.md).
