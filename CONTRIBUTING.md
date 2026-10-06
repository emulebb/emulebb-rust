# Contributing To emulebb-rust

`emulebb-rust` is the active forward eD2K/Kad client in the eMuleBB suite. The
first useful contributions should stay small, preserve stock-compatible protocol
behavior, and keep the embedded SPA WebUI, REST contract, and tests aligned.

## Change Policy

The public beta remains experimental, but the former pre-release freeze has
ended. Every actionable change still needs a stable work-item ID and a public
issue on the [eMuleBB Roadmap](https://github.com/orgs/emulebb/projects/3)
before implementation. Keep each commit to one coherent change and include the
stable ID in its subject.

Changes must preserve the stock-compatible wire protocol, the Rust-native async
runtime model, and the current-only profile policy described in `AGENTS.md` and
the routed product documentation. Do not add migration, repair, or reset paths
for older Rust metadata schemas; an incompatible profile must fail with a clear
fresh-profile instruction.

Large refactors, new integrations, and protocol changes remain separately
scoped work. Do not fold unrelated cleanup into a bug fix, documentation
change, test/evidence update, or packaging change.

## Start Here

- Read `README.md` for the repo shape and local quality gates.
- Read `AGENTS.md` for repo-local policy, especially Rust API, schema, and build
  output rules.
- Use the public suite board for workflow state:
  <https://github.com/orgs/emulebb/projects/3>
- Confirm that the issue states the intended compatibility and validation scope
  before implementation. Older labels and starter suggestions do not broaden
  that scope.

## Local Checks

For docs or small policy-sensitive edits:

```powershell
python tools\rust_quality_gate.py policy
```

For normal Rust code changes, use the scoped gate that matches the changed
surface. The CI baseline is:

```powershell
python tools\rust_quality_gate.py quick
```

For embedded SPA WebUI changes:

```powershell
python tools\rust_quality_gate.py webui-test
```

All local Cargo work must use the workspace output root through
`CARGO_TARGET_DIR`; never create a repo-local `target` directory.

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

See [Nightly beta builds](README.md#nightly-beta-builds) for the publishing,
versioning, retention, and download policy.
