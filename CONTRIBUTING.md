# Contributing To emulebb-rust

`emulebb-rust` is the active forward eD2K/Kad client in the eMuleBB suite. The
first useful contributions should stay small, preserve stock-compatible protocol
behavior, and keep the embedded SPA WebUI, REST contract, and tests aligned.

## Beta Change Policy

The public beta remains experimental. Release-candidate changes are accepted
only when they are one of the following:

- a release blocker;
- a test or evidence fix;
- a documentation correction;
- a packaging fix.

Do not start indexer or Arr integration, major refactors, or new protocol
features during the freeze. In particular, `RUST-FEAT-002`, `RUST-FEAT-004`,
and `RUST-REF-005` through `RUST-REF-007` remain post-beta work. A test/evidence
label does not authorize unrelated cleanup or feature work. Coordinate allowed
work through [RUST-FEAT-033](https://github.com/emulebb/emulebb-rust/issues/20)
and the public suite board before implementation.

## Start Here

- Read `README.md` for the repo shape and local quality gates.
- Read `AGENTS.md` for repo-local policy, especially Rust API, schema, and build
  output rules.
- Use the public suite board for workflow state:
  <https://github.com/orgs/emulebb/projects/3>
- Confirm that proposed work satisfies one of the four freeze admission classes
  before implementation. Older issue labels and starter suggestions do not
  override the freeze.

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
