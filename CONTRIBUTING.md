# Contributing To emulebb-rust

`emulebb-rust` is the active forward eD2K/Kad client in the eMuleBB suite. The
first useful contributions should stay small, preserve stock-compatible protocol
behavior, and keep the embedded SPA WebUI, REST contract, and tests aligned.

## Start Here

- Read `README.md` for the repo shape and local quality gates.
- Read `AGENTS.md` for repo-local policy, especially Rust API, schema, and build
  output rules.
- Use the public suite board for workflow state:
  <https://github.com/orgs/emulebb/projects/3>
- Prefer starter issues labeled `good first issue` or `help wanted`.

Good starter areas are:

- `RUST-CI-003`: wire OpenAPI conformance/drift checks into CI.
- `RUST-REF-005`: small behavior-preserving module decomposition slices.
- `RUST-FEAT-036`: focused embedded WebUI/settings polish.

Avoid taking the automated VPN leak-test gate (`RUST-FEAT-005`) as a first task
unless you already have the required Windows/VPN test environment.

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
