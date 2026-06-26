---
id: RUST-BUG-035
status: done
type: bug
area: rest
---

# RUST-BUG-035: Align destructive confirmation body validation with MFC

## Problem

Rust REST handlers validated destructive confirmation flags after dispatch for
several routes, and the shared route-body metadata did not list every accepted
confirmation field. The MFC seam applies `RequireBooleanFieldTrue` before
dispatch for shutdown, diagnostics, clear operations, and shared-directory root
replacement, producing stable `INVALID_ARGUMENT` failures.

## Resolution

- Added route body allowlists for destructive confirmation endpoints.
- Added shared MFC-parity confirmation validation for shutdown, diagnostic dump,
  crash test, clear-completed transfers, clear logs, and shared-directory root
  replacement.
- Preserved the MFC validation order for `PATCH /api/v1/shared-directories`:
  root shape is checked before `confirmReplaceRoots`.
- Covered destructive confirmation failures in REST route-body validation tests.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
