---
id: RUST-BUG-034
status: done
type: bug
area: rest
---

# RUST-BUG-034: Align preferences PATCH body validation with MFC

## Problem

The Rust REST preferences PATCH route relied on serde and core-layer validation
for most request-body failures. The MFC seam validates the body before dispatch,
including an empty-body check, unsigned preference ranges, and boolean
preference types with stable `INVALID_ARGUMENT` messages.

## Resolution

- Added the `PATCH /api/v1/app/preferences` body field allowlist.
- Added MFC-parity request-body validation for the mutable unsigned and boolean
  preferences.
- Covered invalid preferences PATCH payloads in REST route-body tests.
- Moved preferences validation into a focused validator submodule to avoid
  growing the shared route-body validator file.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
