---
id: RUST-BUG-038
status: done
type: bug
area: rest
---

# RUST-BUG-038: Validate diagnostic dump fullMemory body type

## Problem

MFC rejects `POST /api/v1/diagnostics/dumps` bodies where `fullMemory` is
present but not a boolean. Rust accepted the field through route metadata and
left the mismatch to handler deserialization, producing a non-MFC error seam.

## Resolution

- Added route-level validation for the optional `fullMemory` boolean after the
  destructive `confirmDump` check.
- Refactored optional boolean body validation so `paused` and `fullMemory` share
  the same small helper.
- Added route body validation coverage for the MFC error message and validation
  ordering.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
