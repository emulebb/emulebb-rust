---
id: RUST-BUG-037
status: done
type: bug
area: rest
---

# RUST-BUG-037: Match diagnostic dump response shape with MFC

## Problem

Rust returned diagnostic dump response fields that are not part of the MFC
native REST shape or the OpenAPI contract. eMuleBB MFC returns only `ok`, `path`,
and `fullMemory` for `POST /api/v1/diagnostics/dumps`; Rust additionally exposed
`kind` and `sizeBytes`.

## Resolution

- Removed the extra `kind` and `sizeBytes` fields from the public
  `DiagnosticDumpResult` DTO.
- Kept the richer internal JSON dump payload unchanged on disk.
- Tightened the REST route test to assert the contracted three-field response
  shape.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_app --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
