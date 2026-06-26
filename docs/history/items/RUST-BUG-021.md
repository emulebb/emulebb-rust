---
id: RUST-BUG-021
workflow: local
title: REST path parameters bypass MFC metadata validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-021 - REST path parameters bypass MFC metadata validation

## Summary

Rust delegated several REST path parameters to Axum path extraction or later
handler/core lookups. eMuleBB MFC validates template parameters in the route
metadata seam before query validation and dispatch, producing canonical
`INVALID_ARGUMENT` messages for malformed `categoryId`, hash/userHash,
`serverId`, and `clientId` values.

`searchId` remains a separate parity gap: the current MFC seam treats it as a
bounded unsigned decimal id while Rust currently exposes search ids as UUID
strings. That needs a model-level migration rather than a metadata-only fix.

## Acceptance Criteria

- [x] Category path ids reject non-decimal values with
      `categoryId must be an unsigned decimal string`.
- [x] Category path ids reject values above `UINT_MAX` with
      `categoryId is out of range`.
- [x] Hash path parameters reject non-lowercase or non-32-character hex values
      with the MFC hash/userHash message.
- [x] Server path ids reject tokens outside `address:port` with a port in
      `1..65535`.
- [x] Client path ids accept either lowercase MD4 hex or `address:port`, and
      reject other values with the MFC clientId message.
- [x] Valid path parameters still reach their route handlers.

## Resolution

- Added MFC-style path parameter validation to the REST route metadata
  middleware, after route matching and before query/body metadata validation.
- Kept `searchId` validation out of this slice and documented it as a separate
  model-level parity gap.
- Added focused route path validation tests.

## Evidence

- `cargo test -p emulebb-rest route_path_validation --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
