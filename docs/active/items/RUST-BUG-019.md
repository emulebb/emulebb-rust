---
id: RUST-BUG-019
workflow: local
title: Transfers categoryId query uses serde-shaped errors
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-019 - Transfers categoryId query uses serde-shaped errors

## Summary

Rust parsed `GET /api/v1/transfers?categoryId=...` through the generic
`serde_urlencoded` DTO path, so invalid or out-of-range values produced
serde-shaped error text. eMuleBB MFC validates `categoryId` centrally as a
strict unsigned decimal token bounded to `UINT_MAX`, with stable field-specific
messages.

## Acceptance Criteria

- [x] Non-unsigned `categoryId` query values are rejected as
  `categoryId must be an unsigned number`.
- [x] Values above `u32::MAX` are rejected as `categoryId is out of range`.
- [x] Valid values, including `0`, remain accepted.
- [x] Existing query name, duplicate, boolean, and state validations remain
  intact.

## Resolution

- Added central `categoryId` query validation to the REST route metadata
  validator.
- Matched MFC's strict unsigned decimal handling: no signs, whitespace, or
  partial numeric tokens.
- Added regression coverage for invalid, out-of-range, and valid category IDs.

## Evidence

- `cargo test -p emulebb-rest transfers_category_id_query_uses_mfc_unsigned_validation --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
