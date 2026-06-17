---
id: RUST-BUG-023
workflow: local
title: REST paused body fields bypass MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-023 - REST paused body fields bypass MFC validation

## Summary

Rust delegated `paused` JSON body fields to serde DTO extraction. eMuleBB MFC
validates `paused` in the route metadata seam before dispatch and rejects any
present non-boolean JSON value with the canonical
`paused must be a boolean` message.

Affected supported routes:

- `POST /api/v1/transfers`
- `POST /api/v1/searches/{searchId}/results/{hash}/operations/download`

For `POST /api/v1/transfers`, MFC validates the `link`/`links` selector before
checking `paused`; Rust now preserves that order in the route metadata
middleware.

## Acceptance Criteria

- [x] String, numeric, `null`, and other non-boolean `paused` body values fail
      with `paused must be a boolean`.
- [x] `POST /api/v1/transfers` reports missing or mutually exclusive
      `link`/`links` before `paused`, matching MFC validation order.
- [x] DTO deserialization keeps the same `paused` type check as a defensive
      fallback.
- [x] Focused REST route body validation tests cover the supported routes.

## Resolution

- Added MFC-style `paused` body validation to REST route metadata.
- Added minimal transfer-add selector validation in route metadata to preserve
  MFC ordering before `paused`.
- Added serde fallback validation for `paused` DTO fields.
- Extended route body validation tests.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
