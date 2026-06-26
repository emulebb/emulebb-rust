---
id: RUST-BUG-024
workflow: local
title: REST transfer-add link fields bypass MFC body validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-024 - REST transfer-add link fields bypass MFC body validation

## Summary

Rust delegated `POST /api/v1/transfers` `link`/`links` body validation to serde
and later core parsing. eMuleBB MFC validates transfer-add body shape in the
route metadata seam before dispatch, including canonical messages for string
type checks, empty arrays, oversized link batches, and invalid link-array
members.

## Acceptance Criteria

- [x] `link` must be a string.
- [x] A single `link` is trimmed and rejected when empty, too long, containing
      whitespace/control characters, or not starting with `ed2k://`.
- [x] `links` must be an array.
- [x] `links` must not be empty.
- [x] `links` must contain at most 100 items.
- [x] Every `links` item must be a non-empty eD2K string, with MFC's aggregate
      `links must be a non-empty string array` message for item failures.
- [x] Focused REST route body validation tests cover the MFC messages.

## Resolution

- Added MFC-style transfer-add `link`/`links` shape validation to REST body
  metadata middleware.
- Kept deeper eD2K link parsing in the existing core path; this slice covers
  the route seam's body-shape validation and message parity.
- Extended route body validation tests.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
