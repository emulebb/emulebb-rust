---
id: RUST-BUG-025
workflow: local
title: REST transfer PATCH body shape bypasses MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-025 - REST transfer PATCH body shape bypasses MFC validation

## Summary

Rust delegated `PATCH /api/v1/transfers/{hash}` mutation-family and field
shape validation to DTO/core handling. eMuleBB MFC validates this body in the
route metadata seam before dispatch, including the single-mutation-family rule
and canonical `priority`/`name` errors.

## Acceptance Criteria

- [x] Empty transfer PATCH bodies fail with
      `transfer PATCH requires priority, categoryId, categoryName, or name`.
- [x] Transfer PATCH bodies containing more than one mutation family fail with
      `transfer PATCH accepts only one mutation family`.
- [x] `priority` must be a string.
- [x] `priority` must be one of `auto`, `verylow`, `low`, `normal`, `high`, or
      `veryhigh`.
- [x] `name` must be a string.
- [x] Trimmed `name` must not be empty.
- [x] Invalid public eD2K file names fail with the canonical transfer rename
      message.
- [x] Focused REST route body validation tests cover the MFC messages.

## Resolution

- Added MFC-style transfer PATCH body validation to REST body metadata
  middleware.
- Reused the existing route metadata flow so body validation still runs after
  path/query checks and before handler/core dispatch.
- Extended route body validation tests.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
