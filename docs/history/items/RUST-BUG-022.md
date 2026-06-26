---
id: RUST-BUG-022
workflow: local
title: REST categoryId body fields bypass MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-022 - REST categoryId body fields bypass MFC validation

## Summary

Rust delegated `categoryId` JSON body fields to serde DTO extraction. eMuleBB
MFC validates category selectors in the route metadata seam before dispatch,
rejecting non-unsigned JSON numbers, `null`, and values above `UINT_MAX` with
canonical `INVALID_ARGUMENT` messages.

Affected supported routes:

- `POST /api/v1/transfers`
- `PATCH /api/v1/transfers/{hash}`
- `POST /api/v1/searches/{searchId}/results/{hash}/operations/download`

## Acceptance Criteria

- [x] `categoryId` body values that are strings, negative numbers, `null`, or
      other non-unsigned JSON numbers fail with
      `categoryId must be an unsigned number`.
- [x] `categoryId` body values above `UINT_MAX` fail with
      `categoryId is out of range`.
- [x] The REST route metadata middleware enforces the MFC validation order
      before handler/core dispatch.
- [x] DTO deserialization keeps the same checks as a defensive fallback.
- [x] The oversized REST model source is reduced below the policy cap while
      adding the validation helper.

## Resolution

- Added MFC-style `categoryId` body validation to REST route metadata for the
  supported category-selector body routes.
- Added serde fallback validation for the same DTO fields.
- Normalized serde JSON error location suffixes in REST error messages.
- Extracted REST-model serde helper functions into a smaller module to keep
  `rest_model.rs` within the Rust client file-size policy.
- Added focused route body validation tests.

## Evidence

- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
