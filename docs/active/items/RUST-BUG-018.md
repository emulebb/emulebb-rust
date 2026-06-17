---
id: RUST-BUG-018
workflow: local
title: REST boolean query errors use non-MFC messages
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-018 - REST boolean query errors use non-MFC messages

## Summary

Rust delegated boolean query value parsing to `serde_urlencoded`, so invalid
values on `confirm`, `includeScoreBreakdown`, `includeEvidence`, and
`exactTotal` produced serde-shaped error text. eMuleBB MFC validates these
fields centrally and reports `<field> must be true or false`.

## Acceptance Criteria

- [x] Invalid REST boolean query values are rejected before handler dispatch.
- [x] Rejection messages match the MFC field-specific text.
- [x] Lowercase `true` and `false` remain accepted.
- [x] Existing decoded query-name, duplicate, and transfer-state validations
  keep their current behavior.

## Resolution

- Added central boolean query value validation to the REST route metadata
  validator.
- Covered every MFC boolean query field currently present in the `/api/v1`
  route spec.
- Added regression coverage for invalid values plus a valid `false` value.

## Evidence

- `cargo test -p emulebb-rest boolean_query_values_use_mfc_validation_messages --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
