---
id: RUST-BUG-017
workflow: local
title: Transfers accepts invalid state query values
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-017 - Transfers accepts invalid state query values

## Summary

Rust accepted arbitrary `GET /api/v1/transfers?state=...` values and returned
an empty page when no transfer state matched. eMuleBB MFC validates the `state`
query value during central route parsing and rejects tokens outside the REST
transfer-state vocabulary.

## Acceptance Criteria

- [x] Invalid `state` query values are rejected before handler dispatch.
- [x] Valid state values remain accepted.
- [x] The rejection message matches the MFC REST contract.
- [x] Existing query name decoding, duplicate rejection, and pagination
  validation remain intact.

## Resolution

- Added transfer-state vocabulary validation to the central REST route metadata
  validator.
- Reused the existing decoded query field parse so escaped parameter names and
  duplicate detection keep their MFC order.
- Added regression coverage for invalid and valid transfer-state query values.

## Evidence

- `cargo test -p emulebb-rest transfers_reject_unknown_state_query_values --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
