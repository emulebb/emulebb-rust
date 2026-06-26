---
id: RUST-BUG-020
workflow: local
title: Numeric REST query values use serde-shaped errors
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-020 - Numeric REST query values use serde-shaped errors

## Summary

Rust validated route names and several typed query values centrally, but `limit`
and `offset` still reached the serde query parser first on some paths. Invalid
values such as `limit=-1`, `limit=abc`, or `offset=-1` therefore produced
serde-shaped messages instead of the eMuleBB MFC contract:
`<field> must be an unsigned number`.

The current MFC route seam validates every allowed `limit` query in the range
`1..1000`, every allowed `offset` query in the range `0..2147483647`, and
`categoryId` in the range `0..UINT_MAX` before command dispatch.

## Acceptance Criteria

- [x] `limit` rejects non-decimal values with `limit must be an unsigned number`.
- [x] `offset` rejects non-decimal values with `offset must be an unsigned number`.
- [x] `limit` rejects values outside `1..1000` with bounded error details.
- [x] `offset` rejects values above `2147483647` with bounded error details.
- [x] Snapshot and logs routes use the same MFC metadata validation as the other
      limited REST routes.
- [x] `categoryId` keeps its MFC unsigned/range validation.

## Resolution

- Added a shared bounded unsigned query parser to the REST route-metadata
  middleware.
- Applied it to `limit`, `offset`, and `categoryId` before typed query parsing.
- Updated snapshot and log tests to reflect the current MFC validation order:
  invalid `limit` values are rejected before downstream clamp/default logic.

## Evidence

- `cargo test -p emulebb-rest pagination_rejects_out_of_range_bounds_with_details --locked`
- `cargo test -p emulebb-rest all_limited_routes_reject_out_of_range_limit_like_mfc --locked`
- `cargo test -p emulebb-rest snapshot_limit_rejects_out_of_range_values_like_master --locked`
- `cargo test -p emulebb-rest logs_limit_matches_master_query_semantics --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
