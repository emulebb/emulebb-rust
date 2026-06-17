---
id: RUST-BUG-041
status: done
type: bug
area: rest
---

# RUST-BUG-041: Validate destructive query confirmations in route metadata

## Problem

MFC validates query-based destructive confirmations in the route seam for
`DELETE /api/v1/searches`, `DELETE /api/v1/shared-files/{hash}/file`, and
`DELETE /api/v1/transfers/{hash}/files`. Rust allowed those requests to reach
handlers when `confirm=true` was missing or false, producing handler-level
`BAD_REQUEST` errors instead of the MFC `INVALID_ARGUMENT` route error.

## Resolution

- Added route metadata validation that requires `confirm=true` for the three
  destructive query-confirmed routes.
- Kept boolean syntax validation first, so invalid values still report
  `confirm must be true or false`.
- Added query validation tests for missing and false confirmations.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest destructive_query_confirmations_use_mfc_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
