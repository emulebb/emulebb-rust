---
id: RUST-BUG-033
status: done
type: bug
area: rest
---

# RUST-BUG-033: Align search-create body validation with MFC

## Problem

The Rust REST search-create route did not apply the MFC seam's pre-dispatch
request-body validation. Invalid search bodies could therefore fall through to
serde or core behavior with non-canonical messages, and accepted queries were
not normalized with the native REST ASCII-whitespace rules before dispatch.

## Resolution

- Added the `POST /api/v1/searches` body field allowlist.
- Added MFC-parity validation for `query`, `method`, `type`, `extension`,
  `minSizeBytes`, `maxSizeBytes`, and `minAvailability`.
- Normalized accepted search queries before core dispatch.
- Moved search-create validation into a focused validator submodule to keep the
  shared route-body validator file below the source-size budget.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
