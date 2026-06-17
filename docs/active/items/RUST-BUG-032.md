---
id: RUST-BUG-032
status: done
type: bug
area: rest
---

# RUST-BUG-032: Align friend-create body validation with MFC

## Problem

The Rust REST friend-create route relied on serde and core-layer validation for
payload-shape failures. The MFC seam validates `POST /api/v1/friends` before
dispatch, including the `userHash` MD4 lowercase-hex shape and optional friend
name string limits.

## Resolution

- Added the `POST /api/v1/friends` body field allowlist to route metadata.
- Added MFC-parity request-body validation for `userHash` and optional `name`.
- Covered invalid friend-create request bodies in REST route-body tests.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
