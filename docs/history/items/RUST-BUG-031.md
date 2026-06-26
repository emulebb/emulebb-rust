---
id: RUST-BUG-031
status: done
type: bug
area: rest
---

# RUST-BUG-031: Align category mutation body validation with MFC

## Problem

The Rust REST category create/update routes relied on serde and core-layer
validation for several payload-shape failures. The MFC seam validates these
request bodies before dispatch and returns stable `INVALID_ARGUMENT` messages
for missing names, empty patches, path shape, comment type, RGB color bounds,
and category priority shape.

## Resolution

- Added route metadata field allowlists for `POST /api/v1/categories` and
  `PATCH /api/v1/categories/{categoryId}`.
- Added MFC-parity validators for category create and patch request bodies.
- Covered invalid category create/update payloads in REST route-body tests.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
