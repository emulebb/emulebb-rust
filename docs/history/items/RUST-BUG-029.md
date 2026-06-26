---
id: RUST-BUG-029
workflow: local
title: REST server mutation bodies bypass MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-029 - REST server mutation bodies bypass MFC validation

## Summary

Rust delegated `POST /api/v1/servers` and
`PATCH /api/v1/servers/{serverId}` body-shape checks to serde/core handling.
eMuleBB MFC validates server mutation bodies in the route seam before command
dispatch, with canonical messages for `address`, `port`, `name`, `priority`,
`static`, `connect`, and empty PATCH bodies. MFC also trims accepted server
addresses before dispatch.

## Acceptance Criteria

- [x] Server create bodies require `address` as a non-empty string.
- [x] Accepted server create addresses are ASCII-trimmed before core handling.
- [x] Server create bodies require `port` in the range `1..65535`.
- [x] Optional `name`, `priority`, `static`, and `connect` fields use MFC body
      shape messages.
- [x] Server PATCH bodies require at least one of `name`, `priority`, or
      `static`.
- [x] Server PATCH `name`, `priority`, and `static` fields use MFC body shape
      messages.
- [x] Focused REST body validation tests cover the MFC messages.

## Resolution

- Added MFC-style server create/update validation to REST body metadata
  middleware.
- Registered body field allowlists for server create/update routes.
- Trimmed accepted server create addresses before adding the server.
- Extended route body validation and server CRUD tests.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
