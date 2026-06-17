---
id: RUST-BUG-013
workflow: local
title: REST routes without query specs accept unknown query fields
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-013 - REST routes without query specs accept unknown query fields

## Summary

Rust only validated query strings in handlers that explicitly parsed a query
DTO. eMuleBB MFC validates query names centrally against the route spec table,
and a route with an empty query field list rejects any query parameter. As a
result, Rust accepted and ignored unsupported query parameters on routes such as
`GET /api/v1/uploads` or `GET /api/v1/app`.

## Acceptance Criteria

- [x] Routes with no declared query parameters reject unknown query fields.
- [x] Routes with declared query parameters still accept their supported names.
- [x] Unknown routes and wrong-method routes keep their existing 404/405
  behavior.
- [x] Existing per-handler query parsing still validates value shape and range.

## Resolution

- Added centralized route-query whitelist validation in the REST router.
- Kept `/api/v1/capabilities` as a Rust capability discovery extension with no
  query parameters.
- Added regression coverage for no-query routes and allowed-query routes.

## Evidence

- `cargo test -p emulebb-rest query_routes_use_canonical_error_envelope --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
