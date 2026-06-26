---
id: RUST-BUG-015
workflow: local
title: REST DELETE routes accept ignored request bodies
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-015 - REST DELETE routes accept ignored request bodies

## Summary

Rust accepted non-empty JSON request bodies on registered REST `DELETE` routes
and then ignored them in the handler. eMuleBB MFC validates the registered route
and query first, then rejects non-empty `DELETE` bodies with
`DELETE request bodies are not supported`.

## Acceptance Criteria

- [x] Registered REST `DELETE` routes reject non-empty request bodies.
- [x] Route/query validation still runs before the body rejection.
- [x] Unknown routes and method-not-allowed requests are not reclassified as
  body-validation failures.
- [x] JSON content-type validation remains unchanged for non-`DELETE` write
  bodies.

## Resolution

- Replaced separate query and content-type middleware with a route-scoped REST
  metadata validator.
- Matched the MFC validation order: registered route, query fields, `DELETE`
  body rejection, then JSON content type.
- Added regression coverage for `DELETE` body rejection and route/query
  precedence.

## Evidence

- `cargo test -p emulebb-rest delete_routes_reject_request_bodies_after_route_query_validation --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
