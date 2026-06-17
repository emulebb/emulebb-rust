---
id: RUST-BUG-027
workflow: local
title: REST JSON bodies can bypass MFC object-shape validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-027 - REST JSON bodies can bypass MFC object-shape validation

## Summary

eMuleBB MFC parses every non-empty JSON request body on registered API routes
and rejects non-object values with `JSON body must be an object` before command
dispatch. Rust only parsed bodies for routes with explicit field metadata, so
some JSON routes could reach serde/handlers with arrays, strings, numbers, or
booleans and return non-canonical errors or ignore the body.

## Acceptance Criteria

- [x] Non-empty JSON request bodies on registered routes must parse before
      dispatch.
- [x] JSON arrays, strings, numbers, booleans, and null must fail with
      `JSON body must be an object`.
- [x] Existing per-route body field validation still applies after object-shape
      validation.
- [x] Focused REST route validation tests cover routes with and without
      explicit body field metadata.

## Resolution

- Made REST body metadata validation parse every non-empty JSON body passed by
  route metadata middleware.
- Added the MFC object-shape rejection before field allowlist and route-specific
  validation.
- Extended route validation tests across representative API routes.

## Evidence

- `cargo test -p emulebb-rest route_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
