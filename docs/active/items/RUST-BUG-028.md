---
id: RUST-BUG-028
workflow: local
title: REST shared path bodies bypass MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-028 - REST shared path bodies bypass MFC validation

## Summary

Rust delegated `POST /api/v1/shared-files` and
`PATCH /api/v1/shared-directories` body-shape checks to serde/core handling.
eMuleBB MFC validates shared-file paths and shared-directory root descriptors in
the route seam before command dispatch, with canonical messages for missing or
malformed `path`, `roots`, `recursive`, and nested root fields. MFC also trims
ASCII whitespace from accepted path text before dispatch.

## Acceptance Criteria

- [x] Shared-file add bodies require `path` as a non-empty string path.
- [x] Shared-file add paths are ASCII-trimmed before reaching core handling.
- [x] Shared-directories PATCH bodies require `roots` as an array.
- [x] Shared-directory roots may be strings or objects with `path` and optional
      boolean `recursive`.
- [x] Unknown shared-directory root object fields fail with the canonical MFC
      message.
- [x] Focused REST body validation tests cover the MFC messages.

## Resolution

- Added MFC-style shared path/root validation to REST body metadata middleware.
- Registered body field allowlists for shared-file add and shared-directories
  PATCH routes.
- Trimmed accepted shared-file add paths before sharing the file.
- Extended route body validation and shared-files contract tests.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
