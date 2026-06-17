---
id: RUST-BUG-026
workflow: local
title: REST shared-file PATCH body shape bypasses MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-026 - REST shared-file PATCH body shape bypasses MFC validation

## Summary

Rust delegated part of `PATCH /api/v1/shared-files/{hash}` body validation to
serde/core handling, which produced generic errors for malformed `priority`,
`comment`, and `rating` payloads. eMuleBB MFC validates these fields in the
route seam before command dispatch and returns canonical field-specific errors.

## Acceptance Criteria

- [x] Empty shared-file PATCH bodies fail with
      `shared-file PATCH requires priority, comment, or rating`.
- [x] `priority` must be a string.
- [x] `priority` must be one of `auto`, `verylow`, `low`, `normal`, `high`, or
      `release`.
- [x] `comment`/`rating` updates require `comment` to be a string.
- [x] `comment`/`rating` updates require `rating` to be an integer between 0
      and 5.
- [x] Focused REST route body validation tests cover the MFC messages.

## Resolution

- Added MFC-style shared-file PATCH body validation to REST body metadata
  middleware.
- Registered the shared-file PATCH body field allowlist with route body
  metadata.
- Extended route body validation tests for priority and comment/rating errors.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
