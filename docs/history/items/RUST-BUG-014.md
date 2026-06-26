---
id: RUST-BUG-014
workflow: local
title: REST JSON bodies ignore Content-Type
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-014 - REST JSON bodies ignore Content-Type

## Summary

Rust parsed non-empty REST request bodies as JSON regardless of the
`Content-Type` header. eMuleBB MFC validates request metadata before JSON
parsing and rejects non-empty JSON bodies unless the media type is
`application/json` (parameters such as `charset=utf-8` are allowed).

## Acceptance Criteria

- [x] Non-empty REST write bodies without `Content-Type: application/json` are
  rejected before handler dispatch.
- [x] `application/json` with optional parameters remains accepted.
- [x] Empty request bodies are not rejected solely because no content type is
  present.
- [x] Existing malformed/unknown-field JSON errors keep their canonical
  envelopes.

## Resolution

- Added centralized JSON content-type validation in the REST router.
- Matched MFC media-type parsing: trim, lowercase, ignore parameters after `;`.
- Added regression coverage for a valid JSON transfer-create body sent as
  `text/plain`.

## Evidence

- `cargo test -p emulebb-rest json_body_requires_json_content_type --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
