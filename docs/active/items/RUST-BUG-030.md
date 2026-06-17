---
id: RUST-BUG-030
workflow: local
title: REST URL import and Kad bootstrap bodies bypass MFC validation
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-030 - REST URL import and Kad bootstrap bodies bypass MFC validation

## Summary

Rust delegated URL-import and Kad bootstrap body-shape validation to serde/core
handling. eMuleBB MFC validates these route bodies before dispatch, returning
canonical messages for `url`, `address`, and `port` and trimming accepted text
fields before invoking command handling.

## Acceptance Criteria

- [x] Server and Kad URL import bodies require `url` as a non-empty string.
- [x] URL import text is ASCII-trimmed and rejects control characters,
      overlong text, whitespace, unsupported schemes, and missing hosts.
- [x] Kad bootstrap bodies require `address` as a non-empty string.
- [x] Kad bootstrap bodies require `port` in the range `1..65535`.
- [x] Accepted URL import text and Kad bootstrap addresses are trimmed before
      core handling.
- [x] Focused REST body validation tests cover the MFC messages.

## Resolution

- Added MFC-style URL import and Kad bootstrap validation to REST body metadata
  middleware.
- Registered body field allowlists for `servers/import-met-url`,
  `kad/import-nodes-url`, and `kad/bootstrap`.
- Trimmed accepted URL import text and Kad bootstrap addresses in handlers.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
