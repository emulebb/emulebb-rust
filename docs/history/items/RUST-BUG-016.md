---
id: RUST-BUG-016
workflow: local
title: REST query names are validated before URL decoding
status: DONE
priority: Minor
category: bug
labels: [rest, parity, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-016 - REST query names are validated before URL decoding

## Summary

Rust validated raw query parameter names in the REST route whitelist and reused
the JSON-body unknown-field error text. eMuleBB MFC parses query strings as
URL-encoded unique fields first, rejects duplicate decoded names, then reports
unknown decoded names as `unknown query parameter: <name>`.

## Acceptance Criteria

- [x] Route query whitelisting uses decoded query parameter names.
- [x] Duplicate decoded query parameter names are rejected before handler
  dispatch.
- [x] Unknown query names use the MFC `unknown query parameter` error text.
- [x] Existing typed query value validation still runs after the central route
  whitelist.

## Resolution

- Added central URL-decoded query-name parsing in the REST route metadata
  validator.
- Added duplicate decoded-name detection before whitelist validation.
- Updated REST regression coverage for decoded allowed names, decoded unknown
  names, and duplicates.

## Evidence

- `cargo test -p emulebb-rest query_routes_use_canonical_error_envelope --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
