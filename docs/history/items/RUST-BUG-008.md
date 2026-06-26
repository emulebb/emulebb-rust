---
id: RUST-BUG-008
workflow: local
title: Logs endpoint ignores the MFC limit query
status: DONE
priority: Minor
category: bug
labels: [rest, parity, logs]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-008 - Logs endpoint ignores the MFC limit query

## Summary

Rust's `GET /api/v1/logs` endpoint returned the whole recent-log ring buffer and
ignored the `limit` query parameter. eMuleBB MFC declares `GET /logs` with a
`limit` query and builds log entries with `max(1, limit)` using a default of
`200`.

## Acceptance Criteria

- [x] `GET /api/v1/logs?limit=N` returns at most `N` recent log entries.
- [x] `limit=0` follows MFC semantics and is clamped to one entry.
- [x] Missing `limit` uses the MFC default limit of 200.
- [x] Unsupported query fields are rejected through the canonical error envelope.

## Resolution

- Added a `LogsQuery` DTO with `deny_unknown_fields`.
- Parsed the logs query in the REST handler and applied the MFC limit semantics
  before building the collection envelope.
- Added REST tests for bounded logs, default behavior, zero-limit clamping, and
  unsupported query rejection.

## Evidence

- `cargo test -p emulebb-rest logs_limit_matches_master_query_semantics --locked`
- `cargo test -p emulebb-rest logs_clear_requires_canonical_confirmation --locked`
- `cargo test -p emulebb-rest query_routes_use_canonical_error_envelope --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
