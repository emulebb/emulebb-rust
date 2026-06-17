---
id: RUST-BUG-011
workflow: local
title: Snapshot limit rejects values MFC clamps
status: DONE
priority: Minor
category: bug
labels: [rest, parity, snapshot]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-011 - Snapshot limit rejects values MFC clamps

## Summary

Rust reused the generic pagination validator for `GET /api/v1/snapshot?limit`,
so `limit=0` and values over `1000` were rejected. eMuleBB MFC clamps snapshot
limits with `max(1, min(1000, limit))` and uses a default of `100`.

## Acceptance Criteria

- [x] Missing snapshot limit defaults to `100`.
- [x] `limit=0` is accepted and clamped to `1`.
- [x] Values over `1000` are accepted and clamped to `1000`.
- [x] Generic paged endpoints still reject out-of-range pagination values.

## Resolution

- Changed the snapshot-only limit helper to clamp instead of returning a
  validation error.
- Left the generic pagination validator unchanged for paged collection routes.
- Added REST tests for the snapshot clamp behavior.

## Evidence

- `cargo test -p emulebb-rest snapshot_limit_clamps_like_master --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
