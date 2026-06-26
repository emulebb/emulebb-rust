---
id: RUST-BUG-011
workflow: local
title: Superseded snapshot limit clamp assumption
status: DONE
priority: Minor
category: bug
labels: [rest, parity, snapshot]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-011 - Superseded snapshot limit clamp assumption

Superseded by RUST-BUG-020. Later parity review against the current MFC route
metadata seam showed that the clamp described here is downstream of central
query validation. The current contract rejects out-of-range `limit` values
before snapshot dispatch.

## Summary

Earlier review concluded that Rust should accept `GET /api/v1/snapshot?limit=0`
and values over `1000` because the downstream MFC snapshot handler clamps with
`max(1, min(1000, limit))` and uses a default of `100`. RUST-BUG-020 supersedes
that conclusion: current MFC route metadata rejects invalid `limit` values
before snapshot dispatch.

## Acceptance Criteria

- [x] Missing snapshot limit defaults to `100`.
- [x] Superseded: `limit=0` was temporarily accepted and clamped to `1`.
- [x] Superseded: values over `1000` were temporarily accepted and clamped to `1000`.
- [x] Generic paged endpoints still reject out-of-range pagination values.

## Historical Resolution

- Changed the snapshot-only limit helper to clamp instead of returning a
  validation error.
- Left the generic pagination validator unchanged for paged collection routes.
- Added REST tests for the snapshot clamp behavior.

## Historical Evidence

- `cargo test -p emulebb-rest snapshot_limit_clamps_like_master --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
