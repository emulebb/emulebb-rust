---
id: RUST-BUG-009
workflow: local
title: Snapshot omits recent logs
status: DONE
priority: Minor
category: bug
labels: [rest, parity, snapshot, logs]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-009 - Snapshot omits recent logs

## Summary

Rust's `GET /api/v1/snapshot` always returned an empty `logs` array. eMuleBB MFC
builds snapshot logs with `BuildLogEntriesJson(maxEntries)`, using the same
bounded recent-log model as the logs endpoint.

## Acceptance Criteria

- [x] Snapshot responses include recent logs.
- [x] Snapshot logs respect the caller-visible snapshot limit.
- [x] The log row JSON shape is shared with `GET /api/v1/logs`.
- [x] REST tests cover snapshot log inclusion and bounding.

## Resolution

- Extracted a shared `recent_log_values(limit)` helper for REST log rows.
- Reused the helper from both the logs handler and the snapshot handler.
- Added a REST test proving snapshot returns the newest bounded log entries.

## Evidence

- `cargo test -p emulebb-rest snapshot_includes_bounded_recent_logs --locked`
- `cargo test -p emulebb-rest --lib --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
