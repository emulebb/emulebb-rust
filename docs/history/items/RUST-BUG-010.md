---
id: RUST-BUG-010
workflow: local
title: Snapshot limit truncates server list
status: DONE
priority: Minor
category: bug
labels: [rest, parity, snapshot, servers]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-010 - Snapshot limit truncates server list

## Summary

Rust applied the snapshot `limit` parameter to the `servers` array. eMuleBB MFC
uses the limit for transfers, shared files, uploads, upload queue, and logs, but
builds snapshot servers with the full `BuildServersListJson()` result.

## Acceptance Criteria

- [x] `GET /api/v1/snapshot?limit=N` returns the full server list.
- [x] Other bounded snapshot collections continue to use the snapshot limit.
- [x] REST tests cover the server-list behavior.

## Resolution

- Removed the snapshot limit from the server list in the REST snapshot builder.
- Added a REST test proving `limit=1` does not truncate two configured servers.

## Evidence

- `cargo test -p emulebb-rest snapshot_limit_does_not_truncate_servers --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
