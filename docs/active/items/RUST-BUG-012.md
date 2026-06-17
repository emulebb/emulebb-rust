---
id: RUST-BUG-012
workflow: local
title: Paused downloads are reported as active downloads
status: DONE
priority: Minor
category: bug
labels: [rest, parity, stats]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-012 - Paused downloads are reported as active downloads

## Summary

Rust computed transfer stats as `active = total - completed`, so paused and
stopped downloads were reported as active downloads. eMuleBB MFC counts active
downloads from `CDownloadQueue::GetDownloadingFileCount()`, which includes
ready/empty part files and excludes paused entries. Rust maps those eligible
non-paused entries to `downloading` or `queued`. The total queue count remains
`CDownloadQueue::GetFileCount()`.

## Acceptance Criteria

- [x] Active download stats count only transfers in `downloading` or `queued`
  states.
- [x] `downloadCount` reports the total transfer queue size.
- [x] `runtimeDiagnostics.downloadFileCount` reports the total transfer queue
  size.
- [x] Paused/stopped transfers do not inflate active download counts.

## Resolution

- Added an explicit total transfer count to the core `TransferStats` model.
- Changed core status aggregation so active downloads count only
  `downloading` or `queued` transfers.
- Updated REST stats/status builders to use the explicit total for queue-count
  fields.
- Added a REST regression test covering one active and one paused transfer.

## Evidence

- `cargo test -p emulebb-rest stats_distinguish_active_downloads_from_total_queue --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
