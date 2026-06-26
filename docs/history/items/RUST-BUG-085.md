---
id: RUST-BUG-085
title: Apply MFC SX2 answer cooldown per file
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-085: Apply MFC SX2 answer cooldown per file

## Problem

Rust decoded `OP_ANSWERSOURCES2` and remembered any sources it carried, but it
did not update a per-file answer timestamp. eMuleBB MFC calls
`CPartFile::SetLastAnsweredTime()` as soon as a matching SX2 answer arrives,
before adding sources, so empty answers still suppress subsequent SX2 requests
for that file.

That leaves a selected-surface drift after `RUST-BUG-084`: Rust had the peer
reask timing, but not the file-level answer cooldown that MFC applies to rare
and common files.

## Acceptance

- [x] A matching `OP_ANSWERSOURCES2` records the file's SX2 answer time even when
      the answer contains zero sources.
- [x] Very rare files stay exempt from the file-level answer cooldown.
- [x] Rare files apply the MFC 5-minute file answer cooldown.
- [x] Common files apply the MFC 20-minute file answer cooldown.
- [x] Mismatched SX2 answer hashes are still ignored.

## Implementation Notes

- Added in-memory per-file SX2 answer timestamps to `Ed2kTransferRuntime`.
- The SX2 request gate now checks the MFC rarity class before the peer/file
  throttle map is updated.
- The download session records the answer timestamp after the answer hash
  matches the requested file and before source ingestion.

## Evidence

- MFC comparison:
  `srchybrid/DownloadClient.cpp` `CUpDownClient::IsSourceRequestAllowed`,
  `ListenSocket.cpp` `OP_ANSWERSOURCES2` handling, and `PartFile.h`
  `SetLastAnsweredTime`.
- `cargo test -p emulebb-ed2k source_exchange -- --nocapture`
