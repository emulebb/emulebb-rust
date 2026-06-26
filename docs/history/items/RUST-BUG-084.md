---
id: RUST-BUG-084
title: Use MFC common-file SX2 reask timing
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-084: Use MFC common-file SX2 reask timing

## Problem

Rust throttled repeated SX2 requests to the same peer/file tuple for 40 minutes
regardless of how many sources the file already had.

eMuleBB MFC uses `CUpDownClient::IsSourceRequestAllowed` with two timing classes:

- rare and very rare files may re-ask a previously asked peer after
  `SOURCECLIENTREASKS`, which is 40 minutes;
- common files require `SOURCECLIENTREASKS * MINCOMMONPENALTY`, which is
  160 minutes.

That means Rust could re-ask SX2-capable peers too aggressively for common files
after a long-running transfer crossed the rare-file source threshold.

## Acceptance

- [x] Files with source counts at or below the MFC rare-file threshold keep the
      existing 40-minute SX2 peer/file throttle.
- [x] Files above the rare-file threshold use the MFC common-file 160-minute
      peer/file throttle.
- [x] The soft source cap from `RUST-BUG-083` still denies SX2 before the
      throttle state is updated.

## Implementation Notes

- Added an MFC-derived rare/common SX2 reask interval helper in the ED2K transfer
  runtime.
- Kept the existing peer/file/user-hash throttle key.
- Extended the source-exchange tests moved out during `RUST-BUG-083`.

## Evidence

- MFC comparison:
  `srchybrid/DownloadClient.cpp` `CUpDownClient::IsSourceRequestAllowed` and
  `srchybrid/Opcodes.h` constants `SOURCECLIENTREASKS`, `MINCOMMONPENALTY`, and
  `RARE_FILE`.
- `cargo test -p emulebb-ed2k source_exchange -- --nocapture`
