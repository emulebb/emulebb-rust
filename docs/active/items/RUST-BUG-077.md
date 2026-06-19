---
id: RUST-BUG-077
title: Persist accepted ED2K request blocks before bitmap recovery
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-077: Persist accepted ED2K request blocks before bitmap recovery

## Problem

The hide.me live-wire run `rust-hideme-20260618T232801Z` stayed VPN-bound,
connected HighID, connected Kad, and downloaded several megabytes, but the
harness failed because no file completed before timeout. Packet diagnostics
showed three single-part transfers received and flushed byte ranges up to the
file end, while persisted transfer metadata still showed missing block-bitmap
gaps.

The missing bitmap gaps matched full eMule request blocks that had been accepted
after the last durable manifest checkpoint and before a later non-prefix block
forced bitmap tracking. Those full blocks had been written to the payload and
kept only in the volatile manifest cache, so the bitmap recovery transition
could seed from stale durable progress.

Comparing against eMuleBB MFC showed the parity rule:

- `CUpDownClient::ProcessBlockPacket` accepts any received range whose start is
  inside a pending requested block, rejecting only when the received end exceeds
  that requested block.
- `CPartFile::WriteToBuffer` queues the absolute byte range and immediately
  calls `FillGap`, so accepted data updates the shared gap map independently of
  later buffer flush timing.
- `CPartFile::RemoveBlockFromList` removes the covered requested block from the
  central requested-block list.

Rust therefore must make every accepted full eMule request block durable before
later bitmap recovery can rely on persisted manifest state.

## Acceptance

- [x] Full-size ED2K request blocks checkpoint transfer metadata immediately.
- [x] Sub-block progress can still stay cache-only until the normal checkpoint
      threshold or interval.
- [x] A bitmap transition after cached prefix progress preserves every accepted
      full request block.
- [x] The existing out-of-order requested-block completion path still verifies
      the part before marking it complete.

## Implementation Notes

- Lowered the ED2K resume checkpoint byte threshold from sixteen eMule blocks to
  one eMule block.
- Kept the existing time-based checkpoint path for smaller sub-block progress.
- Added a regression test that writes twenty-nine full request blocks, reloads
  the runtime to prove the durable prefix, then receives a later block first and
  verifies the bitmap preserves the accepted prefix.

## Evidence

- Live evidence source: `rust-hideme-20260618T232801Z`.
- Focused diagnostic counts from that run: VPN-bound true, ED2K HighID true,
  Kad connected true, packet diagnostics captured 5,286 diagnostic records, and
  no malformed JSONL lines.
- `cargo test -p emulebb-ed2k out_of_order_transition_preserves_cached_prefix_blocks --locked`
- `cargo test -p emulebb-ed2k append_piece_block_keeps_subblock_progress_in_memory_until_checkpoint --locked`
- `cargo test -p emulebb-ed2k ed2k_transfer::tests::salvage --locked`
- `cargo fmt --all --check`
- `python tools/rust_quality_gate.py quick`
- `python -m emule_workspace build clients --client emulebb-rust --diagnostics`
  built the diagnostics client with 0 warnings.
- hide.me live-wire run `rust-hideme-20260618T235505Z`: passed, VPN-bound,
  HighID, Kad connected, 20 downloads started, 5 completed, 31,564,154
  completed bytes, packet diagnostics captured, `unexpected block` count 0,
  `native_download/error` count 0, `piece_verification_failed` count 0, and
  every non-empty diagnostic JSONL line parsed as one JSON object.
