---
id: RUST-BUG-075
title: Preserve out-of-order requested ED2K blocks
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-075: Preserve out-of-order requested ED2K blocks

## Problem

The hide.me live-wire run `rust-hideme-20260618T223339Z` completed downloads and
stayed VPN-bound, but its native download diagnostics included
`received unexpected block` errors. The failing ranges were valid eMule block
ranges that arrived ahead of the current contiguous prefix.

Comparing the path against eMuleBB MFC showed a parity drift:

- MFC `CUpDownClient::ProcessBlockPacket` matches a received range by checking
  whether the incoming start offset is inside any pending requested block.
- MFC rejects the payload only when the received end exceeds that pending block.
- MFC then calls `CPartFile::WriteToBuffer` with the absolute received range, so
  a later requested block can be buffered before an earlier block arrives.
- Rust `append_piece_block` accepted only the exact current contiguous
  `bytes_written` prefix and rejected later requested blocks.

## Acceptance

- [x] Rust preserves a full out-of-order requested eMule block instead of
      rejecting the session as an unexpected range.
- [x] Out-of-order data is accepted only for exact block-aligned eMule request
      ranges inside the target part.
- [x] The existing contiguous fast path stays compact and does not force a
      bitmap when blocks arrive in order.
- [x] Once every block is present, the part is MD4-verified before it becomes
      upload-visible.
- [x] Focused regression coverage proves a second requested block can arrive
      before the first and still complete the part after the missing prefix
      arrives.
- [x] Existing ICH salvage bitmap coverage still passes.

## Implementation Notes

- Added `ed2k_transfer::requested_block` for normal-download out-of-order block
  persistence.
- The contiguous `append_piece_block` path now dispatches to the bitmap path
  only when a non-prefix response arrives or the part already has a block
  bitmap.
- The bitmap path writes the block at its absolute offset, marks that eMule
  block present, persists the manifest immediately, and verifies the whole part
  once the bitmap is complete.
- Duplicate already-present blocks become no-op incomplete writes, matching the
  MFC duplicate-buffer behavior.

## Evidence

- `cargo test -p emulebb-ed2k out_of_order_requested_blocks_are_persisted_by_bitmap --locked`
- `cargo test -p emulebb-ed2k ed2k_transfer::tests::salvage --locked`
- `cargo fmt --all --check`
- `python tools/rust_quality_gate.py quick`
