---
id: RUST-BUG-062
title: Batch ED2K global UDP source requests like MFC
status: in_progress
priority: Major
category: bug
workflow: local
---

# RUST-BUG-062: Batch ED2K global UDP source requests like MFC

## Problem

Rust now sends ED2K global UDP source requests, but live diagnostics show it
sends one `OP_GLOBGETSOURCES` packet per transfer/server pair. eMuleBB MFC walks
the download list per UDP server and packs several file IDs into one
`OP_GLOBGETSOURCES` or `OP_GLOBGETSOURCES2` datagram until the MFC packet/file
limits are reached.

The one-hash Rust path is stock-compatible on the wire for each individual
packet, but it is not behaviorally equivalent to the MFC global source walk. It
creates excess UDP traffic and prevents a single server walk from refreshing
multiple scarce transfers together.

## Acceptance

- [x] The ED2K server packet layer can encode multi-file
      `OP_GLOBGETSOURCES` requests.
- [x] The ED2K server packet layer can encode multi-file
      `OP_GLOBGETSOURCES2` requests, including large-file sizes.
- [x] The packet fill behavior matches the MFC `MAX_UDP_PACKET_DATA` /
      `MAX_REQUESTS_PER_SERVER` rules.
- [x] The ED2K server source-search layer exposes a batch UDP request API that
      returns sources grouped by file hash.
- [x] Active transfer source acquisition coalesces scarce transfers into
      batched per-server UDP source requests.
- [ ] Live hide.me diagnostics show fewer global UDP source packets than
      transfer/server pairs when multiple scarce transfers are active, with
      payloads containing multiple file IDs.

## Implementation Notes

- Added the MFC UDP source-request packet limits to the ED2K server packet
  encoder.
- Kept the existing single-transfer source acquisition path on the batch encoder
  so the next slice can wire cross-transfer batching without changing packet
  shape again.
- Added an ED2K source-search API that sends one batched UDP request per server
  and merges `OP_GLOBFOUNDSOURCES` replies per requested file hash.
- Added a core-side 30-minute per-file claim window, matching MFC
  `UDPSERVERREASKTIME`, so the first concurrent scarce transfer can batch other
  active scarce transfers and later concurrent attempts do not duplicate the
  same server UDP walk.

## Evidence

- `cargo test -p emulebb-ed2k udp_source_request_batch --locked`
- `cargo test -p emulebb-ed2k udp_source --locked`
- `cargo test -p emulebb-core claim_batches_current_and_other_active_scarce_transfers_once --locked`
- `cargo test -p emulebb-core claim_skips_terminal_or_rich_transfers --locked`
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T155348Z\report.json`
  showed 213 outbound one-hash `OP_GLOBGETSOURCES` packets for 16 active
  downloads.
