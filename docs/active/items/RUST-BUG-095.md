---
id: RUST-BUG-095
title: Skip incomplete LowID UDP reasks
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-095: Skip incomplete LowID UDP reasks

## Problem

Rust treated a firewalled LowID source with incomplete Kad buddy metadata as a
direct client-UDP reask target. MFC `CUpDownClient::UDPReaskForDownload` only
sends `OP_REASKFILEPING` to HighID sources, and only sends
`OP_REASKCALLBACKUDP` for LowID sources when the buddy endpoint and buddy id are
both known. With missing buddy data MFC sends no UDP datagram and does not mark
the source UDP-pending.

## Acceptance

- [x] LowID sources with complete buddy endpoint + id still emit plaintext
      `OP_REASKCALLBACKUDP` to the buddy endpoint.
- [x] LowID sources missing either the buddy endpoint or buddy id emit no direct
      `OP_REASKFILEPING`.
- [x] Skipped LowID sources do not open the pending-reply gate because no UDP
      request was sent.

## Implementation Notes

- `ReaskSourceSet::due_datagrams` now skips LowID sources when callback
  origination cannot be built from complete buddy metadata.
- The regression test that previously expected a direct LowID fallback now
  asserts the MFC-compatible no-send behavior.

## Evidence

- Compared against MFC
  `CUpDownClient::UDPReaskForDownload` in `DownloadClient.cpp`.
- `cargo test -p emulebb-ed2k low_id_buddy_source_originates_callback_udp_to_the_buddy_endpoint -- --nocapture`
- `python tools/rust_quality_gate.py quick`
