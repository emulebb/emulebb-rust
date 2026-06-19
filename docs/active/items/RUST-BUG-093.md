---
id: RUST-BUG-093
title: Retain client UDP reask packet diagnostics
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-093: Retain client UDP reask packet diagnostics

## Problem

Live-wire runs showed UDP source-reask activity through daemon trace lines and
`diag_event_v1` `sched/reask_sent` events, but the retained `ed2k_packet_v1`
packet dump only covered eD2K TCP, server packets, and Kad UDP. That meant the
MFC-compatible client-UDP reask family (`OP_REASKFILEPING`, `OP_REASKACK`,
`OP_FILENOTFOUND`, `OP_QUEUEFULL`, `OP_REASKCALLBACKUDP`, and
`OP_DIRECTCALLBACKREQ`) could not be inspected as packet evidence, especially
when datagrams were obfuscated on the wire.

## Acceptance

- [x] Packet diagnostics emit `ed2k_packet_v1` records for client-UDP reask
      sends.
- [x] Obfuscated outbound sends retain opcode and plaintext payload metadata
      while preserving the actual raw datagram bytes.
- [x] Inbound client-UDP datagrams are decoded for packet diagnostics when the
      local user hash and sender IP allow deobfuscation.
- [x] The live-wire packet-summary glob includes the new dump file because it
      uses the `emulebb-rust-ed2k-*-dump-*.jsonl` naming family.

## Implementation Notes

- Added an `ed2k_client_udp::dump` module with the same `ed2k_packet_v1`
  envelope shape used by the TCP/server diagnostics.
- Added `ClientUdpDatagram` metadata to the outbound builders so diagnostics can
  retain both the exact raw datagram and the pre-obfuscation opcode/payload.
- Kept the source-set and service logic I/O-free; runtime is the only layer that
  writes packet diagnostics.

## Evidence

- Pre-fix live-wire evidence:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T053849Z`.
- `cargo test -p emulebb-ed2k ed2k_client_udp --features packet-diagnostics -- --nocapture`
