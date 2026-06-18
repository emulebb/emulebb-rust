---
id: RUST-BUG-063
title: Do not serialize ED2K UDP source-batch sends behind per-server waits
status: in_progress
priority: Major
category: bug
workflow: local
---

# RUST-BUG-063: Do not serialize ED2K UDP source-batch sends behind per-server waits

## Problem

Rust's batched ED2K global UDP source search sent one `OP_GLOBGETSOURCES*`
packet, waited for that server's response timeout, and only then sent the next
server packet.

eMuleBB MFC `CDownloadQueue::SendNextUDPPacket` sends the selected UDP source
packet and returns immediately; server replies are processed asynchronously by
the UDP socket. The serialized Rust behavior made the server walk slower than
MFC and produced live packet captures with roughly timeout-spaced UDP source
packets.

## Acceptance

- [x] Batched ED2K UDP source search sends all selected server packets before
      waiting for replies.
- [x] Replies are decoded against the server that actually sent the datagram,
      preserving UDP obfuscation-key handling.
- [ ] Live hide.me diagnostics show batched `OP_GLOBGETSOURCES*` packets are no
      longer spaced by the per-server response timeout.

## Implementation Notes

- Added an ED2K UDP runtime helper that reads one datagram and decodes it
  against the matching requested server IP.
- Changed only the batched source-search path; the legacy single-file helper
  keeps its previous sequential behavior for now.

## Evidence

- `cargo test -p emulebb-ed2k udp_response_candidates_match_queried_server_ip --locked`
- `cargo test -p emulebb-ed2k udp_source --locked`
