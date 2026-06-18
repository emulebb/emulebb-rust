---
id: RUST-BUG-059
title: Collect multiple ED2K UDP keyword replies per server
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-059: Collect multiple ED2K UDP keyword replies per server

## Problem

After Rust learned to decode direct `OP_GLOBSEARCHRES` entries, live-wire search
returned only one result even though packet diagnostics showed multiple UDP
search-result datagrams arriving from the queried server.

eMuleBB MFC keeps processing UDP search answers from requested servers. Rust
stopped the per-server receive loop after the first decoded UDP result.

## Acceptance

- [x] A valid UDP keyword result packet no longer ends the per-server receive
      window.
- [x] Malformed UDP keyword result packets are discarded without ending the
      per-server receive window.
- [x] Live-wire diagnostics can verify multiple `OP_GLOBSEARCHRES` packets in
      one search pass.

## Implementation Notes

- Changed the active UDP keyword search loop to continue reading until the
  per-server timeout expires after valid or malformed result packets.

## Evidence

- `cargo test -p emulebb-ed2k ed2k_server --locked`
- Live-wire verification pending on the next diagnostics run.
