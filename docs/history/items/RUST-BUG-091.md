---
id: RUST-BUG-091
title: Return EXT2 identifier answer for source-only multipackets
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-091: Return EXT2 identifier answer for source-only multipackets

## Problem

Rust answered an `OP_MULTIPACKET_EXT2` request containing only
`OP_REQUESTSOURCES2` with the separate `OP_ANSWERSOURCES2` source-exchange
reply, but did not send the identifier-only `OP_MULTIPACKETANSWER_EXT2`.
eMuleBB MFC initializes the EXT2 response buffer with the file identifier and
sends it whenever `data_out.GetLength() > 16`, so a source-only EXT2 request
still receives a multipacket answer after the separate SX2 reply.

## Acceptance

- [x] A valid `OP_MULTIPACKET_EXT2` request always receives an
      `OP_MULTIPACKETANSWER_EXT2` carrying the matched file identifier.
- [x] Source-only EXT2 requests still receive the separate SX2 answer first
      when sources are available.
- [x] Listener coverage asserts the source-only EXT2 response sequence.

## Implementation Notes

- Changed the shared-file EXT2 request handler to emit the EXT2 answer after
  successful sub-op processing even when no filename/status subanswer was added.
- Kept the answer construction in the shared-file handler because it owns the
  MFC `data_out` response-buffer behavior for multipacket file requests.

## Evidence

- `cargo test -p emulebb-ed2k listener_multipacket_ext2_source_only_returns_identifier_answer -- --nocapture`
- `python tools/rust_quality_gate.py quick`
