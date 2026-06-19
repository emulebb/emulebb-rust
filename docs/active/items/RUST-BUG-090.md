---
id: RUST-BUG-090
title: Preserve SX2 live-source connect options
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-090: Preserve SX2 live-source connect options

## Problem

Rust source-exchange v4 replies advertised live download sources with
`connect_options=0`, even when the connected source had advertised eMule
crypt-layer support/request/require bits in its hello. eMuleBB MFC writes each
source client's current crypt options in `CreateSrcInfoPacket`, so the Rust
responder could make downstream peers miss obfuscation capability for sources
learned through SX2.

## Acceptance

- [x] The download live-source registry records the connected peer's current
      crypt-layer connect options.
- [x] `OP_ANSWERSOURCES2` v4 replies emit the recorded options for live sources.
- [x] The decoded hello profile exposes the MISCOPTIONS2 crypt bits as the same
      source-exchange connect-options byte MFC writes.
- [x] Listener tests assert the emitted SX2 v4 connect-options byte.

## Implementation Notes

- Added `peer_connect_options` to the download session and live-source registry.
- Refreshed the value from decoded `OP_HELLO` / `OP_HELLOANSWER` metadata.
- Kept persisted source hints unchanged; only live sources advertise known
  crypt options.
- Moved the MISCOPTIONS2 crypt-bit decoder into `hello_miscoptions.rs` so
  `hello.rs` stays within the repository file-size budget.

## Evidence

- Live behavior that led to the check:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T045033Z`.
- `cargo test -p emulebb-ed2k listener_source_exchange -- --nocapture`
- `python tools/rust_quality_gate.py quick`
