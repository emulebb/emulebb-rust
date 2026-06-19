---
id: RUST-BUG-087
title: Dump outgoing secure-ident signatures
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-087: Dump outgoing secure-ident signatures

## Problem

The hide.me live-wire run `rust-hideme-20260619T034125Z` confirmed that Rust now
continues startup after secure-ident key exchange, but packet diagnostics did
not include outgoing `OP_SIGNATURE` records. That made secure-ident parity
analysis weaker than the MFC diagnostics surface: eMuleBB MFC has an explicit
`SendSignaturePacket` path, and Rust should expose the same outbound packet in
diagnostic packet dumps without changing wire behavior.

## Acceptance

- [x] Outgoing secure-ident signatures are written to the ED2K TCP packet dump.
- [x] The diagnostic phase remains the canonical `signature` phase used by the
      MFC comparison oracle.
- [x] The emitted wire packet remains unchanged.

## Implementation Notes

- Added the packet-dump send wrapper beside the existing `OP_SIGNATURE` write in
  `try_send_secure_ident_signature`.
- Added a unit guard for the canonical outgoing signature phase mapping.

## Evidence

- Live behavior exposing the diagnostics gap:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T034125Z`.
- MFC comparison: `BaseClient.cpp` `SendSignaturePacket` and
  `ListenSocket.cpp` secure-ident packet handling.
- `cargo test -p emulebb-ed2k secure_ident -- --nocapture`
- `python tools/rust_quality_gate.py quick`
