---
id: RUST-BUG-088
title: Report direct-source crypt options in diagnostics
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-088: Report direct-source crypt options in diagnostics

## Problem

The hide.me live-wire run `rust-hideme-20260619T040724Z` showed direct download
attempts with `obfuscated=true`, but the packet dumps could not show whether the
peer's crypt option byte actually advertised support/request semantics. eMuleBB
MFC selects outgoing client TCP obfuscation from the peer's connect-option bits:
valid user hash, support bit, and either peer request or local preference. Rust
already uses the same predicate, but its diagnostics only exposed the broad
source record shape.

## Acceptance

- [x] Direct-download `connect_start` diagnostics include the source crypt option
      byte when present.
- [x] Diagnostics distinguish missing crypt metadata from an explicit zero/flag
      value.
- [x] Wire behavior is unchanged.

## Implementation Notes

- Added `crypt_options=0xNN` / `crypt_options=none` to the direct ED2K TCP
  download connection-start note.

## Evidence

- Live behavior exposing the ambiguity:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T040724Z`.
- MFC comparison: `BaseClient.cpp` `Connect`, `TryToConnect`, and
  `SetConnectOptions`.
- `cargo test -p emulebb-ed2k secure_ident -- --nocapture`
- `python tools/rust_quality_gate.py quick`
