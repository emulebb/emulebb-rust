---
id: RUST-BUG-092
title: Name server callback requests in diagnostics
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-092: Name server callback requests in diagnostics

## Problem

The live-wire server packet dump reported sent opcode `0x1C` as `UNKNOWN`.
That opcode is the stock eD2K server `OP_CALLBACKREQUEST` packet; Rust already
sends it through the callback request path, but the retained diagnostics name
table did not include it. This made packet-report analysis noisier and obscured
normal MFC-compatible callback behavior.

## Acceptance

- [x] Server diagnostics label opcode `0x1C` as `OP_CALLBACKREQUEST`.
- [x] The existing server diagnostics opcode-name test covers the callback
      request opcode.

## Implementation Notes

- Added `OP_CALLBACKREQUEST` to the eD2K server diagnostics import and
  `server_opcode_name` match table.
- Kept the fix diagnostics-only; packet encoding and callback behavior were not
  changed.

## Evidence

- Live-wire report with unknown opcode evidence:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T052645Z`.
- `cargo test -p emulebb-ed2k server_dump_names_global_udp_opcodes -- --nocapture`
- `python tools/rust_quality_gate.py quick`
