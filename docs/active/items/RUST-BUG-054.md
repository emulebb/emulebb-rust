---
id: RUST-BUG-054
title: Delay server endpoint advertisement until ED2K login is accepted
status: done
priority: Major
category: bug
workflow: github
---

# RUST-BUG-054: Delay server endpoint advertisement until ED2K login is accepted

## Problem

During a public ED2K server login, Rust answered the server's inbound callback
hello with the server endpoint already populated in `OP_HELLOANSWER`. eMuleBB
MFC keeps the server IP and port fields zero until the server socket is actually
connected. The live server accepted the callback TCP connection and received
Rust's hello answer, but then closed the login socket before `OP_IDCHANGE`, so
the Rust live-wire proof never reached HighID.

## Acceptance

- [x] `OP_HELLOANSWER` keeps server IP and port zero while a server login is
      still only connecting.
- [x] Connected ED2K sessions still advertise the connected server endpoint in
      peer hello packets.
- [x] The hide.me-bound live-wire proof reaches ED2K HighID after the fix.
- [x] The fix has focused protocol coverage and passes fmt/clippy gates.

## Implementation Notes

- Changed ED2K hello identity enrichment to copy the server endpoint only when
  `Ed2kServerState.connected` is true.
- Added regression coverage for the connecting-but-not-yet-connected callback
  window.

## Evidence

- `cargo test -p emulebb-ed2k enrich_hello_identity --locked`
- `python tools\rust_quality_gate.py quick`
- `python -m emule_workspace build clients --client emulebb-rust --config Release --platform x64`
- `python scripts\rust-live-wire-hideme.py --inputs live-wire-inputs.local.json`
  - Report:
    `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T114200Z\report.json`
  - Result: passed single obfuscation-on hide.me live-wire pass with VPN bind,
    ED2K HighID, Kad connected, 300 server search results, 50 transfer starts,
    completed downloads, and packet diagnostics captured.
