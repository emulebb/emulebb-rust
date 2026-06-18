---
id: RUST-BUG-055
title: Match MFC obfuscated server login for metadata-poor ED2K servers
status: done
priority: Major
category: bug
workflow: github
---

# RUST-BUG-055: Match MFC obfuscated server login for metadata-poor ED2K servers

## Problem

When obfuscation is enabled and the configured ED2K server is endpoint-only,
Rust opened a plaintext server TCP session but still advertised crypt support
and preference flags in `OP_LOGINREQUEST`. In live-wire evidence, that shape was
closed before `OP_IDCHANGE`.

eMuleBB MFC first tries server TCP obfuscation for an untried server when crypt
is preferred, even if the server has not yet advertised an obfuscation port. If
the server transport is already obfuscated, MFC keeps the login crypt flags
conservative and advertises support without requesting crypt negotiation again.

## Acceptance

- [x] Metadata-poor endpoint-only ED2K servers use obfuscated TCP transport when
      local crypt is enabled.
- [x] Known plain servers still use plaintext transport.
- [x] Obfuscated server transport suppresses request/require crypt login flags.
- [x] A hide.me-bound live-wire obfuscation-on pass reaches ED2K HighID with
      the rebuilt staged runtime.

## Evidence

- `cargo test -p emulebb-ed2k ed2k_server --locked`
- `python tools\rust_quality_gate.py quick`
- `python -m emule_workspace build clients --client emulebb-rust --config Release --platform x64 --clean`
- `python scripts\rust-live-wire-hideme.py --inputs live-wire-inputs.local.json --max-terms 1 --max-concurrent 20 --download-timeout 600`
  - Report:
    `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T130300Z\report.json`
  - Result: passed obfuscation-on hide.me live-wire pass with VPN bind, ED2K
    HighID, Kad connected, server search results, completed downloads, and TCP
    obfuscation observed.
  - Daemon evidence: the connected server session used obfuscated transport
    with `connect_options=0x01 (supports_crypt)` and received a HighID
    `OP_IDCHANGE`.
