---
id: RUST-BUG-055
title: Match MFC obfuscated server login for metadata-poor ED2K servers
status: in_progress
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
- [ ] A hide.me-bound live-wire obfuscation-on pass reaches ED2K HighID with
      the rebuilt staged runtime.

## Evidence

- `cargo test -p emulebb-ed2k ed2k_server --locked`
- `python tools\rust_quality_gate.py quick`
