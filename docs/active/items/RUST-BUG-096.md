---
id: RUST-BUG-096
title: Keep unroutable LowID queue sources on TCP retry
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-096: Keep unroutable LowID queue sources on TCP retry

## Problem

Rust detached TCP-discovered queued LowID sources onto the client-UDP reask loop
even though a TCP hello only carries the peer's buddy endpoint, not the buddy id
required for `OP_REASKCALLBACKUDP`. After `RUST-BUG-095` correctly stopped
direct-pinging incomplete LowID buddy targets, these detached sources could sit
in the UDP reask set without any routable datagram.

MFC keeps this distinction: Kad source results of type 3/5 carry buddy id plus
buddy endpoint and can use the LowID buddy UDP reask path. Ordinary TCP queue
sessions without a valid buddy id do not get a routable LowID UDP reask and
remain on the normal reconnect/callback path.

## Acceptance

- [x] HighID queued TCP sources can still detach to UDP reask.
- [x] LowID queued TCP sources without a buddy id do not detach to UDP reask.
- [x] Kad buddy sources that already carry buddy id + endpoint remain handled by
      the existing Kad source-result reask path.

## Implementation Notes

- `try_detach_queued_source_for_reask` now refuses TCP-session detach for LowID
  sources because that path cannot provide a buddy id.
- Focused tests cover both the retained HighID detach path and the skipped
  LowID TCP-session path.

## Evidence

- Compared against MFC `CPartFile::Process`, `CUpDownClient::AskForDownload`,
  `CUpDownClient::TryToConnect`, and `CUpDownClient::UDPReaskForDownload`.
- Live-wire clue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T063351Z`
  recorded a queued detached source with no client-UDP send in the obfuscation
  enabled pass.
- `cargo test -p emulebb-ed2k ed2k_tcp::download::session::reask_detach -- --nocapture`
- `python tools/rust_quality_gate.py quick`
