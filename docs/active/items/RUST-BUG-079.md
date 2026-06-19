---
id: RUST-BUG-079
title: Do not report unknown ED2K TCP transport as plaintext
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-079: Do not report unknown ED2K TCP transport as plaintext

## Problem

Live-wire diagnostics showed `native_download` `connect_start` events where the
structured `diag_event_v1.body.obfuscated` field was `false` while the note still
contained source metadata such as `obfuscated=true has_user_hash=true`. At that
phase no transport exists yet, so the on-wire mode is unknown.

This made obfuscation-off parity analysis harder: a source may advertise crypt
metadata, but the actual transport decision is only known at `connect_ready`.
Reporting unknown as `false` made pre-handshake diagnostics look like a confirmed
plaintext verdict.

## Acceptance

- [x] Pre-handshake ED2K TCP meta events with `transportMode="unknown"` omit the
      on-wire `obfuscated` field.
- [x] Known plaintext and obfuscated transport modes still emit explicit boolean
      values.
- [x] Protocol behavior is unchanged.

## Implementation Notes

- Changed the ED2K TCP `diag_event_v1` mapper to emit `body.obfuscated` only for
  known transport modes.
- Kept `body.transportMode` present for every record, including `unknown`.
- Added unit coverage for unknown, plaintext, and obfuscated mapping.

## Evidence

- Live evidence source:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T001217Z`.
- In that run, all obfuscation-off native-download `connect_ready` records were
  plaintext even when some `connect_start` source notes advertised obfuscation
  metadata.
