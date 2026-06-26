---
id: RUST-BUG-065
title: Deduplicate remembered ED2K sources across plaintext fallback
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-065: Deduplicate remembered ED2K sources across plaintext fallback

## Problem

Live-wire diagnostics after `RUST-BUG-064` showed direct download attempts
failing with:

`UNIQUE constraint failed: index 'transfer_sources_identity_idx'`

The failure appeared when an obfuscated direct download failed and Rust queued a
plaintext fallback to the same endpoint. The fallback source intentionally
strips obfuscation metadata and user hash, so the in-memory manifest saw it as a
different `Ed2kSourceHint`. The SQL persistence layer correctly treats source
identity as `(transfer_id, ip, tcp_port, udp_port)`, so persisting both endpoint
hints for one transfer collided.

eMuleBB MFC treats the plaintext retry as another attempt against the same
source endpoint, not as a second durable source.

## Acceptance

- [x] Remembered transfer source hints are unique by endpoint identity.
- [x] A plaintext fallback for an already remembered obfuscated source does not
      append a second durable source hint.
- [x] A later source observation with a user hash can upgrade a hash-less
      endpoint hint.
- [x] Focused regression coverage proves the duplicate endpoint does not reach
      persistence.
- [x] The next hide.me live-wire run does not report
      `transfer_sources_identity_idx` failures.

## Implementation Notes

- Keep the change in transfer source metadata, where durable source identity is
  enforced.
- Preserve a known user hash when a later plaintext fallback has no hash.

## Evidence

- `cargo test -p emulebb-ed2k remembered_source_plaintext_fallback_preserves_single_endpoint_hint --locked`
- `python tools\check_rust_client_policy.py`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T173820Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T173921Z\report.json`:
  VPN-bound HighID run passed, started 16 downloads, completed one candidate,
  and captured packet diagnostics. The daemon log had zero
  `transfer_sources_identity_idx` and zero `UNIQUE constraint failed` entries
  after four plaintext fallback schedules.
