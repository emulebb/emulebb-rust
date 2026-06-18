---
id: RUST-BUG-064
title: Cover all effective servers in ED2K UDP source batches
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-064: Cover all effective servers in ED2K UDP source batches

## Problem

Rust's batched ED2K global UDP source search still capped the selected server
walk with `source_server_attempt_budget`, whose default is intentionally tiny
for legacy diagnostic one-shot source probes.

eMuleBB MFC keeps rotating through the global server list for its UDP source
walk. After `RUST-BUG-063`, Rust sends selected batched server packets before
waiting for replies, so covering the effective runtime/imported server list no
longer serializes source acquisition behind one timeout per server.

## Acceptance

- [x] Batched global ED2K UDP source search uses the full effective configured
      and runtime-imported server count.
- [x] Legacy source-server attempt budgets remain available to diagnostic
      one-shot source paths.
- [x] Focused unit coverage proves a small diagnostic budget does not shrink
      the batched global source walk.
- [x] Live hide.me diagnostics show batched `OP_GLOBGETSOURCES*` packets cover
      more than the old three-server cap when more candidate servers are
      available.

## Implementation Notes

- Keep the change scoped to active transfer source batching.
- Do not change the default diagnostic source-server attempt budget globally.

## Evidence

- `cargo test -p emulebb-core global_udp_source_batch_attempts_cover_effective_server_list --locked`
- `python tools\check_rust_client_policy.py`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T171837Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T171926Z\report.json`:
  VPN-bound HighID run captured 31 outbound `OP_GLOBGETSOURCES` packets to 31
  distinct servers. Each packet had a 256-byte payload and the packets were sent
  between `2026-06-18T17:23:47.278Z` and `2026-06-18T17:23:47.281Z`, proving
  the batched source walk is no longer capped at three servers.

The same live run did not complete a download before timeout and exposed a
separate transfer-source identity persistence bug; that failure is tracked
separately from this server-coverage fix.
