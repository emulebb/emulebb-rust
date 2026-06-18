---
id: RUST-BUG-064
title: Cover all effective servers in ED2K UDP source batches
status: in_progress
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
- [ ] Live hide.me diagnostics show batched `OP_GLOBGETSOURCES*` packets cover
      more than the old three-server cap when more candidate servers are
      available.

## Implementation Notes

- Keep the change scoped to active transfer source batching.
- Do not change the default diagnostic source-server attempt budget globally.

## Evidence

- `cargo test -p emulebb-core global_udp_source_batch_attempts_cover_effective_server_list --locked`
- `python tools\check_rust_client_policy.py`
- `python tools\rust_quality_gate.py quick`
