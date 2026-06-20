---
id: RUST-BUG-001
workflow: local
title: kad_swarm multi-node transfer tests are isolated in CI
status: IN_PROGRESS
priority: Minor
category: bug
labels: [kad, tests, ci, flaky, debt]
milestone: phase-0
created: 2026-06-14
source: PM quality review (2026-06-14) — isolate + document CI timing debt
---

# RUST-BUG-001 - kad_swarm multi-node transfer tests are isolated in CI

## Summary

The `kad_swarm` multi-node networking tests (`emulebb-core` `--test kad_swarm`,
and `local_kad_swarm` cases) have cross-node transfer timing sensitivity. They
are **isolated** in CI: the main test step skips `local_kad_swarm`, and a
separate serialized step runs `kad_swarm` with `--test-threads=1`
(`.github/workflows/ci.yml`). The isolated step is blocking; this item tracks
the remaining isolation debt.

## Why This Matters

An isolated CI step can still hide scheduler/order coupling that would appear in
the normal workspace test matrix. The tests cover multi-node Kad transfer, a core
capability of the Phase 0 "perfectly functional" gate, so the timing sensitivity
must be diagnosed and folded back into the standard gate.

## Current State

- `ci.yml` main test step: `cargo test --workspace --locked -- --skip local_kad_swarm`.
- `ci.yml` isolated blocking step: `cargo test -p emulebb-core --test kad_swarm
  --locked -- --test-threads=1`.

## Intended Shape

- Diagnose the cross-node transfer-timing sensitivity (likely timing/port/bind or
  scheduler ordering), make the tests deterministic under the normal workspace
  runner, then fold them back into the main gating matrix.

## Acceptance Criteria

- [ ] Root cause of the timing flakiness identified and documented.
- [ ] `kad_swarm` / `local_kad_swarm` pass deterministically across the OS matrix.
- [x] CI runs the isolated `kad_swarm` step blocking.
- [ ] CI runs them in the standard workspace matrix without `--skip`.

## Notes

- Until fully folded back, the isolated step must stay visible and blocking so
  coverage is not lost; this item is its owner of record.
- 2026-06-19 parity closure review: this is CI isolation debt, not a core
  Rust-vs-MFC parity close blocker while the isolated `kad_swarm` step remains
  visible and blocking. It still belongs in the Phase 0 cleanup lane before the
  normal workspace matrix can be treated as fully rationalized.
