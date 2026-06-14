---
id: RUST-BUG-001
workflow: local
title: kad_swarm multi-node transfer tests are flaky and run non-blocking in CI
status: OPEN
priority: Minor
category: bug
labels: [kad, tests, ci, flaky, debt]
milestone: phase-0
created: 2026-06-14
source: PM quality review (2026-06-14) — isolate + document CI non-blocking debt
---

# RUST-BUG-001 - kad_swarm multi-node transfer tests are flaky and run non-blocking in CI

## Summary

The `kad_swarm` multi-node networking tests (`emulebb-core` `--test kad_swarm`,
and `local_kad_swarm` cases) have unstable cross-node transfer timing. To keep the
CI matrix green they are **isolated**: the main test step skips `local_kad_swarm`,
and a separate `continue-on-error` step runs `kad_swarm` non-blocking
(`.github/workflows/ci.yml`). This item tracks that isolation as **known debt** so
the non-blocking step does not silently rot.

## Why This Matters

A `continue-on-error` test step is invisible debt: a real Kad regression could hide
behind the flakiness. The tests cover multi-node Kad transfer, a core capability of
the Phase 0 "perfectly functional" gate, so the flakiness must be diagnosed and the
gate restored to blocking — not left non-blocking indefinitely.

## Current State

- `ci.yml` main test step: `cargo test --workspace --locked -- --skip local_kad_swarm`.
- `ci.yml` non-blocking step: `cargo test -p emulebb-core --test kad_swarm --locked
  -- --test-threads=1` with `continue-on-error: true`.

## Intended Shape

- Diagnose the cross-node transfer-timing nondeterminism (likely timing/port/bind
  or scheduler ordering), make the tests deterministic, then **remove
  `continue-on-error`** and fold them back into the gating matrix.

## Acceptance Criteria

- [ ] Root cause of the timing flakiness identified and documented.
- [ ] `kad_swarm` / `local_kad_swarm` pass deterministically across the OS matrix.
- [ ] CI runs them **blocking** (remove `continue-on-error` and the `--skip`).

## Notes

- Until fixed, the non-blocking step must stay visible (do not delete it) so the
  coverage is not lost; this item is its owner of record.
