---
id: RUST-BUG-074
title: Include reaskCount in Rust UDP reask diagnostics
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-074: Include reaskCount in Rust UDP reask diagnostics

## Problem

The corrected hide.me live-wire reask run `rust-hideme-20260618T223339Z`
confirmed that Rust emits the same `sched/reask_sent` event family as eMuleBB
MFC for outbound UDP source reasks. Comparing the event bodies found a small
diagnostics parity drift:

- MFC emits `{"outcome":"sent","transport":"udp","reaskCount":N}` from
  `DiagEventLogUdpReaskSent`.
- Rust emitted `{"outcome":"sent","transport":"udp"}` per successful send.

The Rust event was behaviorally correct, but the missing `reaskCount` field made
MFC-vs-Rust diagnostics diffs less direct.

## Acceptance

- [x] Rust `sched/reask_sent` events include `reaskCount`.
- [x] Per-send Rust events use `reaskCount: 1`, preserving the existing event
      cadence while matching the MFC aggregate field shape.
- [x] Focused unit coverage locks the event body shape.

## Implementation Notes

- Added a small helper for the Rust UDP reask diagnostics body.
- `drive_reask_tick` now emits `reaskCount: 1` for each successful outbound UDP
  reask send.

## Evidence

- `cargo test -p emulebb-ed2k udp_reask_sent_body_matches_mfc_diag_shape --locked`
