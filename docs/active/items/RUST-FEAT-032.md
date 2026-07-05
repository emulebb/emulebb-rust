---
id: RUST-FEAT-032
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: Kad - routing-zone consolidation (merge sparse sibling leaf bins on the 45-minute timer)
status: OPEN
priority: Minor
category: feature
labels: [kad, routing, parity]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: Protocol & internals parity review 2026-07-02 (finding A4); 0.1.0-beta.1 release program (2026-07-05)
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-032 - Kad routing-zone consolidation

## Summary

Implement stock Kad routing-table consolidation: on a 45-minute cadence, merge
sibling leaf bins whose combined contact count has fallen below K/2 back into
their parent, keeping the routing tree compact as contacts churn out. Absent
today; the rust table only ever splits, so long-running nodes accumulate
sparse leaf pairs. Also directly serves the RUST-FEAT-002 indexer ambition
(healthier routing tree over long uptimes).

## Oracle

`srchybrid/kademlia/routing/RoutingZone.cpp:745-784` (`Consolidate`), cadence
`srchybrid/kademlia/kademlia/Kademlia.cpp:310` (every `MIN2S(45)`): post-order
walk; a branch whose children are **both leaves** and whose combined contact
count is strictly `< K/2` merges the two bins into a new parent bin,
re-`AddContact`ing every child contact (rejects are dropped).

## Intended Shape

- `crates/emulebb-kad-routing/src/zone.rs`: `consolidate_walk` mirroring the
  oracle (both-leaf + strict `< K/2`, bottom-up).
- `crates/emulebb-kad-routing/src/table.rs`: `consolidate()` running the walk
  through the **same accounting as removal** (per-IP /24 counters,
  `total_contacts` — the `small_timer_maintenance` pattern) so cached counters
  cannot drift when a merged bin rejects a contact.
- Passthrough on `DhtNode` in `emulebb-kad-dht`; 45-minute tick counter in
  `crates/emulebb-core/src/kad_routing_maintenance.rs` beside the existing
  small/big timer counters (whole-table pass, the accepted rust pattern).

## Acceptance Criteria

- [ ] Sparse sibling leaves merge; every surviving contact is preserved.
- [ ] Combined count exactly K/2 does **not** merge (strict less-than).
- [ ] Multi-level tree consolidates bottom-up in one pass.
- [ ] IP-bookkeeping and `total_contacts` stay consistent when the merged bin
      rejects a contact on re-add.
- [ ] Existing split/maintenance tests unaffected; kad_swarm smoke passes.
