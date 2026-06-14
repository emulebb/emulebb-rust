---
id: FEAT-002
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/2
title: Indexer — autonomous Kad/eD2K snooping index with Torznab surface
status: OPEN
priority: Major
category: feature
labels: [kad, ed2k, indexer, torznab, suite]
milestone: phase-0
created: 2026-06-14
source: suite forward program (notes 13-15); SUITE-JOINT-ROADMAP
---

> Workflow status is tracked in GitHub: https://github.com/emulebb/emulebb-rust/issues/2. This local document is retained as an engineering spec/evidence record.

# FEAT-002 - Indexer — autonomous Kad/eD2K snooping index with Torznab surface

## Summary

Make emulebb-rust an autonomous index of the Kad + eD2K networks, not just a
client. Passive-first snoop of routed Kad traffic, plus gentle/compliant active
replay and common-extension sweeps, plus optional eD2K-server search enrichment,
into one FTS SQLite index, surfaced over Torznab. This is part of the Phase 0
"perfectly functional" gate (the indexer role is inside deliverable #1). Full
design: [`docs/design/kad-ed2k-indexer.md`](../../design/kad-ed2k-indexer.md).

## Why This Matters

The suite's "no strict reliance on servers/indexers" goal requires the client to
build its own discovery. Kad stores search-ready metadata natively (no
BEP-9-equivalent fetch), so eD2K/Kad indexing is cheaper per query than BT DHT
harvesting. The index is the eD2K half of the suite's Prowlarr-federated search.

## Intended Shape

- Passive snoop layer hooking the `emulebb-kad-net` receive loop (free, primary).
- Gentle active layers under live-wire discipline: keyword replay + curated
  common-extension dictionary sweep, widely spaced and single-pass.
- Opportunistic source/availability capture only (no dedicated source sweep).
- Optional eD2K-server `OP_SEARCH`/`OP_GETSOURCES` enrichment (never a dependency).
- Storage: SQLite + FTS5, conventions mirroring the qBittorrentBB harvester and
  `emulebb-metadata/schema.sql` (WAL, NFKC, first/last_seen_ms). Indexer schema
  parity with qBittorrentBB is a living goal, co-evolved, not frozen.

## Scope Constraints

- New modules within the `policy/rust-client.toml` size budget; no big-refactor of
  legacy `.rs`. SQLite-only (no on-disk metadata-file mirror).
- Active querying must respect [[live-wire-be-gentle-no-ban]]: no aggressive
  enumeration, protocol-compliant.
- Out of scope: cooperative-DHT mechanisms and BEP-46 publishing (parked, see
  `emulebb-tooling/docs/ideas/IDEA-COOPERATIVE-DHT-COOPERATION.md`).

## Acceptance Criteria

- [ ] Passive snoop populates the index from routed Kad keyword/source/search
      traffic with zero extra queries.
- [ ] Active replay + common-extension sweep run under a documented rate budget.
- [ ] FTS SQLite index with the shared column conventions; queryable by keyword.
- [ ] Torznab endpoint serving the index (same dialect/caps/apikey as qBittorrentBB).
- [ ] eD2K-server enrichment is optional and absent-server-safe.

## Validation

- Unit: codec/index round-trips; sweep rate-budget math; Torznab response shape.
- Local: snoop populates the index against a local Kad/eD2K fixture; Torznab query
  returns indexed results.
- Gentle live witness per live-wire policy before any public-network run.

## Notes

- Surfaces pair with FEAT-004 (Arr integration). Design parity tracked against the
  qBittorrentBB harvester.
