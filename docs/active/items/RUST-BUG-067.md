---
id: RUST-BUG-067
title: Reuse remembered ED2K sources alongside fresh lookups
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-067: Reuse remembered ED2K sources alongside fresh lookups

## Problem

The hide.me live-wire run
`EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T175809Z` proved
VPN binding, HighID, Kad connectivity, server search, and packet diagnostics, but
started 18 downloads without completing one. The daemon found fresh direct
endpoints for only a few files, then later retry attempts depended on fresh
source acquisition again.

Rust remembered durable direct sources in transfer metadata, but only merged
them when the current lookup returned zero sources. eMuleBB MFC keeps sources
attached to the part file across later processing rounds, so a non-empty fresh
lookup must not hide older direct endpoints that remain valid candidates.

## Acceptance

- [x] Remembered direct sources are merged into the candidate set even when a
      fresh connected-server/Kad/UDP lookup already found other sources.
- [x] Duplicate remembered endpoints remain deduplicated by the existing source
      merge policy.
- [x] Self-source, IP-filter, and ban filtering still run after remembered
      source merge.
- [x] Focused unit coverage proves remembered endpoints are retained alongside a
      non-empty fresh source set.
- [x] The next hide.me live-wire run shows the direct attempt path can reuse
      durable remembered endpoints across retry attempts.

## Implementation Notes

- Keep durable source reuse in the source-merge helper module to avoid growing
  the core orchestration file.
- Preserve the existing MFC-aligned source sorting and direct lease logic; this
  change only restores previously learned sources to the candidate set before
  filtering and selection.

## Evidence

- `cargo test -p emulebb-core remembered_sources_are_merged_with_non_empty_fresh_sources --locked`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T184021Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T184108Z\report.json`:
  VPN-bound HighID run started 16 downloads, completed 2 files, reached 21 peak
  reported sources from 16 initial sources, captured packet diagnostics, and
  made 24 direct peer attempts. This is the follow-up pass after
  `RUST-BUG-067` increased direct peer attempts from 3 in
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T175809Z` to 16
  in `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T182219Z`.
