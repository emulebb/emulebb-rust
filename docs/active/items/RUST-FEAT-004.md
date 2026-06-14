---
id: RUST-FEAT-004
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/4
title: Arr integration — Torznab indexer + qBittorrent-emulating download client
status: OPEN
priority: Major
category: feature
labels: [arr, torznab, qbittorrent-api, prowlarr, suite]
milestone: phase-0
created: 2026-06-14
source: suite forward program (note 15); SUITE-JOINT-ROADMAP
---

> Workflow status is tracked in GitHub: https://github.com/emulebb/emulebb-rust/issues/4. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-004 - Arr integration — Torznab indexer + qBittorrent-emulating download client

## Summary

Give emulebb-rust the three Arr-stack roles alongside its native `/api/v1` REST:
a Torznab indexer (serving the RUST-FEAT-002 index), a Prowlarr indexer definition,
and a qBittorrent-WebUI-emulating download-client API so Prowlarr/Sonarr/Radarr
and aMuTorrent drive rust as if it were a qBittorrent — zero new integration.

## Why This Matters

This is how the self-built eD2K/Kad index plugs into tooling operators already
use, and how the suite controller drives rust uniformly. It mirrors the pattern
eMuleBB (MFC) already proved with its `/api/v2` compat + Torznab adapters; copy
that pattern rather than invent one.

## Intended Shape

- Torznab endpoint over the REST surface; same dialect/caps/apikey scheme and the
  "everything category 8000/Other" decision as qBittorrentBB (known limitation:
  weak category routing for the Arr stack — conscious for now).
- A suite Prowlarr indexer definition (YAML), shared shape with qBittorrentBB.
- A qBittorrent-WebUI-API-compatible download-client surface (add/list/pause/
  resume/delete mapped to eD2K transfers).
- Grabs route directly to the client (standard Arr flow); aMuTorrent is an
  optional layer on top, not a required hop.

## Scope Constraints

- Reuse the eMuleBB MFC `WebServerQBitCompat`/`WebServerArrCompat` shapes as the
  contract reference; keep the native `/api/v1` as the primary control surface.
- Federation across cooperating operators' Torznab endpoints is the app-layer form
  of cooperation; deeper wire-level cooperation is parked (see cooperation idea).

## Acceptance Criteria

- [ ] Torznab endpoint returns valid results from the RUST-FEAT-002 index to Prowlarr.
- [ ] Prowlarr recognizes rust via the shared suite indexer definition.
- [ ] Sonarr/Radarr/aMuTorrent can add and manage a download treating rust as a
      qBittorrent download client.
- [ ] `/api/v1` remains the primary native control/search surface, unchanged.

## Validation

- Contract tests for the Torznab response and the qBit-compat endpoints.
- Local Prowlarr + Arr smoke: search via Torznab, grab → download appears in rust.

## Notes

- Depends on RUST-FEAT-002 for index content. Parity with the qBittorrentBB Torznab
  contract is a living goal (co-evolved, not frozen).
