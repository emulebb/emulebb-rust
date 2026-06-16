---
id: RUST-FEAT-006
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/6
title: Publish a linuxserver-style GHCR Docker image
status: OPEN
priority: Major
category: feature
labels: [docker, ghcr, packaging, bundle]
milestone: phase-2
created: 2026-06-16
source: SUITE-DOCKER design (2026-06-16)
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-006 - Publish a linuxserver-style GHCR Docker image

## Summary

Publish a **linuxserver-style** Docker image for the emulebb-rust headless eD2K/Kad
core to **GHCR** (`ghcr.io/emulebb/emulebb-rust`, `latest` + versioned), built and
pushed by this repo's CI. Design:
[`emulebb-tooling/docs/active/SUITE-DOCKER.md`](../../../emulebb-tooling/docs/active/SUITE-DOCKER.md).

## Why This Matters

The **enabling prerequisite** for the suite Docker bundle: without this image the
Docker form of the bundle cannot start. It is the eD2K core in the container set
(MFC is Windows-only, so Docker is rust-only for eD2K).

## Intended Shape

- **linuxserver convention:** s6-overlay, `PUID`/`PGID`, `TZ`, `/config` (state) +
  `/data` (downloads).
- Writes downloads under `/data/ed2k` so hardlink + atomic-move to `/data/media`
  works across the single shared volume (Model 1: eD2K promoted through Arr).
- Runs behind an **optional Gluetun** namespace (`network_mode: "service:gluetun"`);
  no own ports — `/api/v1` + eD2K TCP + Kad UDP are published on the fronting
  service.
- amd64 first; multi-arch later.

## Acceptance Criteria

- [ ] CI builds and pushes `ghcr.io/emulebb/emulebb-rust:latest` + a version tag on release.
- [ ] Image honours `PUID`/`PGID`/`TZ`; state under `/config`, downloads under `/data`.
- [ ] `/api/v1` + eD2K TCP + Kad UDP reachable when ports are published on a fronting service.

## Notes

- One of the four prerequisite images (with `qbittorrentbb-nox`, `trackmulebb`,
  `bountarr`). Coheres with the VPN fail-closed model (RUST-FEAT-003/005) — Gluetun
  is the Docker analog of the Windows hide.me split-tunnel.
