---
id: RUST-BUG-061
title: Supplement scarce connected-server sources with global UDP source search
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-061: Supplement scarce connected-server sources with global UDP source search

## Problem

Rust only ran the global UDP ED2K server source-search path when the connected
server TCP source request returned zero sources.

eMuleBB MFC keeps the global UDP source walk active for files that are still
below their source cap. A connected-server answer with one or two sources should
not suppress UDP server discovery entirely.

## Acceptance

- [x] Global UDP source search still skips the connected server endpoint when a
      background server session is available.
- [x] Global UDP source search supplements empty and scarce connected-server
      source sets.
- [x] Source refresh remains limited to the initial server-source round.

## Implementation Notes

- Added a focused scarcity predicate for global UDP server source
  supplementation.
- Reused the existing source-supplement threshold so Rust improves parity
  without increasing first-round UDP server traffic for already well-sourced
  files.

## Evidence

- `cargo test -p emulebb-core server_udp_source_supplement_runs_for_empty_or_scarce_server_sources --locked`
- `python tools\rust_quality_gate.py quick`
