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

Live packet evidence also showed that source acquisition was using only the
static bootstrap server list, while keyword search already merged the runtime
server list imported from `server.met`. After excluding the connected server,
that left the UDP source-search path with no candidate servers.

## Acceptance

- [x] Global UDP source search still skips the connected server endpoint when a
      background server session is available.
- [x] Global UDP source search supplements empty and scarce connected-server
      source sets.
- [x] Source acquisition uses the same runtime/imported ED2K server list as
      keyword search.
- [x] Source refresh remains limited to the initial server-source round.

## Implementation Notes

- Added a focused scarcity predicate for global UDP server source
  supplementation.
- Reused the existing source-supplement threshold so Rust improves parity
  without increasing first-round UDP server traffic for already well-sourced
  files.
- Reused the effective ED2K config merge for source acquisition so imported
  servers are available to the UDP source walk.

## Evidence

- `cargo test -p emulebb-core server_udp_source_supplement_runs_for_empty_or_scarce_server_sources --locked`
- `cargo test -p emulebb-core effective_ed2k_config_includes_runtime_servers --locked`
- `python tools\rust_quality_gate.py quick`
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T155348Z\report.json`:
  VPN-bound HighID run passed, started 16 downloads, completed one candidate,
  and captured 213 outbound `OP_GLOBGETSOURCES` packets in the ED2K server UDP
  dump.
