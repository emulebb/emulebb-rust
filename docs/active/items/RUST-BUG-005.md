---
id: RUST-BUG-005
workflow: local
title: REST server rows drop live eD2K server status counters
status: DONE
priority: Major
category: bug
labels: [rest, ed2k, parity, servers]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-005 - REST server rows drop live eD2K server status counters

## Summary

Rust already decodes `OP_SERVERSTATUS`, UDP global-server-status replies, and
`OP_SERVERIDENT` into `Ed2kServerState`, but `EmulebbCore::servers()` did not
overlay those live values onto the current `ServerInfo`. eMuleBB MFC
`BuildServerJson` reports `CServer::GetUsers()`, `GetFiles()`, name, and
description from the live server model.

## Acceptance Criteria

- [x] Current server rows expose live user/file counters when the protocol state
      has them.
- [x] Current server rows expose live server name/description when the protocol
      state has them.
- [x] Local tests cover the view overlay.

## Resolution

- Extracted `EmulebbCore::servers()` into `server_list.rs`, reducing the huge
  core source while keeping the same public API.
- Added `ServerLiveDetails` and overlay the live server name, description,
  user count, and file count onto the current server row.
- Kept the protocol layer unchanged; Rust already populated these fields from
  TCP `OP_SERVERSTATUS`, UDP global-server-status, and `OP_SERVERIDENT`.

## Evidence

- `cargo test -p emulebb-core server_live_details_overlay_protocol_status --locked`
- `python tools\rust_quality_gate.py quick`
