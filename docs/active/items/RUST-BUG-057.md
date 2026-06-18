---
id: RUST-BUG-057
title: Match MFC connected-server keyword search timeout
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-057: Match MFC connected-server keyword search timeout

## Problem

Rust waited only the ED2K connect timeout floor before treating a connected-server
keyword search as silent and moving on to the global UDP server walk.

eMuleBB MFC sends `OP_SEARCHREQUEST` to the connected server and arms
`TimerServerTimeout` for 50 seconds. If the local server replies sooner, global
UDP starts then; if it stays silent, global UDP starts only after that 50-second
timer expires. Rust's shorter 15-second floor was a behavioral drift.

## Acceptance

- [x] Connected-server keyword searches use a 50-second stock timeout floor.
- [x] Operator configs with a timeout above the stock floor remain honored.
- [x] The timeout floor is covered by a focused unit test.

## Implementation Notes

- Added `ED2K_LOCAL_SERVER_SEARCH_TIMEOUT_SECS` and a helper that documents the
  MFC timer source.
- Wired REST-created ED2K server/global keyword searches through the helper.

## Evidence

- `cargo test -p emulebb-core connected_server_keyword_search_timeout_matches_mfc_floor --locked`
