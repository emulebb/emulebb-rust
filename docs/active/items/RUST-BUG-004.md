---
id: RUST-BUG-004
workflow: local
title: REST server status does not report live connecting state
status: DONE
priority: Major
category: bug
labels: [rest, ed2k, parity, servers]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-004 - REST server status does not report live connecting state

## Summary

The Rust REST server status surface reported `connecting=false` unconditionally,
and server rows were built with `connecting=false`. eMuleBB MFC reports
`ServerConnect::IsConnecting()` globally and marks the current server row as
connecting while a server connection attempt is in progress.

## Acceptance Criteria

- [x] The live eD2K server state records a connecting attempt separately from an
      established connection.
- [x] REST server status reports `connecting=true` while connecting.
- [x] The current server row reports `connecting=true` for the attempted
      endpoint and `connected=false` until login succeeds.
- [x] Local tests cover the REST mapping.

## Resolution

- Added `Ed2kServerState::connecting` and update it at server dial start,
  login acceptance/rejection, setup rollback, and session clear.
- Core server views now derive `connected`, `connecting`, and `current` from
  the live eD2K server state, so a pending target is visible like MFC
  `ServerConnect::IsConnecting()`.
- REST `/server/status` now reports the live connecting aggregate instead of a
  constant `false`.

## Evidence

- `cargo test -p emulebb-ed2k server_connect_rolls_back_connecting_state_on_setup_failure --locked`
- `cargo test -p emulebb-core server_connection_flags --locked`
- `cargo test -p emulebb-rest server_status_reports_connecting_current_server --locked`
