---
id: RUST-BUG-002
workflow: local
title: REST ED2K status reports LowID as HighID
status: DONE
priority: Major
category: bug
labels: [rest, ed2k, parity, lowid]
milestone: phase-0
created: 2026-06-17
source: iterative Rust-vs-MFC parity review (2026-06-17)
---

# RUST-BUG-002 - REST ED2K status reports LowID as HighID

## Summary

The Rust REST stats and server-status surfaces reported every connected eD2K
session as HighID. The MFC surface reports `ed2kHighId` as connected and not
LowID, and reports `servers.lowId` from the server connection's LowID verdict.

## Why This Matters

LowID is a user-visible connectivity state and affects callback/reachability
diagnostics. Reporting it as HighID hides real firewall/reachability failures and
breaks parity with the MFC REST surface.

## Acceptance Criteria

- [x] Core eD2K status carries the connected server session's LowID/firewalled
      verdict.
- [x] REST global stats report `ed2kHighId=false` when connected LowID.
- [x] REST server status reports `lowId=true` for connected LowID and `null`
      while disconnected.
- [x] Local tests cover the LowID REST mapping.

## Evidence

- Fixed in the local `RUST-BUG-002` implementation slice.
- Validation: targeted `emulebb-rest low_id` tests and the Rust `quick` gate.
