---
id: RUST-BUG-097
title: Cancel accepted slots when no block is claimable
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-097: Cancel accepted slots when no block is claimable

## Problem

Live hide.me packet captures showed peers sending `OP_ACCEPTUPLOADREQ` while
Rust then waited until the peer-session timeout without sending
`OP_REQUESTPARTS`. In the matching MFC path, `CUpDownClient::ProcessAcceptUpload`
enters `StartDownload()`, and `SendBlockRequests()` either sends
`OP_REQUESTPARTS` or, when no useful block can be reserved, sends
`OP_CANCELTRANSFER` and transitions through No Needed Parts / A4AF.

Rust's request window could return idle when all useful blocks were already
claimed by another live session. That left the granted upload slot occupied
until timeout instead of releasing it immediately.

## Acceptance

- [x] An accepted peer with a claimable block still receives `OP_REQUESTPARTS`.
- [x] An accepted peer with no claimable block receives `OP_CANCELTRANSFER`.
- [x] The session returns the existing `NoNeededParts` outcome so the caller can
      run the A4AF-lite swap path.

## Implementation Notes

- `pump_download_request_window` now distinguishes `RequestSent`, `Idle`, and
  `NoClaimablePart`.
- The download session sends `OP_CANCELTRANSFER` and returns `NoNeededParts`
  when the accepted request window is empty with no active or pending block.

## Evidence

- Compared against MFC `CUpDownClient::ProcessAcceptUpload`,
  `CUpDownClient::StartDownload`, and `CUpDownClient::SendBlockRequests`.
- Live-wire clue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T063351Z`
  recorded accepted slots ending in `peer_timeout_incomplete` without an
  outbound request-parts packet.
- `cargo test -p emulebb-ed2k accepted_peer_without_claimable_blocks_is_cancelled_as_no_needed_parts -- --nocapture`
