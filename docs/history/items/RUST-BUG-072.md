---
id: RUST-BUG-072
title: Do not expire queued connected-server source requests before dispatch
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-072: Do not expire queued connected-server source requests before dispatch

## Problem

The post-`RUST-BUG-071` hide.me live-wire runs stayed VPN-bound, HighID, and
Kad-connected, but failed to complete a payload. Packet and daemon logs showed
that most started downloads never reached direct peers because connected-server
source requests timed out at the caller while waiting in the background-session
queue:

- `rust-hideme-20260618T201235Z`: 18
  `timed out waiting for ED2K background source response after 15s` failures.
- `rust-hideme-20260618T202723Z`: 35 caller-side 15-second source-response
  timeouts plus one in-session `OP_FOUNDSOURCES` timeout.

eMuleBB MFC buffers local server source requests into TCP frames in
`DownloadQueue.cpp` and later accepts `OP_FOUNDSOURCES` asynchronously in
`ServerSocket.cpp`. It does not start a per-file source-response timeout before
the request is dispatched on the connected server session. Rust used the same
15-second timeout both inside the session driver and around the caller's
oneshot wait, so concurrent downloads could expire before their request was
even sent.

## Acceptance

- [x] Connected-server source requests still carry a timeout used after dispatch.
- [x] Waiting in the background-session queue does not consume the dispatch
      timeout.
- [x] Cancellation still aborts the caller wait promptly.
- [x] Focused unit coverage proves a queued source request can wait longer than
      its dispatch timeout before being answered.
- [x] The next hide.me live-wire diagnostics run shows fewer caller-side
      connected-server source timeouts and more source acquisition opportunity.

## Implementation Notes

- Keep keyword searches unchanged; user-facing keyword searches still need a
  caller-visible timeout.
- This fix only changes connected-server source lookup queue semantics. It does
  not increase server request rate or add new server login sessions.

## Evidence

- `cargo test -p emulebb-ed2k background_source_search_waits_while_queued_before_dispatch --locked`
- `cargo test -p emulebb-ed2k background_source_search_cancel_stops_queued_wait --locked`
- `cargo test -p emulebb-ed2k background_source_search_channel_round_trips_results --locked`
- `cargo test -p emulebb-ed2k background_udp_source_search_preserves_responding_server --locked`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T210610Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T210709Z\report.json`:
  VPN-bound HighID run passed, started 17 downloads, completed 4 files
  (5388230 bytes total), reached 32 peak reported sources, stayed Kad-connected
  with 70 contacts, and captured packet diagnostics (5491 diagnostic records,
  968 ED2K packet records, 4609 Kad UDP packet records).
- Source-acquisition comparison:
  `rust-hideme-20260618T201235Z` had 18 caller-side
  `timed out waiting for ED2K background source response after 15s` failures,
  8 direct attempts, and 0 completed files. `rust-hideme-20260618T202723Z` had
  35 caller-side source-response timeouts, 14 direct attempts, and 0 completed
  files. The fixed run had 0 caller-side source-response timeouts, 29 direct
  attempts, 4 completed files, and retained the RUST-BUG-071 scheduler fix
  (`reason=direct_sources_deferred` remained 0).
