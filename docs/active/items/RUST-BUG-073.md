---
id: RUST-BUG-073
title: Preserve MFC queued-source UDP reask cadence
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-073: Preserve MFC queued-source UDP reask cadence

## Problem

The hide.me live-wire diagnostics run
`rust-hideme-20260618T215028Z` exposed a queued-source parity gap when UDP reask
was enabled: the run stayed VPN-bound and connected, but completed no downloads
while producing many UDP reask log entries. Packet diagnostics showed a queued
direct source being moved to UDP reask immediately after a TCP queue-rank
response.

Reviewing the Rust state machine against eMuleBB MFC found two related drifts:

- MFC sends the TCP file request in `CUpDownClient::SendFileRequest()` and then
  immediately stamps `SetLastAskedTime()`.
- MFC later gates `UDPReaskForDownload()` through `GetTimeUntilReask()`, so a
  queued source is not reasked over UDP until the normal `FILEREASKTIME` window
  expires.
- MFC also refuses UDP reask while the TCP socket is still connected:
  `UDPReaskForDownload()` checks `!(socket && socket->IsConnected())`.
- Rust registered a TCP-detached queued source with `next_reask = now`, making
  the first UDP reask immediately due. Global pacing could suppress the packet in
  short live runs, but the source-state cadence was still too aggressive.
- Rust also detached on the queue-rank packet itself, closing the TCP session
  before a late `OP_ACCEPTUPLOADREQ` could arrive.

## Acceptance

- [x] TCP queue-rank packets keep the connected TCP session alive so late accept
      packets can still start a transfer.
- [x] TCP-queued sources detached onto the UDP reask loop after an incomplete TCP
      exit are not immediately due for a UDP reask.
- [x] Their first detached reask is delayed by the MFC file reask interval.
- [x] Kad buddy-only source registration remains immediately due because no TCP
      file request was sent first.
- [x] Focused unit coverage proves an initial reask delay suppresses the first
      tick until the configured delay expires.
- [x] Focused queue coverage proves a queued peer can send a late accept after
      the read timeout and complete without emitting a reask-detach command.
- [x] Existing queued-source, reask, and Kad buddy tests still pass.

## Implementation Notes

- `ReaskDetachArgs` now carries an explicit `initial_reask_delay`.
- TCP download sessions no longer detach to UDP reask when the queue-rank packet
  arrives. They detach only on incomplete TCP exits after the queued session is
  gone or has timed out.
- The TCP queued-source detach path sets the first UDP reask delay to
  `FILE_REASK_TIME`, matching the MFC `SetLastAskedTime()` plus
  `GetTimeUntilReask()` cadence.
- The Kad buddy source path uses `Duration::ZERO`, preserving immediate first
  contact for sources that have not just been asked over TCP.
- The detach helper moved out of the already-large download session file into
  `ed2k_tcp::download::session::reask_detach`.

## Evidence

- `cargo test -p emulebb-ed2k register_command_respects_initial_reask_delay --locked`
- `cargo test -p emulebb-ed2k ed2k_client_udp:: --locked`
- `cargo test -p emulebb-ed2k download::queue_only --locked`
- `cargo test -p emulebb-core kad_buddy --locked`
- `cargo test -p emulebb-core disconnect_releases_detached_reask_source_leases_and_re_engages --locked`
- `cargo fmt --all --check`
- `python tools/rust_quality_gate.py quick`
- `python -m emule_workspace build clients --client emulebb-rust --diagnostics`
- hide.me live-wire run `rust-hideme-20260618T221517Z` with `--reask` and
  packet diagnostics: passed, VPN-bound, HighID, Kad connected, 20 downloads
  started, 2 downloads completed, 2 TCP queue-rank packets observed, 6
  `OP_ACCEPTUPLOADREQ` packets observed, and no immediate queue-rank
  `QueuedDetached` diagnostics.
