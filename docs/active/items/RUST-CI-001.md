---
id: RUST-CI-001
title: Capture ED2K global UDP packets in diagnostics
status: done
priority: Major
category: ci
workflow: local
---

# RUST-CI-001: Capture ED2K global UDP packets in diagnostics

## Problem

The diagnostics Release build emitted structured `ed2k_packet_v1` records for
connected-server TCP and listener flows, but active ED2K server UDP helper
traffic was visible only in daemon text logs.

That left live-wire parity analysis weaker than MFC packet diagnostics for the
global UDP search path: global keyword/source requests, status requests, and
server UDP replies could not be diffed as structured packet records.

## Acceptance

- [x] ED2K server UDP helper sends are recorded as `ed2k_packet_v1`.
- [x] Successfully decoded ED2K server UDP receives are recorded as
      `ed2k_packet_v1`.
- [x] UDP records include global search/source and status opcode names.
- [x] The existing diagnostics feature gate keeps normal builds unchanged.

## Implementation Notes

- Added a UDP packet-dump emitter beside the existing server TCP emitter.
- Wired the UDP runtime send/receive boundary so all server UDP helper callers
  inherit the diagnostics.
- Added focused coverage for global UDP opcode names in diagnostic records.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-ed2k server_dump_names_global_udp_opcodes --locked`
