---
id: RUST-BUG-003
workflow: local
title: REST network status reports placeholder ports and binding
status: DONE
priority: High
category: bug
labels: [rest, parity, network]
created: 2026-06-17
source: Rust/MFC parity review
---

# RUST-BUG-003 - REST network status reports placeholder ports and binding

## Summary

The Rust REST status/snapshot network object reported `0` ports and empty bind
fields even when the eD2K network was configured. eMuleBB MFC's
`BuildNetworkStatusJson` reports the configured TCP/UDP ports plus the configured
and active bind address/interface state.

## Acceptance Criteria

- [x] REST `network.ports.tcp` reports the configured eD2K TCP listen port.
- [x] REST `network.ports.udp` reports the configured Kad/eD2K UDP listen port.
- [x] REST `network.binding` reports configured P2P bind IP/interface origin and the
  current resolve token instead of unconditional placeholders.
- [x] Interface-only, IP-only, and IP+interface bind configurations remain valid.

## Notes

- Rust currently has no stable configured eD2K server UDP local port equivalent;
  the server UDP helper binds ephemeral sockets, so `serverUdp` remains `0`.

## Evidence

- Fixed in the local `RUST-BUG-003` implementation slice.
- Validation: targeted `network_binding`, `network_response`, and daemon
  interface-only binding tests plus the Rust `quick` gate.
