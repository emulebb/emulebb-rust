---
id: RUST-BUG-099
title: Name deprecated Kad hello packets in diagnostics
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-099: Name deprecated Kad hello packets in diagnostics

## Problem

The hide.me live-wire diagnostics run reported one received Kad opcode `0x10` as
`UNKNOWN`. eMuleBB MFC names this legacy opcode
`KADEMLIA_HELLO_REQ_DEPRECATED`; the matching response opcode is
`KADEMLIA_HELLO_RES_DEPRECATED`.

This is a diagnostics gap only. It does not add legacy Kad handling and does not
change the supported Kad2 behavior.

## Acceptance

- [x] Kad diagnostics name opcode `0x10` as `KADEMLIA_HELLO_REQ_DEPRECATED`.
- [x] Kad diagnostics name opcode `0x18` as `KADEMLIA_HELLO_RES_DEPRECATED`.
- [x] Unit coverage locks the labels.

## Evidence

- Live-wire clue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T075800Z`
  contained one received plaintext Kad opcode `0x10` labeled `UNKNOWN`.
- Compared against eMuleBB MFC `Opcodes.h`.
