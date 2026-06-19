---
id: RUST-BUG-081
title: Stop Rust live-wire downloads after first completion
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-081: Stop Rust live-wire downloads after first completion

## Problem

The Rust hide.me live-wire harness documents that the download phase passes as
soon as at least one started transfer completes, and the pass status uses the
same criterion. The implementation still waited until every started transfer
completed or the full download timeout elapsed.

During `rust-hideme-20260619T021252Z`, obfuscation-on completed many transfers
early and obfuscation-off completed one transfer early, but each pass kept
running until the configured download window expired. That wastes public-network
live-test time and makes the "check and intervene" loop slower without adding a
stronger pass condition.

## Acceptance

- [x] The download loop returns once any started transfer completes.
- [x] The reported completion count, bytes, progress, and source counts still
      come from the final observed snapshot.
- [x] Existing packet-diagnostic source-exchange evidence still runs after the
      daemon stops.

## Implementation Notes

- Changed the live-wire download loop condition from "until all started
  transfers complete" to "until one started transfer completes."
- Added unit coverage for two started transfers where one completes and the
  other remains incomplete.

## Evidence

- Live behavior exposing the issue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T021252Z`.
- `python -m pytest tests/python/test_rust_live_wire_hideme.py -q`
