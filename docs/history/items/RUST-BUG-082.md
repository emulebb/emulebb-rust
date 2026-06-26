---
id: RUST-BUG-082
title: Report SX2 answer source counts in live-wire evidence
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-082: Report SX2 answer source counts in live-wire evidence

## Problem

After `RUST-BUG-080`, the Rust hide.me live-wire report showed when
`OP_ANSWERSOURCES2` packets were received, but it did not expose how many source
entries those answers carried.

The first live SX2 answer observed in `rust-hideme-20260619T021252Z` was a valid
version-4 answer with source count `0`. That is important parity evidence:
eMuleBB MFC passes the answer payload to `AddClientSources`; Rust decodes the
same payload and has no sources to remember when the count is zero. Without the
count in the report, "answer received" could be mistaken for "usable source
entries received."

## Acceptance

- [x] Live-wire packet evidence reports total source entries carried by received
      `OP_ANSWERSOURCES2` packets.
- [x] Empty SX2 answers are counted separately.
- [x] Malformed SX2 answers are counted separately.
- [x] Client wire behavior is unchanged.

## Implementation Notes

- Added Python decoding of the `OP_ANSWERSOURCES2` source-count field from
  packet diagnostics.
- Kept request counting unchanged.
- Added unit coverage for non-empty and empty SX2 answers.

## Evidence

- Live behavior exposing the issue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T021252Z`.
- The observed answer payload was version `4`, file hash matched the requested
  transfer, and source count was `0`.
- `python -m pytest tests/python/test_rust_live_wire_hideme.py -q`
