---
id: RUST-BUG-080
title: Count embedded SX2 requests in Rust live-wire evidence
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-080: Count embedded SX2 requests in Rust live-wire evidence

## Problem

Rust live-wire reports marked `download.sourceExchangeObserved=false` even when
the ED2K TCP packet dump showed Rust sending `OP_REQUESTSOURCES2` inside
`OP_MULTIPACKET_EXT` or `OP_MULTIPACKET_EXT2` startup requests.

The MFC client sends SX2 both as a standalone `OP_REQUESTSOURCES2` packet and as
an embedded multipacket sub-op when startup uses the multipacket path. The Rust
client matched that selected-surface behavior, but the Python live-wire harness
only inferred source exchange from transfer source-count growth and daemon log
strings. Public peers may ignore the SX2 request, so source-count growth is not
equivalent to "Rust sent an SX2 source-exchange request."

## Acceptance

- [x] Live-wire evidence counts standalone `OP_REQUESTSOURCES2` sends.
- [x] Live-wire evidence counts embedded `OP_REQUESTSOURCES2` sub-ops inside
      `OP_MULTIPACKET_EXT` and `OP_MULTIPACKET_EXT2`.
- [x] `download.sourceExchangeObserved` becomes true when packet diagnostics
      prove Rust sent SX2, even if no public peer answered.
- [x] Client wire behavior is unchanged.

## Implementation Notes

- Added Python packet-dump summarization to the hide.me Rust live-wire harness.
- The parser skips the self-describing `OP_REQUESTFILENAME` ext-info block before
  counting SX2 sub-ops, avoiding raw-byte scans through hashes or variable
  payloads.
- Added unit coverage for embedded SX2 in both `OP_MULTIPACKET_EXT` and
  `OP_MULTIPACKET_EXT2`.

## Evidence

- Existing packet dumps prove the previous report was a false negative:
  - `rust-hideme-20260619T001217Z` obfuscation-on: 9 embedded SX2 requests sent.
  - `rust-hideme-20260619T001217Z` obfuscation-off: 8 embedded SX2 requests sent.
  - `rust-hideme-20260619T005416Z` obfuscation-on: 2 embedded SX2 requests sent.
  - `rust-hideme-20260619T011757Z` obfuscation-on: 4 embedded SX2 requests sent.
  - `rust-hideme-20260619T011757Z` obfuscation-off: 1 embedded SX2 request sent.
- No `OP_ANSWERSOURCES2` replies were observed in those public live captures.
- `python -m pytest tests/python/test_rust_live_wire_hideme.py -q`
