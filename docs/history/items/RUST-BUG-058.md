---
id: RUST-BUG-058
title: Decode ED2K UDP search-result entries without TCP count prefix
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-058: Decode ED2K UDP search-result entries without TCP count prefix

## Problem

Live-wire diagnostics showed valid `OP_GLOBSEARCHRES` UDP packets arriving during
global ED2K keyword search, but Rust still reported zero server-search results.

The Rust decoder reused the TCP `OP_SEARCHRESULT` page parser for UDP global
search replies. That parser expects a four-byte result count prefix. eMuleBB MFC
parses `OP_GLOBSEARCHRES` through `ProcessUDPSearchAnswer`, which constructs one
`CSearchFile` directly from the UDP payload without that TCP count prefix.

## Acceptance

- [x] UDP global search replies decode single search-result entries without a
      TCP count prefix.
- [x] TCP search-result page decoding keeps the count-prefixed behavior.
- [x] The live-wire observed shape is covered by a synthetic regression test.

## Implementation Notes

- Extracted the common per-result entry parser from the TCP page decoder.
- Changed the UDP decoder to parse one or more direct result entries, skipping
  chained `OP_GLOBSEARCHRES` markers when present.

## Evidence

- `cargo test -p emulebb-ed2k udp_search_result_decodes_single_entry_without_count_prefix --locked`
- `cargo test -p emulebb-ed2k ed2k_server --locked`
- hide.me-bound live-wire verification:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T143542Z\report.json`
  - Result: live UDP global search results reached the REST search output after
    the decoder stopped treating UDP replies as TCP count-prefixed pages.
