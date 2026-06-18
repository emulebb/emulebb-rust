---
id: RUST-BUG-056
title: Ignore malformed ED2K UDP global-search replies
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-056: Ignore malformed ED2K UDP global-search replies

## Problem

During hide.me-bound live-wire testing, Rust reached ED2K HighID and started the
stock-style global UDP keyword search walk, but one public server reply with a
malformed search-result tag aborted the whole global search.

eMuleBB MFC follows the stock eMule UDP receive model: malformed or unrelated UDP
datagrams are discarded at the receive boundary, and the client keeps waiting or
continues the server walk. A single malformed public UDP reply must not become a
fatal search error.

## Acceptance

- [x] Malformed ED2K UDP keyword global-search replies are logged and discarded.
- [x] Malformed ED2K UDP source global-search replies are logged and discarded.
- [x] Background UDP searches keep their pending request alive after malformed
      replies so a later valid reply or the normal timeout decides completion.
- [x] Focused regression tests cover malformed background UDP keyword and source
      replies.

## Implementation Notes

- Converted `OP_GLOBSEARCHRES` UDP decoding in active global keyword search from
  fatal propagation to warn-and-discard handling.
- Applied the same non-fatal handling to active UDP source search, including
  mismatched source-result sets.
- Updated background UDP keyword/source handlers to restore the pending search
  after malformed UDP input instead of consuming the responder.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-ed2k background_udp --locked`
- hide.me-bound live-wire pass:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T140539Z\report.json`
  - Result: passed with VPN bind, ED2K HighID, Kad connected, public search
    results, completed downloads, and packet diagnostics captured.
  - Malformed ED2K UDP keyword-search response was discarded without aborting
    the global server walk.
