---
id: RUST-BUG-051
title: Route public searches through the selected ED2K or Kad network
status: done
priority: Major
type: bug
workflow: local
labels: [search, kad, ed2k, parity]
---

# RUST-BUG-051: Route public searches through the selected ED2K or Kad network

Rust accepted `POST /api/v1/searches` with `method=kad`, but the background
search path only drove ED2K server keyword search. Explicit Kad searches could
therefore use the connected ED2K server instead of Kad, and automatic searches
could not fall back to Kad when it was the only connected search network.

eMuleBB MFC resolves `automatic` before dispatch: ED2K connectivity selects
global ED2K search; Kad is selected only when it is the sole connected search
network. Explicit `server`, `global`, and `kad` methods stay on their selected
network.

## Acceptance Criteria

- [x] Search method routing is resolved from live ED2K/Kad connectivity before
      background search dispatch.
- [x] Explicit `kad` searches do not run ED2K server searches.
- [x] Explicit `kad` searches collect Kad keyword results.
- [x] Automatic searches fall back to Kad keyword results when Kad is connected
      and ED2K is not.
- [x] Kad keyword query selection follows the MFC first-keyword/invalid-character
      rules.

## Implementation Notes

- `search_query::resolve_search_network_method` now implements the MFC automatic
  resolution policy.
- `run_background_search` dispatches ED2K only when the resolved method is
  `Ed2kServer` or `Ed2kGlobal`.
- `search_kad_keywords` now streams DHT keyword results into the same REST
  `SearchResult` DTO used by local and ED2K server searches, with per-search
  hash de-duplication and a bounded result cap.
- Public Kad search now hashes the MFC-style first keyword, with quote trimming,
  lowercase normalization, and the stock invalid-character set.
