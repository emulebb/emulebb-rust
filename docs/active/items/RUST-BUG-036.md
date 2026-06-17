---
id: RUST-BUG-036
status: done
type: bug
area: rest
---

# RUST-BUG-036: Align search ids with MFC decimal path tokens

## Problem

Rust generated search session ids as UUID strings and did not validate
`searchId` path parameters. The MFC `/api/v1` seam exposes search ids as public
decimal strings, validates `{searchId}` as a bounded unsigned decimal path
token, and then resolves the decimal token through the search handlers.

## Resolution

- Replaced new Rust search-session UUIDs with monotonic decimal string ids.
- Initialized the next search id from numeric persisted search ids without
  deleting older non-numeric rows.
- Added MFC-style `searchId` path validation for search read/delete and
  search-result download routes.
- Updated REST validation tests that used non-decimal placeholder search ids.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-core search_uses_local_index --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
