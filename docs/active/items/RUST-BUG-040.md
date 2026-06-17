---
id: RUST-BUG-040
status: done
type: bug
area: rest
---

# RUST-BUG-040: Match single search delete response with MFC

## Problem

MFC returns `{ "ok": true }` for `DELETE /api/v1/searches/{searchId}` through
the `search/delete` command. Rust returned `{ "deleted": true }`, while the
OpenAPI contract already references the common `OkResponse`.

## Resolution

- Changed the single-search delete handler to return the canonical `ok` result.
- Added REST route coverage that rejects the old `deleted` field on the public
  response shape.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest search_delete_uses_canonical_ok_response --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
