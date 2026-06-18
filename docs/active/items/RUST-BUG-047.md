---
id: RUST-BUG-047
status: done
type: bug
area: ed2k
---

# RUST-BUG-047: Keep keyword searches on the connected ED2K server session

## Problem

The Rust client could fall back to an active one-shot ED2K server keyword search
when the background server session was unavailable, returned no results, or
failed. That path opened a fresh TCP login/search session against ED2K servers.

Stock eMule/eMuleBB MFC does not do that for normal keyword searches: local ED2K
searches send `OP_SEARCHREQUEST` through the current connected server socket,
and global ED2K searches continue with UDP requests to other servers. The Rust
fallback therefore created non-stock public-server traffic and repeated the
same pattern seen in the source-search storm.

The same issue applied to hash-only ED2K metadata resolution, which reused the
active keyword search fallback before trying Kad metadata.

## Resolution

- Removed the one-shot TCP keyword-server fallback from normal ED2K searches.
- Kept keyword results sourced from the connected background server session.
- Kept hash-only metadata lookup on the connected server session first and Kad
  metadata second, without opening extra ED2K server TCP login sessions.
- Left the lower-level active keyword helper available for diagnostics or a
  future explicitly paced parity implementation.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
