---
id: RUST-BUG-049
status: done
type: bug
area: ed2k
---

# RUST-BUG-049: Do not duplicate connected-server searches over UDP

## Problem

The Rust background ED2K server session sent keyword and source searches over
the connected server TCP session, then also sent an immediate UDP global-search
packet to that same connected server.

Stock eMule/eMuleBB MFC keeps those paths separate. The connected server gets
the local TCP request (`OP_SEARCHREQUEST` or `OP_GETSOURCES`), while global UDP
requests are sent later to other servers from the server list. Sending the same
request over UDP to the connected server is therefore duplicate non-stock
traffic.

## Resolution

- Removed immediate UDP keyword sends from the connected background server
  search dispatcher.
- Removed immediate UDP source sends from the connected background server source
  dispatcher.
- Left the standalone UDP source walk available to the core initial source
  acquisition path, where it excludes the connected server.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-ed2k background --locked`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
