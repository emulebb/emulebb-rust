---
id: RUST-BUG-050
status: done
type: bug
area: ed2k
---

# RUST-BUG-050: Add global ED2K UDP keyword search

## Problem

The Rust client searched keywords only through the connected ED2K server TCP
session. Stock eMule/eMuleBB MFC sends the local `OP_SEARCHREQUEST` over the
connected server socket, then global ED2K searches continue over UDP with
`OP_GLOBSEARCHREQ*` requests to other servers from the server list.

Without that UDP walk, explicit global searches and automatic searches had less
server-side coverage than the MFC client.

## Resolution

- Added a UDP keyword search helper for `OP_GLOBSEARCHREQ`,
  `OP_GLOBSEARCHREQ2`, and `OP_GLOBSEARCHREQ3`.
- Wired core keyword search so `automatic` and `global` methods combine the
  connected-server TCP result page with UDP global results from other servers.
- Kept `server` searches on the connected server only.
- Deduplicated ED2K network results by file hash before merging them into the
  REST search session.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-ed2k udp_keyword_search_request --locked`
- `cargo test -p emulebb-core ed2k_global_keyword_search_runs_for_automatic_and_global_methods --locked`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
