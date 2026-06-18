---
id: RUST-BUG-044
status: done
type: bug
area: ed2k
---

# RUST-BUG-044: Avoid one-shot TCP server source-search storms

## Problem

Live packet diagnostics showed the Rust download source refresh path opening
hundreds of one-shot ED2K server TCP sessions for `active_sources`, each sending
`OP_LOGINREQUEST` before `OP_GETSOURCES`. eMule/eMuleBB MFC uses the connected
server TCP session for local `OP_GETSOURCES` requests and global server UDP
walks for other servers, both with conservative pacing.

The Rust behavior was non-stock and caused public servers to close many sessions
before `OP_IDCHANGE`, producing repeated HighID wait timeouts in live-wire runs.

## Resolution

- Removed one-shot TCP server source searches from the normal download source
  acquisition path.
- Kept connected-server source lookups on the background ED2K server session.
- Kept global UDP source search as the server fallback, excluding the connected
  server to match eMule's global UDP walk shape.
- Left the one-shot TCP source-search implementation available for explicit
  diagnostics or future fallback work, but no longer used it for ordinary
  download refreshes.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-core global_udp_source_search_skips_connected_server_only_when_background_is_available --locked`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
