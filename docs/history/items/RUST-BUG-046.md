---
id: RUST-BUG-046
status: done
type: bug
area: ed2k
---

# RUST-BUG-046: Keep source refresh requery off ED2K servers

## Problem

After the initial source acquisition round, the Rust download loop can run
short requery rounds after only a few seconds. eMule/eMuleBB MFC does not ask
the connected ED2K server for the same file on that cadence: local server source
requests are paced by `SERVERREASKTIME` (15 minutes), while global server UDP
walks are paced separately.

Running ED2K server source refreshes inside the short requery loop therefore
drifts from stock behavior and risks unnecessary public-server pressure.

## Resolution

- Kept ED2K server source refresh enabled for the initial acquisition round.
- Disabled ED2K server TCP/UDP source refresh during short retry/requery rounds.
- Left Kad supplementation and remembered source reuse available during requery.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-core ed2k_server_source_refresh_is_initial_round_only --locked`
- `cargo test -p emulebb-core global_udp_source_search_skips_connected_server_only_when_background_is_available --locked`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
