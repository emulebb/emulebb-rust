---
id: RUST-BUG-048
status: done
type: bug
area: ed2k
---

# RUST-BUG-048: Do not open ad-hoc server sessions for LowID callbacks

## Problem

The Rust client could request a LowID peer callback by opening a fresh ED2K
server TCP session to the source's reported server when that server was not the
client's currently connected server.

Stock eMule/eMuleBB MFC does not do that. Its LowID connection precheck treats a
server callback as available only when `IsLocalServer(GetServerIP(),
GetServerPort())` is true, and sends `OP_CALLBACKREQUEST` through the already
connected server socket. Otherwise it uses direct UDP callback or Kad buddy
callback when available, or leaves the callback unavailable.

Opening a targeted server login for each foreign-server LowID callback therefore
created another non-stock TCP server path.

## Resolution

- Routed ED2K server callbacks only through the connected background server
  session when the source server matches the connected server.
- Skipped server callback attempts for foreign-server and unknown-server LowID
  sources.
- Left Kad buddy callback handling unchanged.
- Left the lower-level active callback helper available for diagnostics or a
  future explicitly justified parity probe.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-core callback_route_uses_only_matching_connected_server --locked`
- `cargo test -p emulebb-core --locked`
- `python tools\rust_quality_gate.py quick`
