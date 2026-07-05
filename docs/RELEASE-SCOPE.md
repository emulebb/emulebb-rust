# emulebb-rust Release Scope (`rust-v0.1.0-beta.1`)

This document is the unambiguous, human-facing statement of what the
`emulebb-rust` client **does**, what it **intentionally omits**, and what is
**deferred** for a later release. It is the companion to the machine-readable
authority `policy/rust-client-omissions.toml` — that registry is the source of
truth; this doc must not drift from it (the `[review_reporting]` excluded list in
`policy/rust-client.toml` mirrors the same ids). `tools/check_rust_client_policy.py`
keeps the registry and excluded list consistent.

`emulebb-rust` is a **headless eD2K/Kad client** driven over its `/api/v1` REST
contract. It stays stock-compatible on the eD2K and Kad wire; divergences below
are deliberate and either compatibility-neutral or strictly gentler than stock.

## Supported surface

- **eD2K (IPv4):** server login/ident (HighID + LowID), search, source
  discovery (connected-server TCP + global UDP), download and upload with the
  full block/part protocol (multipacket, compressed parts, 64-bit offsets),
  hashset + AICH request/answer, ICH block-level salvage, secure identification
  (RSA), credits/clients persistence, upload queue with scoring and elastic
  broadband slots, UDP source reask, and the eD2K server-mediated LowID callback.
- **Kad (IPv4):** bootstrap, routing table (split / weak-replacement / small- &
  big-timer maintenance / zone consolidation), lookups incl. the FIND_VALUE_MORE
  re-ask, keyword/source/notes search + publish, firewall self-check (UDP + TCP),
  the LowID **buddy** system and buddy-relayed callbacks, and the local
  keyword/source index.
- **Finished-file delivery:** completed downloads are materialized by name into
  the per-transfer category path, else the configured `incomingDir` (hard-link
  on the same volume, copy+atomic-rename across volumes; the internal piece
  store is retained for continued seeding).
- **Safety:** fail-closed VPN egress pinning of every P2P socket to the tunnel
  interface (`IP_UNICAST_IF`); with the tunnel down, zero P2P data-plane traffic
  and the control plane still answers (RUST-FEAT-003 pin + RUST-FEAT-005 leak
  test).
- **Control plane:** the eMuleBB-compatible `/api/v1` REST contract (contract
  version `1.0.0`, `x-contract-version`), API-key auth, driven by TrackMuleBB.
- **Persistence:** single SQLite store (the `known.met` / `clients.met` /
  `server.met` / `preferences.dat` equivalent) — known files, peer credits,
  servers, categories, preferences, local identity/secure-ident, and the local
  Kad index.
- **Anti-abuse:** IP + user-hash ban store (4h TTL), IP filter (`ipfilter.dat`),
  upload-queue admission gates, Kad flood detection / rate limiting, packet
  validation, and the bad-peer diagnostic measures (duplicate-block rejection,
  repeat-request tracking, identity-change / file-request-flood bans, upload/
  download recycle and timeout measures).

## Permanent omissions (intentional, will not be added)

These are product decisions, not open gaps (20 registered entries). Each has a
full `stock_behavior` / `rust_behavior` / `reason` / `compatibility` record in
`policy/rust-client-omissions.toml` (id in parentheses).

- **Source Exchange v1** (`sx1-live-source-exchange`) — SX2-only; SX1 never sent,
  answered, or ingested (operator decision REF-002).
- **Peer chat / captcha** (`peer-chat-messaging`) — no `OP_MESSAGE`; captcha
  hello bit unadvertised. No REST surface for interactive chat.
- **Media preview** (`ed2k-preview`) — inbound preview opcodes decoded/logged,
  never answered; no frame extraction.
- **IPv6** (`ipv6-ed2k-kad`) — IPv4-only for eD2K, Kad, transfer, NAT, bootstrap.
- **Legacy HTML WebServer** (`legacy-html-webserver`) — REST `/api/v1` only.
- **Server UDP description poll** (`server-udp-description-poll`) — cosmetic
  server name/description refresh not sent (server metadata comes from
  server.met import + the connected-server ident).
- **Time-based scheduler** (`time-based-scheduler`) — delegated to the external
  controller over REST (every scheduled effect is a first-class REST operation).
- **Gentler network pacing** — sliding 5s connection-rate window
  (`conn-rate-rolling-five-second-window`), no spike modifier
  (`conn-rate-spike-modifier`), FIFO upload-bandwidth share instead of focus-slot
  (`upload-throttle-focus-slot-distribution`), scarcity-gated global source
  supplement (`source-supplement-scarcity-gate`), unconditional LAN flood
  exemption (`kad-flood-lan-exemption`), and demote-to-tail instead of
  cooldown-suppression for slow uploaders (`upload-slow-cooldown-suppression`).
  All strictly equal-or-gentler than stock, for the VPN'd headless no-ban posture.
- **Synchronous-serve model artifacts** — a cross-packet queued-duplicate block
  is rejected but may be labeled as a done-duplicate
  (`upload-duplicate-queued-intra-packet`); partial-file preview is not a headless
  action (`ed2k-partial-file-preview`). Wire-neutral.
- **Server obfuscation on non-config servers** — obfuscation ports/flags are
  honored for configured servers (kept from config on every restart) but not
  carried through the REST/state/SQLite server model
  (`server-obfuscation-metadata-non-config`), which stays at `/api/v1` contract
  parity without obfuscation fields.
- **Inert GUI preference knobs** — `pref-safe-server-connect`, `pref-new-auto-up`,
  `pref-new-auto-down`, `pref-download-auto-broadband-io` are round-tripped over
  REST for contract compatibility but drive no GUI-tuning behavior.

## Deferred (not omitted — parked for a later release)

Real future capability, intentionally out of `0.1.0-beta.1`:

- **A4AF full model** — A4AF-lite (cross-transfer source reuse + No-Needed-Parts
  swap) ships; the full eMule A4AF source-set/hijacking model is parked pending a
  better design. Downloads are independent per-transfer tasks (no shared
  scheduler) by design.
- **IPv6 dual-stack** — parked by decision; the cores stay IPv4-only for now.
- **Autonomous indexer + Torznab** (RUST-FEAT-002) and **Arr integration**
  (RUST-FEAT-004).
- **Docker/GHCR image** (RUST-FEAT-006) and **REST SSE push** (RUST-FEAT-007).
- **Parser fuzzing** — cargo-fuzz targets for the hand-rolled binary parsers.
- **Alternate UPnP-IGD NAT backend** — `nat/igd.rs` is a stub; the miniupnpc
  backend is the supported one.
- **Anti-abuse depth (defensive-measures plan)** — OP_OutOfPartReqs
  quarantine/cooldown escalation (Phase D), upload-admission cooldowns
  (failed-admit / no-socket / short-failed-slot; Phase E), and the
  download-queue-rank-flood ban (Phase C remainder). The base detectors
  (out-of-part-reqs, file-request-flood, identity-change bans) ship; the
  escalation state machines are parked in the defensive-measures roadmap. None
  blocker.
- **Kad/eD2K memory-safety & stat cosmetics** — self-imposed global Kad
  source/notes index ceilings (MFC has none), the network-size estimate using
  base firewalled constants instead of a live-ratio blend, and the 128-entry
  per-slot DoneBlocks history (MFC unbounded). Documented, effectively
  non-binding, no wire impact.

## Platform tier

- **Windows x64** — release-supported (the distributed artifact).
- **Linux** — runtime-proven (WSL2 Ubuntu) but not packaged in this release.
- **macOS** — compile/test-viable only (one behavioral FS-watcher test is skipped
  there; see `shared_dir_monitor_e2e.rs`).
