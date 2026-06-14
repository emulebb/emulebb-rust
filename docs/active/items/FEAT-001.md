---
id: FEAT-001
workflow: local
title: eD2K — Implement client UDP source reask and queue-slot persistence
status: IN_PROGRESS
priority: Major
category: feature
labels: [ed2k, udp, downloads, parity]
milestone: phase-0
created: 2026-06-14
source: protocol-divergence audit (emulebb-rust vs emulebb-main vs p2p-overlord-agents)
---

# FEAT-001 - eD2K — Implement client UDP source reask and queue-slot persistence

## Summary

The eD2K client↔client UDP reask family (`OP_REASKFILEPING` 0x90, `OP_REASKACK`
0x91, `OP_FILENOTFOUND` 0x92, `OP_QUEUEFULL` 0x93, and the LowID variants
`OP_REASKCALLBACKUDP` 0x94 / `OP_DIRECTCALLBACKREQ` 0x95) is **not implemented**
in emulebb-rust. There is no client UDP socket and no reask dispatcher. Stock
eMule uses this family to keep a downloader's position in remote upload queues
for hours without holding a TCP socket per source. Without it, emulebb-rust loses
queue slots on TCP teardown and silently fails to answer reasks it advertises
support for. Full design: [`docs/design/udp-source-reask.md`](../../design/udp-source-reask.md).

## Current State

**Update 2026-06-14 — code-complete off by default.** The pure + state + loop
layers are implemented behind `enable_udp_reask` (off): codec/policy/registry/
state, the shared-Kad-UDP-port transport, uploader reciprocity, downloader detach,
and TCP-fallback re-engage (~64 tests, clippy-clean). The omission is recorded in
`policy/rust-client-omissions.toml` (`udp-source-reask-transport`). **Remaining:
live validation (Rust↔Rust, then gentle Rust↔stock) before flipping the flag on.**
The original pre-implementation audit below is retained as provenance.

- No client UDP socket exists; `crates/emulebb-ed2k/src/ed2k_tcp/` has no reask
  opcode handling. The gap is **inherited verbatim** from
  `p2p-overlord-agents` (`overlord-agent-emule`), from which the eD2K stack was
  copied — it was never implemented upstream.
- Queued sources use a **held-TCP** model
  (`crates/emulebb-ed2k/src/ed2k_tcp/download/session.rs`): the socket stays
  open while queued, reading `OP_QUEUERANK`/`OP_QUEUERANKING` inline under a
  `QUEUE_RANK_GRACE = 20s` deadline; on timeout or TCP drop the source is
  abandoned as `AcceptedButIncomplete`.
- The application retry loop (`crates/emulebb-core/src/lib.rs`,
  `*_direct_download*`) only reschedules sources when **all** sources are
  loopback (`retry_deadline = Some(now+360s)` gated on `is_loopback()`); for real
  swarm sources `retry_deadline = None`, so there is no periodic reask.
- The rust hello advertises `udp_version = 4` (`ed2k_tcp/hello.rs`), so peers may
  expect us to answer UDP reask that we currently ignore.

## Why This Matters

UDP reask is the backbone of eMule's queue economy. On a busy swarm, uploaders
reclaim idle TCP sockets, so a held-TCP queued model loses the slot as soon as
the connection drops — emulebb-rust cannot reliably climb long queues, which is
the normal way large/rare files are obtained. The reciprocal side is a parity
defect too: we advertise `udp_version = 4` but never answer inbound
`OP_REASKFILEPING`, forcing stock peers queued on us into needless TCP
reconnects.

## Representative Sites

- `crates/emulebb-ed2k/src/ed2k_tcp/download/session.rs` — held-TCP queued read,
  `QUEUE_RANK_GRACE`, `queued_until` (the model to bound and demote to fallback).
- `crates/emulebb-core/src/lib.rs` `*_direct_download*` — loopback-only retry
  loop (where per-transfer reask cadence belongs).
- `crates/emulebb-ed2k/src/ed2k_tcp/hello.rs` — advertised `udp_version`.
- `crates/emulebb-ed2k/src/ed2k_tcp/listener/session/upload_queue.rs` — upload
  queue state needed to answer inbound reasks.
- `crates/emulebb-ed2k/src/ed2k_server/obfuscation.rs`,
  `crates/emulebb-kad-net/src/obfuscation/` — UDP obfuscation primitives to
  reuse.
- Reference (stock): `emulebb-main/srchybrid/DownloadClient.cpp`
  (`UDPReaskForDownload`, `UDPReaskACK`, `UDPReaskFNF`),
  `ClientUDPSocket.cpp` (reask receive/answer), `opcodes.h`
  (`FILEREASKTIME` 29 min, `MIN_REQUESTTIME` 10 min, `UDPMAXQUEUETIME` 20 s).

## Intended Shape

Per the design doc: add one shared **client UDP transport** module
(`ed2k_client_udp/`) that owns the recv loop, de-obfuscates, dispatches the
`OP_EMULEPROT` reask opcodes, and fans replies back to the owning transfer/source
by `(peer_ip, peer_udp_port)` correlation under a `pending` anti-spoof gate. Each
download transfer drives its **own** reask ticker (no global scheduler — honours
the independent per-transfer-task download model); UDP-eligible queued sources
release their TCP socket and keep position by datagram, with TCP reconnect-reask
as the bounded fallback. Implement both downloader and uploader (reciprocity)
sides with exact stock framing (`udp_version`-gated partstatus/complete-count
tails) and stock obfuscation choice. Phase the LowID buddy reask
(`OP_REASKCALLBACKUDP`) and `OP_DIRECTCALLBACKREQ` separately.

## Scope Constraints

- **Out of RC2 scope** — capture and stage; do not build under the freeze.
- IPv4-only; reuse existing obfuscation primitives; new modules within the
  `policy/rust-client.toml` size budget; no big-refactor of legacy `.rs` files.
- Phase 1 = HighID UDP reask + TCP fallback + reciprocity. Phase 2 = LowID buddy
  reask + direct callback.
- Non-goal: A4AF cross-file source dedup (separate parked design); the two
  compose but neither requires the other.

## Acceptance Criteria

- [ ] **Phase 0:** omission recorded in `policy/rust-client-omissions.toml`
      (e.g. `udp-source-reask`) and advertised `udp_version` reconciled with
      actual support.
- [ ] Client UDP transport module bound to the local eD2K UDP port, with
      obfuscated + plaintext recv/send and opcode dispatch keyed on
      socket + protocol byte.
- [ ] Downloader sends `OP_REASKFILEPING` with stock-exact framing (hash16 +
      `udp_version`-gated partstatus + complete-count) only when UDP-eligible
      (peer UDP port + version, not firewalled, no live TCP, no proxy).
- [ ] Downloader handles `OP_REASKACK` (rank + optional partstatus),
      `OP_QUEUEFULL` (rank 0, stay), `OP_FILENOTFOUND` (drop source); unsolicited
      replies dropped by the `pending` gate.
- [ ] UDP-eligible queued sources release the TCP socket and retain queue
      position across TCP teardown via UDP reask on a `FILEREASKTIME`-based
      cadence (×2 NNP, `≥ MIN_REQUESTTIME`), with failure-ratio backoff to TCP.
- [ ] Non-UDP-eligible sources fall back to bounded TCP reconnect-reask.
- [ ] Uploader answers well-formed inbound `OP_REASKFILEPING` from known waiting
      clients with a correct queue position (silent/`OP_QUEUEFULL` per stock
      rules otherwise).
- [ ] Per-transfer reask cadence introduces **no** cross-transfer shared
      scheduler.

## Validation

- Unit: per-opcode encode/decode round-trips incl. `udp_version > 2`/`> 3`
  tails; pending-gate drop; backoff threshold; reask-interval math.
- Rust↔Rust: queued downloader releases TCP and keeps position purely via UDP
  reask across an accelerated cadence.
- Rust↔aMule / Rust↔eMuleBB short-path witness (gentle, widely-spaced,
  single-pass; confirm before any live-wire run per live-wire policy).
- packet_trace labels added for the new opcodes so the harness can assert the
  exchange.

## Notes

- Provenance: protocol-divergence audit across `emulebb-community-baseline`,
  `emulebb-main`, and emulebb-rust; gap confirmed identical in
  `p2p-overlord-agents`.
- Related design: [`docs/design/udp-source-reask.md`](../../design/udp-source-reask.md),
  [`docs/design/source-management-and-a4af.md`](../../design/source-management-and-a4af.md).
- Depends on nothing else; A4AF is independent.
