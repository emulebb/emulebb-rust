---
id: RUST-REF-003
workflow: local
title: Full protocol-parity audit vs stock community eMule 0.72.0 and fingerprint fixes
status: DONE
priority: Major
category: refactor
labels: [parity, protocol, stealth, ed2k, kad, server]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: operator directive — emulebb-rust MUST be wire-indistinguishable from a stock community eMule client
---

# RUST-REF-003 — Wire-parity audit vs stock community eMule 0.72.0

## Summary

Deep, byte-level protocol audit of emulebb-rust against the **vanilla community
eMule 0.72.0** source (`analysis/community-0.72/srchybrid`) — NOT the eMuleBB fork,
which had itself diverged from stock in places. Four specialized sub-agents
compared the eD2K peer handshake, the eD2K server protocol, the eD2K
upload/download transfer protocol, and the Kad UDP protocol. Goal: rust must be
wire-indistinguishable from a stock client. Preceded by RUST-FIX-035 (the
CT_EMULE_MISCOPTIONS2 captcha bit, found against the fork).

## Fixes landed (each a granular commit, built + tested + clippy/fmt-clean)

- **F1** `aa01248` — hello + login CT_NAME serialized as stock `TAGTYPE_STRING`
  (WriteTagToFile), not the compact hybrid that no stock writer emits.
- **F5** `8f308f9` — OP_EMULEINFO version byte is the stock BCD `0x72` (not `0x48`).
- **F4** `80f280a` — OP_OFFERFILES FT_FILETYPE uses the stock ED2K search-IDs
  (audio=1…doc=5, archive→Pro), integer only on TYPETAGINTEGER servers else the
  string term, and no tag for an unknown (ANY) type.
- **F3** `bfe5ba0` — zlib-pack Kad datagrams over 200 bytes (OP_KADEMLIAPACKEDPROT
  0xE5); rust never packed (BOOTSTRAP_RES/RES/SEARCH_RES/PUBLISH).
- **C1** `81d4d4d` — OP_GLOBSEARCHREQ3 UDP-search-flags tag uses the compact
  WriteNewEd2kTag form (`89 0E 01`).
- **C3** `dbe88ae` — empty share advertises zero files (no fabricated sample .iso).
- **C5** `2e41125` — Kad obfuscation marker reserved-byte set matches stock
  (`{C5,D4,E4,E5,A3,B2}`: adds 0xB2, drops 0xE3).
- **C2** `3bd4feb` — advertise Kad TAG_SOURCEUPORT unconditionally (stock
  `!GetUseExternKadPort`), not gated on the UDP firewall verdict.
- **C4** `2be0ad6` — size-optimize OP_OFFERFILES FT_FILESIZE/HI (WriteNewEd2kTag
  down-sizing). Same commit records the C4 sub-item dispositions below.

## Kept by design (operator direction / verified stock-preserving)

- **F2 SX1** — MISCOPTIONS1 SourceExchange1Ver stays 0 (operator: eMuleBB-MFC
  disables it and it works fine).
- **B1 / B2** — upload compression exclusion list + download block-request pipeline
  depth match eMuleBB-MFC (operator direction).
- **C4 GETSOURCES hash-only** — deliberate rust unknown-size live-probe fallback;
  never triggers normally, and the stock shape would send a non-stock 0 size.
- **C4 crypt-suppress** — the obfuscated-login `&= 0x01` yields SUPPORT-only, which
  matches stock's default login crypt flags; removing it would diverge.

## Parked

- **C4 64-bit search clamp** — clamp a >4 GB search numeric constraint to u32 for
  non-64-bit servers; a very rare edge needing server-capability threading.

## Verification

Every fix: targeted + full `emulebb-ed2k`/`emulebb-kad-*`/`emulebb-core` tests,
clippy `-D warnings`, fmt. Full `tools/rust_quality_gate.py quick` green after the
series. Live wire confirmation is the converged soak (both clients now present
identical stock hellos; RUST-FEAT-034 VPN-guard verdict already validated live).
