# Three-way protocol parity matrix — stock vs emulebb-mfc vs emulebb-rust

Date: 2026-07-05. References: **STOCK** = community eMule 0.72.0
(`analysis/community-0.72/srchybrid`), **MFC** = emulebb-mfc fork
(`workspaces/workspace/app/emulebb-main/srchybrid`, 0.72.0), **RUST** =
`repos/emulebb-rust`. Method: 4 specialized sub-agents, one per protocol surface,
byte/bit-level. Companion to RUST-REF-003 (rust↔stock fixes).

## Headline

Stock ≡ MFC byte-for-byte on the wire almost everywhere; the fork's divergences
are mostly **off-wire**. Rust is a faithful wire port of both, is **cleaner than
MFC** on the fork's one big wire fingerprint (`CT_MOD_VERSION`), and follows MFC
only on operator-directed / MFC-behavioral deviations.

## MFC-vs-stock wire divergences, and where rust sits

| # | Divergence | STOCK | MFC | RUST = | Disposition |
|---|---|---|---|---|---|
| 1 | Hello `CT_MOD_VERSION` | none (6 tags) | `"eMuleBB 0.7.3"` always (7 tags) | STOCK | rust cleaner than MFC (mod tag off by default) |
| 2 | MISCOPTIONS1 SX1 nibble | 4 | 0 | MFC | operator F2 |
| 3 | Preview bit (MISC1 + ET_FEATURES) | 1 | 0 (ffmpeg-gated) | MFC | registered preview omission |
| 4 | Download block-request reserve | cap 9 | +512K→12, +1M→18 | MFC | operator B2 |
| 5 | Upload compression exclusion set | 8 exts | 49 exts (+ unconditional avi) | MFC | operator B1 |
| 6 | Login crypt-flag gating | per-prefs unconditional | suppress REQUEST/REQUIRE on obfuscated socket | MFC | RUST-REF-003 C4 (kept) |
| 7 | Offer-file selection/ordering | single-factor priority | multi-factor rank + republish | MFC | per-entry wire identical |

## MFC-vs-stock OFF-WIRE divergences (no packet change)

Kad flood-accounting bug fix (`PacketTracking.cpp` `==`→`!=`), malformed-count
hardening (`RequireSaneKadCount`), VPN startup bind guards, FastKad node-reachability
tracking, memory-safety (`unique_ptr`, `GetTickCount64`), diag hooks
(`ed2k_packet_v1` / `kad_udp`), and tuning constants (`MAX_SOURCES_FILE_SOFT
750→1000`, `UPLOAD_CLIENT_MAXDATARATE 25KB→8MB`, `CLIENTBANTIME 2h→4h`, etc.).

## Where rust lands (summary)

- **= STOCK (cleaner than MFC):** no `CT_MOD_VERSION`; all RUST-REF-003 fixes.
- **= both STOCK and MFC:** the vast majority — full hello structure + MISCOPTIONS2
  (incl. captcha) + version bytes; every transfer packet (REQUESTPARTS/_I64,
  fragmentation, queue-ranking, accept-upload, hashset, AICH); all Kad UDP
  (version 0x0a, HELLO tags/gating, >200-byte 0xE5 pack gate, bootstrap/req/res/
  search/publish, firewalled2/firewallUDP, obfuscation framing + reserved-marker
  set + key derivations); server login/offer/search structure.
- **= MFC (not stock):** only rows 1-7 above.

## Follow-up

- Verify rust's Kad flood tracker matches MFC's corrected per-opcode accounting
  (stock had a genuine `==` bug MFC fixed to `!=`) rather than stock's buggy
  behavior. Anti-abuse correctness, not a wire fingerprint.
- Cosmetic (rust-only, not an MFC divergence): rust hardcodes the login/hello
  nick to `"eMule"` rather than a configurable value; structure identical.
