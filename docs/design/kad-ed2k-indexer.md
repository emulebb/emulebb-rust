# Design: Autonomous Kad/eD2K indexer (notes 13–15)

Status: design / direction. Captured 2026-06-14. Post-0.7.3; full development
mode. This is **inside deliverable #1** — "perfectly functional" means client
parity **plus** this indexer role (per the suite joint roadmap in
`emulebb-tooling/docs/active/SUITE-JOINT-ROADMAP.md`). It is the eD2K/Kad mirror
of the qBittorrentBB DHT harvester.

## Goal

Make `emulebb-rust` not just a client but a **self-driving index of the Kad + eD2K
networks**: a searchable local SQLite index of `{ed2k_hash, filename, size,
keyword(s), source_count, first_seen_ms, last_seen_ms}` with FTS, surfaced via
Torznab and a qBittorrent-emulating download-client API.

## Why Kad indexing is structurally cheaper than BT DHT harvesting

Kad differs from the BitTorrent mainline DHT in a way that matters:

- **Kad natively stores metadata.** A Kad keyword search returns filenames +
  sizes + ed2k hashes **from the DHT itself** (keyword→file mappings and file
  metadata are published into Kad). There is **no separate metadata-fetch step**
  like BitTorrent's BEP-9. Snooping Kad is harvesting a distributed search engine,
  so coverage is search-ready immediately.
- **Two key spaces:** keyword hashes (keyword→file) and file hashes
  (file→source). Indexing reads both.

## Surfaces to harvest

1. **Kad (serverless, the backbone).** `KADEMLIA_SEARCH` on keyword hashes → file
   results; on file hashes → sources. Plus the publish/search traffic the node
   routes.
2. **eD2K servers (bonus, never a dependency).** When connected, fold `OP_SEARCH`
   + `OP_GETSOURCES` results into the same index. Per the north star, servers
   enrich but the index never depends on them.

## Architecture (most-efficient: passive-first)

The bulk of the index comes from traffic the node already routes as a
participating Kad node — free and unlimited. Active querying is a deliberately
gentle, compliant supplement.

1. **Passive snoop layer (primary, free).** Index every keyword-publish,
   source-publish, and routed search/result that passes through the node. Hook the
   Kad RPC receive path (the same `emulebb-kad-net` receive loop the UDP
   source-reask foundation hooks; see `docs/design/udp-source-reask.md`). Zero
   extra queries, zero ban risk.
2. **Replay layer (cheap, active).** Maintain a frequency-ranked table of observed
   keywords; periodically re-search the top-N to deepen result/source sets. Self-
   priming — the network tells you what to search.
3. **Dictionary-sweep layer (active, rate-limited).** A curated common-keyword +
   file-extension dictionary (`avi`, `mkv`, `mp3`, `flac`, `iso`, `pdf`, `epub`,
   `zip`, …) swept slowly to enumerate the popular keyspace the passive layer has
   not seen. Common extensions are high-yield keyword hashes.
4. **Opportunistic source capture only.** No dedicated source-deepening sweep.
   Record source/availability when it arrives for free — you happen to search a
   file, observe a source-publish, or route a source query. Keeps the active
   budget for content coverage.

### Rate discipline (hard constraint)

Active layers (2–4) run under the gentle-live-wire discipline: widely-spaced,
single-pass, rate-limited, protocol-compliant. eD2K servers ban aggressive
searching and Kad has flood protection. **Passive-first plus gentle active** is
the efficiency strategy *and* the ban-avoidance strategy. No aggressive
enumeration.

## Storage

- **SQLite only** (no on-disk metadata-file mirror — the BT side persists
  `.torrent` files because the autotorrent-style reconciliation needs them; the
  eD2K index has no equivalent driver, so the DB is sufficient).
- Conventions mirror the qBittorrentBB harvester and `emulebb-metadata/schema.sql`:
  WAL, `foreign_keys`, NFKC normalization, `first_seen_ms`/`last_seen_ms`,
  schema-version reset, **FTS5** for keyword search.
- **Indexer schema parity with qBittorrentBB is a living goal, not a frozen
  schema** — both co-evolve; columns are negotiated per-field as we build. The
  identity column differs (eD2K: `ed2k_hash`; BT: `infohash`) but the surrounding
  columns (name, size, seen timestamps, source/swarm count, FTS) stay identically
  named and typed so tooling treats both uniformly.

## Arr / controller surfaces (note 15)

- **Native `/api/v1` REST** — rust keeps its own eMuleBB-compliant REST layer as
  the native control + search surface.
- **Torznab endpoint** — serves the Kad/eD2K index to Prowlarr/Sonarr/Radarr,
  same dialect + caps + apikey scheme + "everything category 8000/Other" decision
  as qBittorrentBB, so a Prowlarr operator cannot structurally tell them apart.
  Ship a suite Prowlarr indexer definition (YAML) for both.
  - **Known limitation:** all-8000/Other means no content categorization, which
    Sonarr/Radarr use to filter and route grabs — automatic-grab quality is
    weaker than a categorized feed. This matches current qBittorrentBB behavior
    and is a conscious choice for now; revisit if note-16/17 automation needs
    category-aware routing.
- **qBittorrent-WebUI-emulating download-client API** — so the Arr stack and
  `amutorrent` drive rust as if it were a qBittorrent, with zero new integration.
  This reuses the pattern eMuleBB already proved with its `/api/v2` compat layer
  (`WebServerQBitCompat`) — copy it, do not reinvent.
- **Grabs route directly to the client** (standard Arr flow). `amutorrent` is an
  optional automation layer on top, not a required hop.

## Placement / constraints

- New module(s) hooking `emulebb-kad-net`'s receive loop (passive snoop) and
  driving searches through the existing Kad/eD2K search paths.
- Respect the rust file-size policy: new modules ≤600 lines; no big-refactor of
  legacy `.rs`. Splits are post-parity, as-touched.
- Builds under the output root only.
