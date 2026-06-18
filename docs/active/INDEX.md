# emulebb-rust Active Backlog — Issue Index

This directory is the active local backlog/spec layer for the **emulebb-rust**
headless client. It follows the eMuleBB backlog convention
([`BACKLOG-PROCESS`](../../../emulebb-tooling/docs/reference/BACKLOG-PROCESS.md),
[`BACKLOG-ITEM-TEMPLATE`](../../../emulebb-tooling/docs/reference/BACKLOG-ITEM-TEMPLATE.md)):
each item is `docs/active/items/<ID>.md` with the same front matter and section
vocabulary.

Active items are **GitHub-tracked** (`workflow: github`): issues live in
`emulebb/emulebb-rust` and are aggregated on the org **eMuleBB Suite** board
(`https://github.com/orgs/emulebb/projects/3`, `Product = emulebb-rust`,
`Phase` field). GitHub owns workflow state (status, priority, placement); these
Markdown files own the durable engineering spec. Parked ideas stay out of the
tracker entirely (see the roadmap's Active vs Parked ledger).

## Current Snapshot

**Source of truth:** `EMULEBB_WORKSPACE_ROOT\repos\emulebb-rust` (`main` branch)
**Scope note:** emulebb-rust is **out of RC2 ship scope** — the backlog captures
parity and design work to stage, not release-blocking gates. RC2 is verification
+ release-blocking fixes only.
**Protocol policy:** IPv4-only, stock-compatible for implemented eD2K/Kad
behaviour; intentional omissions are recorded in
[`policy/rust-client-omissions.toml`](../../policy/rust-client-omissions.toml).
**Design sketches:** [`docs/design/`](../design/).
**Backlog process runbook:**
[`BACKLOG-PROCESS`](../../../emulebb-tooling/docs/reference/BACKLOG-PROCESS.md)

## ID Taxonomy

Item IDs carry a **product prefix** so they never collide across the suite repos:
emulebb-rust uses `RUST-<CLASS>-<NNN>` with classes `BUG`, `FEAT`, `REF`, `CI`
(e.g. `RUST-FEAT-002`). Other products use `QBBB-`, `GOED2K-`, `AMUT-`; the frozen
MFC app keeps its legacy unprefixed IDs. IDs are allocated per class and never
reused. Scan `docs/active/items` (and `docs/history/items` once it exists) before
allocating the next number.

## Phase 0 — "perfectly functional" gate

emulebb-rust is the strategic forward eD2K/Kad core (eMuleBB MFC is frozen at
`0.7.3`). "Perfectly functional" = client parity **plus** the indexer role, per
`emulebb-tooling/docs/active/SUITE-JOINT-ROADMAP.md`. The FEAT items below are the
Phase 0 scope. Cooperative-DHT / BEP-46 publishing and similar ideas are **parked**
(see the roadmap's Active vs Parked ledger) and are intentionally **not** backlog
items.

## Features (`FEAT`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-FEAT-001](items/RUST-FEAT-001.md) | Major | IN_PROGRESS | eD2K — Implement client UDP source reask and queue-slot persistence |
| [RUST-FEAT-002](items/RUST-FEAT-002.md) | Major | OPEN | Indexer — autonomous Kad/eD2K snooping index with Torznab surface |
| [RUST-FEAT-003](items/RUST-FEAT-003.md) | Major | IN_PROGRESS | VPN — pin eD2K TCP egress to the tunnel interface (fail-closed) |
| [RUST-FEAT-004](items/RUST-FEAT-004.md) | Major | OPEN | Arr integration — Torznab indexer + qBittorrent-emulating download client |
| [RUST-FEAT-005](items/RUST-FEAT-005.md) | Critical | OPEN | Automated VPN leak-test — assert no data egress off the tunnel (release-blocking) |
| [RUST-FEAT-006](items/RUST-FEAT-006.md) | Major | OPEN | Docker — publish a linuxserver-style GHCR image (suite bundle prerequisite) |
| [RUST-FEAT-007](items/RUST-FEAT-007.md) | Minor | OPEN | REST push — SSE stream for live transfer updates (+ transfers.sse capability) |

## Bugs (`BUG`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-BUG-001](items/RUST-BUG-001.md) | Minor | IN_PROGRESS | kad_swarm multi-node transfer tests are isolated in CI |
| [RUST-BUG-051](items/RUST-BUG-051.md) | Major | DONE | Route public searches through the selected ED2K or Kad network |
| [RUST-BUG-052](items/RUST-BUG-052.md) | Major | DONE | Persist transfer category assignments across restart |
| [RUST-BUG-053](items/RUST-BUG-053.md) | Major | DONE | Reindex transfer categories after category deletion |
| [RUST-BUG-054](items/RUST-BUG-054.md) | Major | DONE | Delay server endpoint advertisement until ED2K login is accepted |
| [RUST-BUG-055](items/RUST-BUG-055.md) | Major | DONE | Match MFC obfuscated server login for metadata-poor ED2K servers |
| [RUST-BUG-056](items/RUST-BUG-056.md) | Major | DONE | Ignore malformed ED2K UDP global-search replies |
| [RUST-BUG-057](items/RUST-BUG-057.md) | Major | DONE | Match MFC connected-server keyword search timeout |
| [RUST-BUG-058](items/RUST-BUG-058.md) | Major | DONE | Decode ED2K UDP search-result entries without TCP count prefix |
| [RUST-BUG-059](items/RUST-BUG-059.md) | Major | DONE | Collect multiple ED2K UDP keyword replies per server |
| [RUST-BUG-060](items/RUST-BUG-060.md) | Major | DONE | Accept ED2K UDP search replies from any requested server |
| [RUST-BUG-061](items/RUST-BUG-061.md) | Major | DONE | Supplement scarce connected-server sources with global UDP source search |
| [RUST-BUG-062](items/RUST-BUG-062.md) | Major | DONE | Batch ED2K global UDP source requests like MFC |

## Refactors (`REF`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-CI-001](items/RUST-CI-001.md) | Major | DONE | Capture ED2K global UDP packets in diagnostics |

## CI / Tooling (`CI`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| _none yet_ | | | |
