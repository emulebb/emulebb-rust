# emulebb-rust Active Backlog — Issue Index

This directory is the active local backlog/spec layer for the **emulebb-rust**
headless client. It follows the eMuleBB backlog convention
([`BACKLOG-PROCESS`](../../../emulebb-tooling/docs/reference/BACKLOG-PROCESS.md),
[`BACKLOG-ITEM-TEMPLATE`](../../../emulebb-tooling/docs/reference/BACKLOG-ITEM-TEMPLATE.md)):
each item is `docs/active/items/<ID>.md` with the same front matter and section
vocabulary.

Most active product items are **GitHub-tracked** (`workflow: github`): issues
live in `emulebb/emulebb-rust` and are aggregated on the org **eMuleBB Suite**
board (`https://github.com/orgs/emulebb/projects/3`, `Product = emulebb-rust`,
`Phase` field). GitHub owns workflow state (status, priority, placement); these
Markdown files own the durable engineering spec. Local-only backlog items record
internal evidence gates, CI debt, or closure decisions that do not need public
workflow state. Parked ideas stay out of the tracker entirely (see the roadmap's
Active vs Parked ledger).

## Current Snapshot

**Source of truth:** `EMULEBB_WORKSPACE_ROOT\repos\emulebb-rust` (`main` branch)
**Scope note:** emulebb-rust is **out of RC2 ship scope** (the MFC RC train).
Since 2026-07-05 the repo carries its **own release gate**: the
`rust-v0.1.0-beta.1` first-usable-release program tracked by
[RUST-FEAT-033](items/RUST-FEAT-033.md) (`milestone: release-0.1.0-beta.1`
groups its items).
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
reused. Scan both `docs/active/items` and `docs/history/items` before
allocating the next number.

## Phase 0 — "perfectly functional" gate

emulebb-rust is the strategic forward eD2K/Kad core (the eMuleBB MFC `0.7.x`
feature line closes at `0.7.3`; MFC then continues in the `0.8.x` modernization
line, while emulebb-rust remains the forward core). "Perfectly functional" =
client parity **plus** the indexer role, per
`emulebb-tooling/docs/active/SUITE-JOINT-ROADMAP.md`. The FEAT items below are the
Phase 0 scope. Cooperative-DHT / BEP-46 publishing and similar ideas are **parked**
(see the roadmap's Active vs Parked ledger) and are intentionally **not** backlog
items.

## Core MFC Parity Closure

Core MFC parity closure is narrower than full Phase 0. It covers core client
behavior, REST contract parity, deterministic local cross-client interop, and an
optional public hide.me smoke witness. It does not close the Phase 0 indexer,
Arr/Torznab, Docker, SSE, or automated tunnel-down leak-test work. The closure
gate and test-rationalization plan are tracked by
[RUST-CI-002](items/RUST-CI-002.md).

## Active Backlog

Only **in-progress / open** items live in `items/`. Items move to
[`../history/items/`](../history/items/) when they reach `DONE`, so these tables
stay active-only; see [Closed Items](#closed-items-archive) for the archive.

### Features (`FEAT`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-FEAT-001](items/RUST-FEAT-001.md) | Major | IN_PROGRESS | eD2K — Implement client UDP source reask and queue-slot persistence |
| [RUST-FEAT-002](items/RUST-FEAT-002.md) | Major | OPEN | Indexer — autonomous Kad/eD2K snooping index with Torznab surface |
| [RUST-FEAT-004](items/RUST-FEAT-004.md) | Major | OPEN | Arr integration — Torznab indexer + qBittorrent-emulating download client |
| [RUST-FEAT-005](items/RUST-FEAT-005.md) | Critical | OPEN | Automated VPN leak-test — assert no data egress off the tunnel (release-blocking) |
| [RUST-FEAT-006](items/RUST-FEAT-006.md) | Major | OPEN | Docker — publish a linuxserver-style GHCR image (suite bundle prerequisite) |
| [RUST-FEAT-007](items/RUST-FEAT-007.md) | Minor | OPEN | REST push — SSE stream for live transfer updates (+ transfers.sse capability) |
| [RUST-FEAT-025](items/RUST-FEAT-025.md) | Major | OPEN | Anti-abuse — redo upload_duplicate_done_block_rejected (+ queued sibling) with conformant ledger semantics |
| [RUST-FEAT-030](items/RUST-FEAT-030.md) | Minor | OPEN | Kad — implement KADEMLIA_FIND_VALUE_MORE re-ask in lookup traversal |
| [RUST-FEAT-031](items/RUST-FEAT-031.md) | Minor | OPEN | Kad — handle inbound legacy KADEMLIA_FIREWALLED_ACK_RES (0x59) |
| [RUST-FEAT-032](items/RUST-FEAT-032.md) | Minor | OPEN | Kad — routing-zone consolidation (merge sparse sibling leaf bins on the 45-minute timer) |
| [RUST-FEAT-033](items/RUST-FEAT-033.md) | Critical | OPEN | Release — first usable release rust-v0.1.0-beta.1 (scope doc, GH release workflow, soak-gated tag) |

### Refactors / Evidence (`REF`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-REF-002](items/RUST-REF-002.md) | Major | OPEN | Parity sweep for the 0.1.0-beta.1 release — enumerate and disposition every unregistered divergence |

### Bugs (`BUG`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-BUG-001](items/RUST-BUG-001.md) | Minor | IN_PROGRESS | kad_swarm multi-node transfer tests are isolated in CI |

### CI / Tooling (`CI`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [RUST-CI-002](items/RUST-CI-002.md) | Major | OPEN | Rationalize and close the core MFC parity evidence gate |
| [RUST-CI-003](items/RUST-CI-003.md) | Minor | OPEN | Wire the /api/v1 OpenAPI conformance/drift check into CI |

## Closed Items (archive)

Closed items keep their full engineering record under
[`../history/items/`](../history/items/). As of 2026-06-26 the archive holds the
DONE set: `RUST-FEAT-003`, `RUST-REF-001`, `RUST-CI-001`, and the
`RUST-BUG-002`…`RUST-BUG-099` parity wave. Browse that directory for the
per-item detail; this index intentionally does not re-list closed items.
