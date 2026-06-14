# emulebb-rust Active Backlog — Issue Index

This directory is the active local backlog/spec layer for the **emulebb-rust**
headless client. It follows the eMuleBB backlog convention
([`BACKLOG-PROCESS`](../../../emulebb-tooling/docs/reference/BACKLOG-PROCESS.md),
[`BACKLOG-ITEM-TEMPLATE`](../../../emulebb-tooling/docs/reference/BACKLOG-ITEM-TEMPLATE.md)):
each item is `docs/active/items/<ID>.md` with the same front matter and section
vocabulary.

Unlike the canonical `emulebb/emulebb` backlog, emulebb-rust items are
**local-only** for now (`workflow: local`): there is no GitHub-primary mirror or
Project board yet, so these Markdown files are the authoritative spec. If/when an
emulebb-rust issue tracker is opened, migrate items to `workflow: github` per the
shared process.

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

Same classes as eMuleBB: `BUG`, `FEAT`, `REF`, `CI`. IDs are allocated per class
and never reused. Scan `docs/active/items` (and `docs/history/items` once it
exists) before allocating the next number.

## Features (`FEAT`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| [FEAT-001](items/FEAT-001.md) | Major | OPEN | eD2K — Implement client UDP source reask and queue-slot persistence |

## Bugs (`BUG`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| _none yet_ | | | |

## Refactors (`REF`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| _none yet_ | | | |

## CI / Tooling (`CI`)

| ID | Priority | Status | Title |
|----|----------|--------|-------|
| _none yet_ | | | |
