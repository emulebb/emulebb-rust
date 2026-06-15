# Source Management & A4AF — Design Sketch

**Status:** **PARKED** (operator decision 2026-06-15) · not strictly necessary ·
revisit only on observed real-network need · post-parity · **out of RC2 scope**
**Area:** ed2k download manager (`emulebb-ed2k`)
**Audience:** anyone implementing multi-file download source scheduling in emulebb-rust

---

## 0. Decision (2026-06-15): parked, revisit-on-observation

A4AF is **not strictly necessary** for the rust client and stays parked. It is an
**optimization, not correctness**: without it every download still works, just
less efficiently when many concurrent transfers share the same peers.

**2026 re-assessment (why parked, not built):**

- **The connection-cost rationale is obsolete.** A4AF's heaviest machinery —
  *hijacking a live TCP connection* from one transfer to another — existed because
  in ~2001 sockets/connections were scarce (slow CPUs, the Windows XP SP2
  half-open cap). In 2026 opening a connection is cheap, so the "full" A4AF
  (cross-task live-connection dirottamento, which is exactly the part that does
  not fit rust's independent per-transfer task model) buys little.
- **What still holds:** A4AF's real driver was never connection count — it is
  (1) the **structural one-relationship-per-peer** fact (eMule keeps one
  `CUpDownClient` per peer requesting one `m_reqfile`; the other wanted files sit
  in `m_OtherRequests_list`), (2) the **queue position** being expensive (earned
  in hours, bounded by the remote uploader's upload bandwidth — protocol economy,
  not hardware), and (3) **NNP** (a peer with no needed parts for X may have them
  for Y). On the **shrunken 2026 eD2K network** with scarce sources, squeezing
  each peer arguably matters *more*, not less.
- **The UDP source-reask we shipped** ([[udp-source-reask-foundation]], commit
  f60fc3c) already makes holding many queue positions cheap (one datagram / ~29
  min), which erodes one A4AF benefit but not the per-peer-relationship or NNP
  ones.

**If revisited, build the "lite" version only** (≈80% of the benefit, fits the
per-transfer model): registry-driven **source-selection bias** + **NNP swap** +
**cross-transfer peer dedup**, using the already-built read-only
`crates/emulebb-core/src/download_source_registry.rs` (peer→files index,
`a4af_candidate_count`, `lease_best_for_file`; has unit tests). **Do not** build
the live-connection hijacking (the obsolete socket-cost part). Two hook points
remain: (a) source selection at engagement, (b) NNP reaction in the download
driver.

**Revisit triggers (watch on the real network):** the rust client running
*dozens* of concurrent eD2K downloads (the operator's expected ceiling) and
observably (a) wasting scarce sources it could reuse, or (b) opening many
redundant simultaneous connections to the same overlapping peer, or (c)
mishandling NNP sources (dropping peers that have needed parts for another wanted
file). Until such behavior is observed, the lite scaffold stays dormant.

---

## 1. Background: what A4AF is in eMule/aMule

**A4AF = "Asked For Another File."**

A single remote client can be a source for several of the files in your
download queue at once — it happens to share more than one thing you want. But
a client can only usefully feed you **one** file at a time (one upload slot from
its side). For the *other* files that peer also has, eMule parks it in those
files' source lists and flags it **A4AF**.

In the eMule/eMuleBB code (`srchybrid/DownloadQueue.cpp`,
`srchybrid/ClientList.cpp`) this is implemented as:

- Each `PartFile` owns its source list **plus** a mirror `A4AFsrclist` of peers
  that are sources for this file but are currently committed to a different file.
- A peer is **active** for exactly one file and **A4AF** for the rest.
- `ProcessA4AFClients()` runs on a timer (every 8 minutes —
  `DownloadQueue.cpp:1355`) and **swaps** peers between files via
  `SwapToAnotherFile()`, weighing file priority, your queue rank on the peer,
  whether the active file already has enough sources, completion state, etc.

A4AF is **not** a wire-protocol feature — there is no A4AF packet. It is purely a
local download-queue scheduling concept, surfaced in the UI as the "A4AF" column
and the right-click "swap to this file" action.

### Why eMule's implementation is painful

Two design choices drive most of the complexity:

1. **Sources are owned by files.** A peer serving 3 files exists in 3 places
   (one source list + mirror entries). Every add / remove / complete must keep
   the mirrors in sync — hence the defensive `DebugLogWarning(... "stale A4AF
   ... pointer")` and `"mirror was already out of sync"` guards scattered
   through `RemoveSource`.
2. **Assignment is eager and polled.** Peers are bound to a file up front, so the
   system must periodically re-balance (`SwapToAnotherFile` every 8 min) to
   correct assignments that have gone stale.

emulebb-rust currently has **none** of this (no `A4AF`, `SwapToAnotherFile`, or
per-file source ownership). That is an opportunity: we can solve the same problem
without inheriting the structure that makes it fragile.

---

## 2. The problem, stated independently of eMule

Given a set of active downloads and a pool of discovered peers where any peer may
be a source for many of those files:

- **R1 — Dedup at the peer level.** Do not occupy multiple queue positions on the
  same peer for different files. It wastes our queue slots and some peers penalize
  it. One peer → one live queue/connection.
- **R2 — Spend each download opportunity on the most valuable file.** When a peer
  gives us a slot, download the highest-value file that peer can actually serve,
  by current file priority / need.
- **R3 — Stay correct as state changes.** Files complete, pause, or change
  priority; peer queue ranks improve. The chosen file must follow those changes.
- **R4 — No stale-state bug surface.** Avoid mirrored bookkeeping that can drift
  out of sync.
- **R5 — Parity-presentable.** We can still show users an "A4AF" view for
  familiarity / parity with the canonical client.

---

## 3. Proposed model: peer-keyed registry + lazy binding

### 3.1 Single source of truth, keyed by peer (not by file)

```text
SourceTable: PeerId -> SourceEntry {
    files:       HashSet<FileHash>,   // every file this peer can serve
    conn_state:  ConnState,           // disconnected | queued | connected | downloading
    queue_rank:  Option<u32>,         // our position in this peer's upload queue
    bound_file:  Option<FileHash>,    // file currently being downloaded, if any
    last_seen, identity, ...
}
```

A peer that serves files {A, B, C} is **one** entry. The per-file view ("who are
the sources for file A?") is a **derived query** over the table, not stored,
mirrored state:

```text
sources_for(file) = { peer | file ∈ peer.files }
```

This single change satisfies **R1** and **R4** outright: there is exactly one
record per peer, so there is nothing to keep in sync and no stale-mirror class of
bugs.

If we lean on the existing SQLite dependency (`libsqlite3-sys` is already in the
tree), this is a `sources(peer_id, file_hash)` table with a unique constraint;
dedup is the constraint and the "best file" query is an `ORDER BY`. An in-memory
`HashMap<PeerId, SourceEntry>` is equally valid — the **shape** is the point, not
the storage engine. Pick in-memory first; promote to SQLite only if persistence
across restarts is wanted.

### 3.2 Decide the target file lazily, at slot-grant time

eMule needs the periodic swap because it commits a peer to a file early and must
keep correcting that commitment. We invert it:

- Keep the peer in the registry as "source for {A, B, C}".
- Maintain its queue position / connection (R1) **without** committing it to a
  file.
- **Only when the peer actually grants us a download slot** (we reach the top of
  its upload queue) do we choose `bound_file` — the best file among
  `peer.files`, scored with *current* priorities/need (R2).

The expensive decision is made exactly once, when it matters, on fresh inputs.
There is no 8-minute sweep and no speculative assignment to undo.

### 3.3 Re-evaluate on events, not on a timer

The only things that change the "best file for this peer" answer are:

- a file completes or is paused/removed,
- a file's priority changes,
- a peer's queue rank materially improves (it's about to grant a slot).

Re-rank the affected peers on **those events**. This is strictly more responsive
than a coarse poll and does less total work (R3). A peer mid-download is normally
left alone until its current chunk/slot ends, to avoid thrashing — re-binding
applies at the next slot boundary.

### 3.4 Scoring (binding policy)

When binding a peer to a file, score candidate files in `peer.files` by, roughly:

1. file priority (user-set: Low…Release),
2. need — files starved of sources rank above well-supplied ones,
3. tie-breakers: closer to completion, fewer active sources, better queue rank.

Keep this a single pure function `pick_file(peer, &files_state) -> FileHash` so it
is unit-testable in isolation and the policy can be tuned without touching the
registry mechanics.

---

## 4. What we deliberately keep, and what we drop

**Keep — peer-level dedup (R1).** Do *not* simplify all the way to "open an
independent connection per (file, peer) and let the peer's queue sort it out."
That throws away the one thing A4AF genuinely buys and is exactly the wasteful
behavior peers penalize.

**Drop — file-centric ownership + the swap timer.** Sources are not owned by
files; there is no `A4AFsrclist` mirror and no `ProcessA4AFClients` periodic
re-balance. Binding is lazy and event-driven instead.

---

## 5. Protocol & parity caveats

- **The ed2k wire protocol is still per-file.** Sources are requested per file
  (`OP_REQUESTSOURCES`) and source-exchange is per file. So we *ingest* per file
  — each discovered (file, peer) pair — and fold it into the one peer-keyed
  registry (`peer.files.insert(file)`). No protocol divergence; only the local
  storage shape differs.
- **Observable behavior will differ from eMule.** Lazy binding produces equal or
  better download efficiency but different *timing* and different A4AF column
  counts than eMule's eager-swap cadence. If the goed2k↔Lugdunum parity loop ever
  asserts eMule-identical swap timing or A4AF counts, satisfy it by surfacing
  **A4AF as a derived read-only view** (peers that serve file X but are currently
  bound elsewhere), presenting the same information without storing it as owned
  state (R5). Do **not** re-introduce eager ownership just to match a column.

---

## 6. Scope & sequencing

- This is **out of RC2 scope** (RC2 is verification + release-blocking fixes
  only; emulebb-rust is explicitly out of ship scope). Capture, don't build yet.
- Precondition: the rust client reliably runs a **multi-file** download queue.
  A4AF is meaningless with a single download or non-overlapping sources, so build
  it once multiple concurrent downloads with overlapping peers actually exist.
- It is then a well-contained module: the `SourceTable` registry, the `pick_file`
  policy function, and an event hook set (file-complete / priority-change /
  slot-grant). No need to touch the large legacy-shaped `.rs` files; add it as new
  modules within the per-module size budget.

---

## 7. Summary

Solve the same problem eMule's A4AF solves — reuse a discovered peer across
overlapping downloads, spend each slot on the best file — but with a **single
peer-keyed registry** and **lazy, event-driven file binding** instead of
file-owned source lists and an 8-minute swap timer. Same-or-better efficiency,
far less bookkeeping, and the entire stale-mirror bug class designed out. Keep
peer-level dedup; surface "A4AF" only as a derived view for parity.
