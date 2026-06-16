# Source Management & A4AF — Design Sketch

**Status:** **A4AF-lite IMPLEMENTED** (operator decision 2026-06-16) · the final
cross-transfer source-reuse capability-parity item · the obsolete
live-connection hijacking remains intentionally out of scope (see §0.1)
**Area:** ed2k download manager (`emulebb-ed2k` + `emulebb-core`)
**Audience:** anyone working on multi-file download source scheduling in emulebb-rust

---

## 0. Decision (2026-06-16): A4AF-lite built; live-connection hijacking excluded

A4AF-lite is **implemented**. It delivers ≈80% of eMule A4AF (the part that fits
rust's independent per-transfer task model) and drops only the obsolete
socket-scarcity-era machinery (live-connection hijacking, §0.1).

A4AF was always an **optimization, not correctness**: without it every download
still works, just less efficiently when many concurrent transfers share the same
peers. On the shrunken 2026 eD2K network with scarce sources, squeezing each peer
matters, so the lite version was built rather than left parked.

### 0.1 The two legs that were built

Both legs are driven by the shared, peer-keyed
`crates/emulebb-core/src/download_source_registry.rs` (peer→files index;
`lease_best_for_file`, `candidate_count_for_file`, `swap_target_for_peer`) and
the cross-transfer `download_coordinator.rs` — the same shared state the
per-transfer tasks already consult, so no monolithic queue loop was introduced.

1. **Source-selection bias + cross-transfer peer dedup**
   (`EmulebbCore::acquire_direct_download_source_leases`). When a transfer
   acquires sources, the registry leases each peer to **its single best file**
   (`lease_best_for_file`, scored by file priority then rare/needed parts) and
   `active_download_peer_endpoints` enforces **one active relationship per peer**
   — a peer registered for several of our files is engaged for exactly one at a
   time, the rest defer (no redundant simultaneous engagement, like eMule's one
   `CUpDownClient` per peer with the other files parked in `m_OtherRequests_list`).
   The per-file soft source cap (`can_engage_file_source`) bounds it further.

2. **NNP (No Needed Parts) swap**
   (`EmulebbCore::swap_no_needed_parts_sources`, master
   `CUpDownClient::SwapToAnotherFile`). When a connected source reports No Needed
   Parts for the current file (eMule `OP_OUTOFPARTREQS` / `DS_NONEEDEDPARTS`), the
   download session returns the new `Ed2kPeerDownloadOutcome::NoNeededParts`. The
   driver then asks the registry (`swap_target_for_peer`) for the **best other
   wanted (non-terminal) file the same peer serves** and re-drives that file's
   download attempt so leg-1 selection re-engages the peer there — **the source is
   moved to the other file instead of being dropped**. A source whose only
   registered file was the current one (no swap target) is **still dropped, as
   before**.

### 0.1.1 Excluded — live-connection hijacking (intentional scope boundary)

The one A4AF piece **deliberately not built** is *hijacking a live, already-open
TCP connection* from one transfer to another in place. That machinery existed
because in ~2001 sockets/connections were scarce (slow CPUs, the Windows XP SP2
half-open cap); in 2026 opening a connection is cheap, and it is exactly the part
that does not fit rust's independent per-transfer task model. A4AF-lite instead
operates at the **source-selection + reask/re-engage level**: the NNP swap
re-queues the target file's own attempt (which reuses the peer through the
registry) rather than steal the socket mid-flight. This is a **scope boundary**,
not an omission of A4AF — the capability (reuse a discovered peer across
overlapping downloads, spend each opportunity on the best file, never lose an NNP
source that serves another wanted file) is present.

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

emulebb-rust deliberately did **not** inherit this file-centric ownership (no
`A4AFsrclist` mirror, no eager per-file source ownership, no `ProcessA4AFClients`
8-minute sweep). A4AF-lite (§0) solves the same problem with the peer-keyed
registry + lazy binding described in §3, designing the fragile stale-mirror class
of bugs out.

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

## 6. Scope & sequencing (as built)

- **Built** as a well-contained slice: the peer-keyed `download_source_registry`
  (with `swap_target_for_peer` for the NNP swap) + the cross-transfer
  `download_coordinator`, consumed by the per-transfer driver in
  `emulebb-core/src/lib.rs` (`acquire_direct_download_source_leases` for leg 1,
  `swap_no_needed_parts_sources` for leg 2). The lazy "best file" decision is
  taken at lease/swap time on current priorities/need; there is no eager
  ownership and no 8-minute sweep.
- The NNP wire signal is the new `Ed2kPeerDownloadOutcome::NoNeededParts`
  (`OP_OUTOFPARTREQS`), carried up through `DirectDownloadOutcome`.
- Coverage: registry unit tests (`swap_target_for_peer` picks the best other
  file / returns `None` when the peer serves only the current file) plus
  `emulebb-core` integration tests (multi-file peer reused + not double-engaged;
  an NNP source swapped to another wanted file; an NNP source with no other
  wanted file dropped; a completed other file rejected as a swap target).

---

## 7. Summary

Solve the same problem eMule's A4AF solves — reuse a discovered peer across
overlapping downloads, spend each slot on the best file — but with a **single
peer-keyed registry** and **lazy, event-driven file binding** instead of
file-owned source lists and an 8-minute swap timer. Same-or-better efficiency,
far less bookkeeping, and the entire stale-mirror bug class designed out. Keep
peer-level dedup; surface "A4AF" only as a derived view for parity.
