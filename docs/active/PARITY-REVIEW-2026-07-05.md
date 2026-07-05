# emulebb-rust ⇄ eMuleBB MFC — Full Parity Review (2026-07-05)

RUST-REF-002 evidence. A three-lane read-only audit of the Rust client against
the MFC oracle (`workspaces/workspace/app/emulebb-main/srchybrid`), scoped to
find **unregistered** divergences — the 15 registered omissions in
`policy/rust-client-omissions.toml` (mirrored in the `[review_reporting]`
excluded list) are suppressed. This is the pre-live-test parity baseline.

## Verdict

The Rust client is an **oracle-faithful port at wire parity** across Kad, the
eD2K client-to-client transfer protocol, the eD2K server protocol, the `/api/v1`
REST contract, and SQLite persistence. **No blocker-class divergence.**
FEAT-025 (duplicate-done/queued block rejection) was verified line-by-line
conformant with the oracle ledger. Thirteen unregistered divergences were found;
**two warrant a code fix**, the rest are register-as-omission or defer.

## Parity matrix (by lane)

Only the **not-AT-PARITY** rows are listed; everything else in each lane was
confirmed at parity (full per-subsystem tables are in the review transcripts).

| Lane | Behavior | Status | Disposition |
|---|---|---|---|
| Kad | KADEMLIA2_REQ→RES returns unverified contacts (missing `IsIpVerified()` filter) | PARTIAL | **FIX** (P-1) |
| Kad | Inbound flood tracker LAN exemption is unconditional (MFC: LAN-mode only) | PARTIAL | REGISTER (P-4) |
| Kad | Self-imposed global source/notes index ceilings (MFC has none) | DIVERGENT | DEFER (P-6) |
| Kad | Network-size estimate uses base firewalled constants, not live ratio | PARTIAL | DEFER (P-6) |
| eD2K | Slow-upload cooldown suppression not enforced (promote/recycle thrash) | PARTIAL | REGISTER (P-4) |
| eD2K | Duplicate-queued rejection is intra-packet only (synchronous-serve model) | PARTIAL | REGISTER (P-4) |
| eD2K | DoneBlocks history bounded to 128 vs MFC unbounded set | DIVERGENT | DEFER (P-6) |
| eD2K | OP_OutOfPartReqs quarantine escalation missing | MISSING | DEFER → defensive Phase D (P-5) |
| eD2K | Upload-admission cooldowns missing | MISSING | DEFER → defensive Phase E (P-5) |
| eD2K | download_queue_rank_flood ban missing | MISSING | DEFER → defensive Phase C-rem (P-5) |
| Server | OP_SERVERLIST auto-add not gated by an "add-servers-from-server" pref | PARTIAL | FIX comment + REGISTER (P-2) |
| Server | Server obfuscation ports/flags not persisted across restart | PARTIAL | REGISTER (P-4, re-dispositioned) |
| REST | `/transfers/{hash}/operations/preview` has no partial-file semantics | PARTIAL | REGISTER (P-4) |

Registered intentional omissions (15) and the reserved-but-unwritten forward
SQLite tables were excluded per scope and are not gaps.

## Execution status (2026-07-05)

All items landed on `main`, gate green. P-1 Kad fix (`e473a52`), P-2 OP_SERVERLIST
preference (`5778c10`), P-4 registrations (5 new omissions incl. the
re-dispositioned obfuscation item), P-5/P-6 defers recorded in
`docs/RELEASE-SCOPE.md`. RUST-REF-002 closed; parity baseline validated → cleared
for the Phase-4 converged soak.

## The fixes (P-1 / P-2)

1. **Kad — filter unverified contacts out of `KADEMLIA2_RES`.** MFC
   `CRoutingBin::GetClosestTo` gates on `GetType() <= uMaxType && IsIpVerified()`
   (`RoutingBin.cpp:242`); the REQ responder uses it (`KademliaUDPListener.cpp:738`).
   Rust `get_closest_max_type` filters only `oracle_type() <= max_type` with no
   `verified` check (`crates/emulebb-kad-routing/src/zone.rs:190-195`,
   `table.rs:161-172`, dispatch `crates/emulebb-core/src/lib.rs:6485`). The
   `Contact.verified` flag already exists (set on handshake / legacy challenge),
   so the fix is to add the `verified` predicate to the REQ/RES path **only**
   (`get_closest` / bootstrap must stay unfiltered to match
   `GetBootstrapContacts`). Anti-poisoning hygiene; wire-visible. Functional.

2. ~~**Server — persist server obfuscation ports/flags across restart.**~~
   **RE-DISPOSITIONED to REGISTER (2026-07-05).** On implementation the fix
   proved larger and worse than the review scoped: obfuscation is dropped one
   layer earlier than the audit saw — at the `ServerInfo` REST/state DTO
   (`crates/emulebb-core/src/rest_model.rs:153`), which Lane C confirmed is at
   `/api/v1` contract parity **without** obfuscation fields. The server.met
   parser does not extract obfuscation tags and OP_SERVERLIST carries only
   `(ip, port)`, so no non-config path supplies obfuscation data; persisting the
   vestigial columns would store zeros, and adding obfuscation to `ServerInfo`
   would regress the documented REST server schema. Configured servers (the
   soak-critical path) keep obfuscation from config on every restart. Registered
   as `server-obfuscation-metadata-non-config`.

## Register-as-omission (P-4)

Add registry entries + `[review_reporting]` ids for these deliberate, wire-
neutral-or-gentler divergences so they stop surfacing in future audits:
- **kad-flood-lan-exemption** — LAN IPs are always flood-exempt (be-gentle; a
  public VPN'd node rarely sees LAN Kad peers).
- **upload-slow-cooldown-suppression** — recycled slow uploaders are demoted to
  the queue tail without a cooldown-until/score-suppression term (local slot
  policy; no wire impact; simpler than eMule's broadband cooldown-probe).
- **upload-duplicate-queued-intra-packet** — the queued-duplicate ledger is
  per-request-batch (synchronous serve model); cross-packet queued duplicates
  collapse into the done-block reject path — anti-abuse coverage preserved, event
  label can differ.
- **ed2k-partial-file-preview** — `operations/preview` returns the transfer view
  only; no incomplete-file preview action (GUI concept, headless-inapplicable).

## Fix + register (P-2)

- **OP_SERVERLIST auto-add.** The handler comment claims a
  `GetAddServersFromServer()` gate that does not exist
  (`crates/emulebb-ed2k/src/ed2k_server/packet_handler.rs:156-161`); the merge is
  unconditional (`crates/emulebb-core/src/lib.rs:1291-1337`). eMule defaults the
  pref ON, so default behavior matches. Fix the misleading comment; register the
  always-on behavior as an omission (or, optional, add the pref + gate).

## Defer (P-5 / P-6)

- **P-5 (defensive-measures plan):** OP_OutOfPartReqs quarantine escalation
  (Phase D), upload-admission cooldowns (Phase E), download_queue_rank_flood ban
  (Phase C-remainder). Already governed by
  [[emulebb-rust-defensive-measures-plan]]; record the parking there, not as
  release surprises. Functional anti-abuse depth, none blocker.
- **P-6 (memory-safety / stat cosmetics):** self-imposed Kad index ceilings,
  network-size estimate constants, the 128-entry DoneBlocks bound. Documented,
  effectively non-binding, no wire impact. Note in the deferred list.

## Execution plan — full parity validation before live tests

Sequenced; each step lands on `main` with the gate green.

1. **P-1 fixes (2)** — Kad `IsIpVerified` filter + server obfuscation persistence,
   each with a unit test (Kad: REQ/RES omits an unverified contact but bootstrap
   still returns it; server: obfuscation ports survive an upsert→reload round
   trip). One coherent commit each.
2. **P-2** — correct the OP_SERVERLIST comment; register the always-on behavior.
3. **P-4** — add the four register-as-omission entries to
   `rust-client-omissions.toml` + the `[review_reporting]` excluded list; extend
   `RELEASE-SCOPE.md` (permanent-omissions section) to match. Policy checker keeps
   them consistent.
4. **P-5 / P-6** — record the deferred anti-abuse items against the defensive-
   measures plan and add the memory-safety/stat cosmetics to the RELEASE-SCOPE
   deferred list with the parking rationale.
5. **Re-green the gate** — `rust_quality_gate.py ci-test` + `quick`; confirm
   **zero undispositioned findings**. Update RUST-REF-002 to DONE with this
   review as the evidence record.
6. **Gate to live tests** — only once every row above is fixed/registered/deferred
   is the parity baseline validated; then proceed to the Phase-4 converged soak
   (live `diag_event_diff` for the FEAT-025 `repeatCount` alignment, witness of
   UDP-reask/buddy/firewall-check, and the operator VPN-pull pktmon evidence).

## Provenance

Three parallel general-purpose review agents (Kad; eD2K transfer+protocol;
server+REST+persistence), each citing rust file:line and MFC file:line evidence.
No files were modified during the audit.
