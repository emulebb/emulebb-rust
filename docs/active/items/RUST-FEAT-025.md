---
id: RUST-FEAT-025
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: Anti-abuse - redo upload_duplicate_done_block_rejected (+ queued sibling) with conformant ledger semantics
status: OPEN
priority: Major
category: feature
labels: [ed2k, upload, anti-abuse, diagnostics, parity]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: FEAT-025 revert 045a781 (oracle non-conformance); defensive-measures wave RUST-FEAT-024..029; 0.1.0-beta.1 release program (2026-07-05)
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-025 - Redo `upload_duplicate_done_block_rejected` with conformant ledger semantics

## Summary

Re-implement the `upload_duplicate_done_block_rejected` bad-peer measure (reject
upload block requests for ranges already completed in the slot) so its
`bad_peer_event_v1` emission is conformant with the eMuleBB MFC oracle, and add
the sibling `upload_duplicate_queued_block_rejected` event for the
already-queued case. This is MFC's single highest-volume anti-abuse measure
(~33,782 firings/30 min in the overnight tally) and currently the largest
observed defensive gap after the first implementation was reverted.

## Why the first attempt was reverted (045a781)

The `4ff79d4` emitter carried only `{action, reason, startOffset, endOffset,
partIndex}`; the oracle event also carries `repeatCount` and `windowSeconds`,
so the rust⊇oracle body-key check in `diag_event_diff` failed. Root causes to
avoid this time:

1. **Ledger scope:** MFC counts **rejections** in a **process-global** ledger
   (`g_badPeerBehaviorLedger`, `UpdateBehaviorLedger` keyed
   `peerKey|block|fileHash|start|end`, window `MIN2MS(60)` -> 3600 s, 60 s
   cleanup sweep) that survives reconnects. A per-connection or per-request
   count skews `repeatCount`.
2. **Body shape:** the harness adapter sets `behavior` only for
   `repeat_block_request`/`repeat_file_request`; this event's body must **not**
   include a `behavior` key.

## Intended Shape

- Global rejection ledger in
  `crates/emulebb-ed2k/src/ed2k_transfer/diag_bad_peer.rs`: key
  `peer|file|start|end`, window `REPEAT_BLOCK_WINDOW_SECS` (3600), counts
  rejection events, pruned and bounded.
- Emitter body: `{action: "reject_block_request", reason: "Duplicate upload
  block request already completed in slot", repeatCount, windowSeconds: 3600,
  startOffset, endOffset, partIndex}` (partIndex = start / ED2K_PART_SIZE).
- Emit sites in
  `crates/emulebb-ed2k/src/ed2k_tcp/listener/session/upload_payload.rs`:
  duplicate-done only on the `(Granted, DuplicateDone)` plan arm; the
  intra-packet dedupe arm gets the sibling
  `upload_duplicate_queued_block_rejected` (reason "...already queued in
  slot") — MFC has both events (`UploadClient.cpp:752,771`) and the reverted
  code mislabeled the queued branch.
- Existing observe-only `repeat_block_request` emission stays untouched.

## Acceptance Criteria

- [ ] Ledger unit tests: first rejection => repeatCount 1, second => 2, window
      prune, bounded size.
- [ ] Listener test: request -> complete -> re-request asserts the drop and
      (with packet diagnostics enabled) a captured event body containing
      `repeatCount: 1, windowSeconds: 3600` and **no** `behavior` key.
- [ ] Offline oracle-conformance diff (`emulebb-build-tests` `diag_event_diff`)
      clean for both events — the exact check that caught the revert.
- [ ] Live converged-soak `repeatCount` alignment vs MFC observed during the
      release soak (RUST-FEAT-033 gate evidence).

## Notes

- Oracle references: `srchybrid/UploadClient.cpp:752` (done), `:771` (queued),
  `srchybrid/BadPeerDiagnosticsSeams.cpp:400-455`
  (`LogUploadBlockRequestBehavior` + `UpdateBehaviorLedger`).
- Adapter mapping: `emule_test_harness/mfc_diag_adapter.py` passes the event
  name through and maps `repeat_count/window_seconds/...` to camelCase.
