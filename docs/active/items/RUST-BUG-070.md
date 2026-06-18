---
id: RUST-BUG-070
title: Pace Kad source refreshes across retry attempts
status: in_progress
priority: Major
category: bug
workflow: local
---

# RUST-BUG-070: Pace Kad source refreshes across retry attempts

## Problem

The hide.me live-wire run
`EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T190522Z` showed
that `RUST-BUG-069` suppressed repeated direct endpoint redials, but active
downloads still restarted Kad source lookups for the same files every background
retry window. Five files produced 34 `ED2K source refresh starting` events in a
single pass; examples included:

- `06399c801aac2379f93ce6bd9049ca4d`: 9 refresh starts.
- `09a6d19d267a1d5f1cf2aeb0342f3755`: 8 refresh starts.
- `e4ba0be15f4e2bfea2062cae30fa7a56`: 8 refresh starts.

eMuleBB MFC stores Kad lookup pacing on the part file: `PartFile.cpp` only starts
a Kad file lookup when the download queue selects the file as due, and then sets
`m_LastSearchTimeKad = curTick + (KADEMLIAREASKTIME * m_TotalSearchesKad)`.
`KADEMLIAREASKTIME` is one hour and `m_TotalSearchesKad` increases up to seven.
Rust already paced connected-server and UDP-server source asks, but Kad source
supplementation still reset with each background retry task.

## Acceptance

- [x] Kad source refreshes are claimed per file across background retry attempts.
- [x] The first Kad refresh suppresses another Kad refresh for one hour.
- [x] Later Kad refreshes increase the due window up to the MFC seven-search cap.
- [x] Connected-server and UDP-server source pacing remain independent.
- [x] Cooldown-deferred direct sources wait for the retry driver instead of
      spinning no-op source refresh rounds.
- [x] Focused unit coverage proves same-file Kad refreshes are deferred while a
      different file can still claim a refresh.
- [ ] The next hide.me live-wire diagnostics run shows Kad source-refresh churn is
      suppressed versus
      `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T190522Z`.

## Implementation Notes

- Keep the Kad pacing in session memory, matching MFC's runtime part-file fields.
- This is source-discovery pacing only; it must not block remembered sources or
  direct source retries that are already due.

## Evidence

- `cargo test -p emulebb-core kad_source_refresh_uses_mfc_backoff_per_file --locked`
- `cargo test -p emulebb-core cooldown_deferred_direct_sources_wait_without_source_requery_spin --locked`
