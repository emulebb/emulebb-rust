---
id: RUST-BUG-071
title: Wait until direct source retry cooldown before reattempting
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-071: Wait until direct source retry cooldown before reattempting

## Problem

The hide.me live-wire run
`EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T194623Z` proved that
`RUST-BUG-070` eliminated network source-refresh churn, but the active download
driver still woke every background retry window for cooldown-deferred remembered
direct sources. The run logged 214
`reason=direct_sources_deferred` no-op loops, including two files that woke
roughly every five seconds until the test ended.

eMuleBB MFC only calls `AskForDownload()` for direct source states such as
`DS_CONNECTING`, `DS_TOOMANYCONNS`, `DS_NONE`, and callback waits when
`curTick >= cur_src->GetLastTriedToConnectTime() + MIN2MS(20)`. Rust already
kept the endpoint from redialing before that window, but it returned to the
outer five-second retry loop instead of waiting until the endpoint was due.

## Acceptance

- [x] A cooldown-deferred direct source reports the earliest endpoint retry due
      delay to the active attempt driver.
- [x] When no direct source is currently acquirable but at least one remembered
      direct source is cooldown-deferred, the attempt waits until the earliest
      retry due time instead of requeueing through the five-second retry task.
- [x] Pause, delete, stop, and shutdown cancellation still stop the wait.
- [x] A4AF/active-lease deferrals that are not endpoint cooldowns still do not
      masquerade as retry due waits.
- [x] Focused unit coverage proves direct-source acquisition exposes endpoint
      cooldown delay.
- [x] The next hide.me live-wire diagnostics run shows the previous five-second
      `direct_sources_deferred` spin is gone.

## Implementation Notes

- Keep retry timing in memory alongside the existing per-endpoint attempt
  timestamps; this matches MFC runtime source state.
- This is a scheduler fix only. It must not change direct packet shape, source
  discovery queries, or source selection order beyond waiting for the existing
  retry gate.

## Evidence

- `cargo test -p emulebb-core released_endpoint_stays_cooldown_deferred_until_retry_window_expires --locked`
- `cargo test -p emulebb-core direct_download_source_leases_defer_peer_to_better_file_candidate --locked`
- `cargo test -p emulebb-core disconnect_releases_detached_reask_source_leases_and_re_engages --locked`
- `cargo test -p emulebb-core a4af_multi_file_peer_is_reused_and_not_double_engaged --locked`
- `cargo test -p emulebb-core cooldown_deferred_direct_sources_wait_without_source_requery_spin --locked`
- `cargo test -p emulebb-core kad_source_refresh_uses_mfc_backoff_per_file --locked`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T201148Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T201235Z\report.json`:
  VPN-bound HighID run captured packet diagnostics (3735 diagnostic records,
  275 ED2K packet records, 3599 Kad UDP packet records). It did not complete a
  file within the 600-second download window, but the old five-second no-op loop
  was gone: `reason=direct_sources_deferred` dropped from 214 in
  `rust-hideme-20260618T194623Z` to 0, with 4 new
  `ED2K direct source retry deferred` waits carrying retry delays from 1184985
  to 1194868 ms.
- Longer hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T202723Z\report.json`:
  VPN-bound HighID run captured packet diagnostics (3611 diagnostic records,
  329 ED2K packet records, 3318 Kad UDP packet records) and stayed Kad-connected
  with 119 contacts. It did not complete a file within the 1500-second download
  window, but it proved the MFC-style retry boundary: direct attempts resumed
  around 20 minutes after the first attempts, then deferred again with
  1169973-1194864 ms delays. The old `reason=direct_sources_deferred` loop
  remained 0.

## Residual Follow-Up

The two post-fix live runs did not complete a payload despite valid VPN binding,
HighID, searches, and packet capture. That is no longer the
cooldown-deferred-source spin fixed here; the next parity pass should analyze
why the selected live candidates produce no payload progress after MFC-paced
direct retry windows.
