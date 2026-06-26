---
id: RUST-BUG-069
title: Pace failed direct source retries per endpoint
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-069: Pace failed direct source retries per endpoint

## Problem

The hide.me live-wire run
`EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T184108Z` proved
that active downloads now keep retrying after direct peer failures, but the retry
loop redialed the same dead direct endpoints several times inside one live
window. The clearest examples were:

- `195.154.51.215:14662`, retried 12 times for file
  `09a6d19d267a1d5f1cf2aeb0342f3755`.
- `89.141.127.85:60662`, retried 4 times for file
  `06399c801aac2379f93ce6bd9049ca4d`.

eMuleBB MFC records a source's last connection attempt and only calls
`AskForDownload()` after the per-source retry window expires. Rust's active retry
task was local-only, so the next task could immediately choose the same failed
endpoint again.

## Acceptance

- [x] A direct endpoint that was just leased remains deferred after the lease is
      released until the retry cooldown expires.
- [x] The cooldown is 20 minutes, matching MFC's direct-source retry gate.
- [x] Existing active peer leases still prevent concurrent duplicate dials.
- [x] Connected-server source refresh pacing remains independent.
- [x] Focused unit coverage proves released endpoints cannot be re-leased inside
      the retry window.
- [x] The next hide.me live-wire diagnostics run shows repeated same-endpoint
      redials are suppressed versus
      `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T184108Z`.

## Implementation Notes

- Keep this in session memory in the source registry. This mirrors MFC's
  runtime source-attempt state and avoids writing transient failure timing into
  transfer metadata.
- Track the cooldown by direct TCP endpoint so the same dead peer is not redialed
  for another active file immediately after a failed attempt.

## Evidence

- `cargo test -p emulebb-core released_endpoint_stays_cooldown_deferred_until_retry_window_expires --locked`
- `python tools\rust_quality_gate.py quick`
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T190434Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T190522Z\report.json`:
  VPN-bound HighID run started 18 downloads, completed candidate 2
  (103303 bytes), reached 24 peak reported sources from 18 initial sources, and
  captured packet diagnostics (6333 diagnostic records, 326 ED2K packet records,
  5903 Kad UDP packet records).
- Retry-pacing comparison against
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T184108Z`:
  direct attempts dropped from 24 to 12. The previously repeated endpoint
  `195.154.51.215:14662` dropped from 12 attempts for
  `09a6d19d267a1d5f1cf2aeb0342f3755` to 1 attempt. The peer-level repeats for
  `89.141.127.85:60662` dropped from 7 attempts to 1 attempt. The only repeated
  endpoints in the fixed run were the expected obfuscated attempt plus immediate
  plaintext fallback inside the same leased source, not retry-task redials.
