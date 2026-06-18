---
id: RUST-BUG-066
title: Pace connected-server source refreshes across retry attempts
status: in_progress
priority: Major
category: bug
workflow: local
---

# RUST-BUG-066: Pace connected-server source refreshes across retry attempts

## Problem

Live-wire diagnostics after `RUST-BUG-065` still showed repeated connected
server source-search timeouts for the same transfer hashes. The short requery
round correctly skipped server refreshes inside a single attempt, but a failed
background download attempt is retried every few seconds and the next task
starts again at requery round zero.

eMuleBB MFC paces connected-server source asks per file with `SERVERREASKTIME`
(15 minutes). A Rust retry task should not reset that wall-clock cooldown and
hit the connected server again immediately.

## Acceptance

- [x] Connected-server source refreshes are claimed per file across background
      retry attempts.
- [x] The per-file cooldown is 15 minutes, matching MFC `SERVERREASKTIME`.
- [x] UDP source batch pacing remains independent at its 30-minute cadence.
- [x] Focused unit coverage proves same-file retries are suppressed while other
      files and expired entries can still refresh.
- [ ] The next hide.me live-wire run shows connected-server source timeout
      churn is reduced versus the 72 warnings seen in
      `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T173921Z`.

## Implementation Notes

- Keep the cooldown in session memory; this is runtime pacing, not durable
  transfer metadata.
- Claim the refresh before sending the connected-server request so timeouts are
  paced too.

## Evidence

- `cargo test -p emulebb-core connected_server_source_refresh_is_paced_per_file --locked`
- `python tools\check_rust_client_policy.py`
- `python tools\rust_quality_gate.py quick`
