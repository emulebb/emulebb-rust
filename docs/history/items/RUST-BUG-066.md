---
id: RUST-BUG-066
title: Pace connected-server source refreshes across retry attempts
status: done
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
- [x] The next hide.me live-wire run shows connected-server source timeout
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
- Diagnostics build
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\logs\builds\20260618T175715Z-build-clients\build-result.json`:
  Release diagnostics build passed with zero warnings.
- Live-wire hide.me diagnostics run
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T175809Z\report.json`:
  VPN-bound HighID run started 18 downloads and captured packet diagnostics.
  The daemon log showed 18 connected-server source-search timeout warnings and
  18 sent connected-server source searches, down from 72 timeout warnings and
  41 sent searches in
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T173921Z`. The
  same run captured 30 batched outbound `OP_GLOBGETSOURCES` packets, each with
  an 18-file payload, sent to 30 distinct servers.

The live run did not complete a download before timeout, so it is not a full
end-to-end pass. It is sufficient evidence for this server-source pacing fix
because the connected-server retry churn was eliminated while VPN binding,
HighID, Kad connectivity, and packet diagnostics were active.
