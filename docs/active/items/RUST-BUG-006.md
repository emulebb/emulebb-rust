---
id: RUST-BUG-006
workflow: local
title: Kad status reports running as connected before bootstrap
status: DONE
priority: Major
category: bug
labels: [rest, kad, parity, status]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-006 - Kad status reports running as connected before bootstrap

## Summary

Rust's fallback Kad status helper reported `connected=true` whenever Kad was
marked running, and exposed user/file totals as `0` before the DHT was actually
bootstrapped. eMuleBB MFC `BuildKadStatusJson` distinguishes `IsRunning()` from
`IsConnected()`: while running but not connected, it reports
`bootstrapping=true`, `connected=false`, and `users`/`files` as `null`.

## Acceptance Criteria

- [x] Running-without-bootstrap Kad status reports `connected=false` and
      `bootstrapping=true`.
- [x] Kad `users` and `files` remain `null` until the runtime is connected.
- [x] Local tests cover stopped, bootstrapping, and runtime-not-bootstrapped
      status mapping.

## Resolution

- Changed the fallback Kad status view so `running=true` no longer implies
  `connected=true`.
- Kept user/file totals unknown (`null` in REST) until the DHT runtime is
  actually bootstrapped.
- Updated the live-runtime status path to expose users/files only when connected.

## Evidence

- `cargo test -p emulebb-core kad_status_running_is_bootstrapping_until_connected --locked`
- `cargo test -p emulebb-core kad_status_stopped_has_unknown_network_totals --locked`
- `cargo test -p emulebb-core status_reports_live_dht_runtime_kad_contacts --locked`
