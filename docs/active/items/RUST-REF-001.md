---
id: RUST-REF-001
workflow: local
title: Split REST route body validators by responsibility
status: DONE
priority: Minor
category: refactor
labels: [rest, maintainability, validation]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-REF-001 - Split REST route body validators by responsibility

## Summary

The REST route body metadata module was approaching the standard Rust source
file budget while accumulating route-specific MFC parity validators. Keeping all
validators in the route dispatch module would make the next parity slices harder
to review and would risk exceeding the file-size policy.

## Acceptance Criteria

- [x] Keep route parsing, validation order, body allowlists, and path matching in
      `route_body_metadata.rs`.
- [x] Move route-specific body validator implementations to a dedicated module.
- [x] Preserve all existing REST body validation behavior and messages.
- [x] Keep both resulting `.rs` files under the standard source budget.

## Resolution

- Added `route_body_metadata/validators.rs` for route-specific body validators.
- Kept the public middleware entry point and MFC validation order in
  `route_body_metadata.rs`.
- Verified focused REST body tests, the full REST crate, and the quick quality
  gate after the split.

## Evidence

- `cargo test -p emulebb-rest route_body_validation --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
