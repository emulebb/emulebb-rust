---
id: RUST-BUG-007
workflow: local
title: App metadata uses non-MFC API and capability tokens
status: DONE
priority: Minor
category: bug
labels: [rest, parity, app-metadata]
created: 2026-06-17
source: iterative Rust-vs-MFC parity review
---

# RUST-BUG-007 - App metadata uses non-MFC API and capability tokens

## Summary

Rust's `/api/v1/app` and `/api/v1/capabilities` metadata exposed a Rust-specific
app name, `apiVersion="1"`, and internal namespaced capability tokens. eMuleBB
MFC `BuildAppJson` publishes the canonical `name="eMuleBB"`,
`apiVersion="v1"`, and the public contract capability names (`transfers`,
`searches`, `servers`, `sharedFiles`, and related feature tokens).

## Acceptance Criteria

- [x] App metadata reports canonical `name="eMuleBB"` and `apiVersion="v1"`.
- [x] App capabilities use the public eMuleBB contract names from MFC
      `BuildAppJson`.
- [x] The capabilities endpoint returns the same public capability token family.
- [x] REST tests cover the metadata contract.

## Resolution

- Changed Rust app metadata to publish canonical `name="eMuleBB"` and
  `apiVersion="v1"`.
- Replaced internal namespaced capability tokens with the public eMuleBB
  `/api/v1/app` capability names from MFC `BuildAppJson`.
- Kept `/api/v1/capabilities` as Rust's capability-list endpoint, but now backed
  by the same public token family.

## Evidence

- `cargo test -p emulebb-rest app_returns_evelope_with_capabilities --locked`
- `cargo test -p emulebb-rest capabilities_returns_contract_version_and_capability_list --locked`
- `cargo test -p emulebb-rest snapshot_returns_bounded_emulebb_polling_shape --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
