---
id: RUST-BUG-089
title: Separate live-wire completed and partial byte counters
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-089: Separate live-wire completed and partial byte counters

## Problem

The hide.me live-wire run `rust-hideme-20260619T042816Z` passed in both
obfuscation modes, but the obfuscation-on report showed one completed file while
`totalCompletedBytes` included bytes from other partially downloaded transfers.
That made live-wire evidence harder to compare against eMuleBB MFC behavior,
where completed-file accounting and partial-progress accounting are separate
concepts.

## Acceptance

- [x] Live-wire reports completed-file bytes separately from aggregate verified
      partial bytes.
- [x] The compatibility `totalCompletedBytes` value now means completed-file
      bytes only.
- [x] Tests cover the mixed completed-plus-partial case.

## Implementation Notes

- Updated `EMULEBB_WORKSPACE_ROOT\repos\emulebb-build-tests\scripts\rust-live-wire-hideme.py` to emit
  `completedFilesTotalBytes`, `aggregateVerifiedBytes`, and a corrected
  `totalCompletedBytes`.
- Added a Python unit test in the shared harness suite.

## Evidence

- Live behavior exposing the report ambiguity:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T042816Z`.
- `python -m pytest tests/python/test_rust_client.py`
