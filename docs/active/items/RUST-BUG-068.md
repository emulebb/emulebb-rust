---
id: RUST-BUG-068
title: Keep active ED2K downloads retrying after exhausted direct peers
status: in_progress
priority: Major
category: bug
workflow: local
---

# RUST-BUG-068: Keep active ED2K downloads retrying after exhausted direct peers

## Problem

The hide.me live-wire run
`EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260618T182219Z` showed
that `RUST-BUG-067` increased direct peer attempts from 3 to 16, but every direct
peer failed and the transfers then stopped circulating through the background
driver. Rust demoted the transfer to `queued` after exhausted direct peer errors,
so the harness waited until timeout with no further source acquisition.

eMuleBB MFC keeps an active part file in processing after source failures: failed
sources are handled, but the file remains eligible for later source discovery and
peer attempts unless the user pauses/stops it.

## Acceptance

- [x] Exhausting direct peer attempts without progress keeps an active download in
      `downloading` instead of demoting it to `queued`.
- [x] The existing delayed retry driver remains responsible for the next attempt.
- [x] Connected-server source refresh cooldowns from `RUST-BUG-066` still prevent
      rapid repeated server source requests across retries.
- [x] Focused unit coverage proves direct peer failure exhaustion requests a retry
      only when direct sources were actually attempted.
- [ ] The next hide.me live-wire run shows continued attempts after the first
      direct peer exhaustion window.

## Implementation Notes

- Keep this as retry-state policy, not as a transport change.
- Do not retry paused, stopped, deleted, or completed transfers; the existing
  cancel/control-state gates still own those cases.

## Evidence

- Pending focused test and live-wire proof.
