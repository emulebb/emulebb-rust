---
id: RUST-REF-002
workflow: local
title: Parity sweep for the 0.1.0-beta.1 release - enumerate and disposition every unregistered divergence
status: OPEN
priority: Major
category: refactor
labels: [parity, review, kad, ed2k, rest, release]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: 0.1.0-beta.1 release program (2026-07-05); follows the 2026-07-02 protocol & internals review
---

# RUST-REF-002 - Release parity sweep with full disposition

## Summary

Run one more full-depth parity review of emulebb-rust vs eMuleBB MFC master
before the `rust-v0.1.0-beta.1` release, using the proven 3-lane pattern
(Kad / eD2K transfer+protocol / server+REST+persistence), scoped to
**unregistered divergences only**: the omissions registry
(`policy/rust-client-omissions.toml`) and the `[review_reporting]` excluded
list suppress known/intentional surface.

## Why This Matters

The A1–A4 gap list came from the 2026-07-02 review, and one of its claims (A2
outbound leg) was already stale by then. The release claim "parity gaps closed,
excluded surface documented with no ambiguity" needs a fresh enumeration after
the RUST-FEAT-025/030/031/032 fixes land.

## Disposition Rule (no ambiguity allowed)

Every finding gets exactly one disposition:

1. **Fix** — real gap on supported surface: sequential fix lane, one coherent
   commit, MFC-pinned semantics + tests; or
2. **Register** — intentional divergence: entry in
   `policy/rust-client-omissions.toml` with stock/rust/reason/compatibility; or
3. **Defer** — parked surface: named in the deferred list of the release scope
   doc (RUST-FEAT-033) with the parking decision referenced.

## Acceptance Criteria

- [ ] 3-lane review executed against current MFC master after Phase 1/2 fixes.
- [ ] Zero findings without a disposition.
- [ ] Review verdict + finding table recorded in this item (not only in
      git-excluded working notes).

## Notes

Local-only workflow: this is an internal evidence gate, not public product
surface.
