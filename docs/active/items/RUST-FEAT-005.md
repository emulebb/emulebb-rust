---
id: RUST-FEAT-005
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/5
title: Automated VPN leak-test — assert no data egress off the tunnel (release-blocking)
status: OPEN
priority: Critical
category: feature
labels: [vpn, anonymity, safety, tests, ci, release-blocker]
milestone: phase-0
created: 2026-06-14
source: PM quality review (2026-06-14); WORKSPACE-POLICY Network Safety invariant
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-005 - Automated VPN leak-test — assert no data egress off the tunnel (release-blocking)

## Summary

Add an automated leak-test that proves emulebb-rust honors the P0 Network Safety
invariant: with the VPN tunnel down/unavailable, the client emits **zero P2P
data-plane traffic** (eD2K TCP, Kad/eD2K UDP) off the tunnel interface. The
control/REST plane on the local IP is unaffected. This gate is **release-blocking**.

## Why This Matters

The suite's "safe / anonymous" promise rests entirely on fail-closed VPN binding.
A leak that ships once destroys the core trust claim. A code-level pin
(RUST-FEAT-003) is necessary but not sufficient without an automated test that
keeps it true over time.

## Intended Shape

- A test that brings the data-plane up with no/incorrect tunnel and asserts no
  connect/sendto leaves a non-tunnel interface (e.g. via a deny-by-default
  firewall/route fixture, or interface-scoped capture asserting zero off-tunnel
  data packets).
- Runs in CI as a blocking gate for emulebb-rust; respects the live-wire policy
  (no public-network contact — the test is local/deterministic).
- Reuse the same leak assertion shape across networked products where possible
  so emulebb-rust, qBittorrentBB, and later suite clients share one safety
  vocabulary.

## Acceptance Criteria

- [ ] Tunnel-down scenario: zero eD2K TCP / Kad UDP egress off the tunnel observed.
- [ ] Control/REST plane on the local IP still functions.
- [ ] Test runs blocking in CI and fails if the data plane leaks.

## Notes

- Pairs with RUST-FEAT-003 (eD2K TCP egress pin). Both are release-blockers per the
  WORKSPACE-POLICY Network Safety invariant. Cross-product sibling: QBBB-FEAT-004.
- 2026-06-19 parity closure review: this item is not required to close **core
  MFC parity**, but it remains the release-blocking gate for claiming automated
  fail-closed anonymity/safety. Public live-wire proof is a smoke witness only.
- 2026-06-17: Added a blocking static Python policy guard for the supported
  public P2P boundary files. The guard rejects regressions that use optional
  bind-ifIndex resolution or explicit no-index egress pinning on those paths.
  This is CI coverage against known leak regressions, but it does not satisfy
  the dynamic tunnel-down packet-observation acceptance criteria above.
- 2026-06-17: Extended the static guard to the STUN public-IP/NAT mapping probe
  path. STUN now requires a resolved bind interface index before DNS/socket
  activity and passes an explicit ifIndex to egress pinning, so a stale or
  unassigned P2P bind IP fails closed instead of degrading to optional pinning.
