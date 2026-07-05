---
id: RUST-FEAT-005
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/5
title: Automated VPN leak-test — assert no data egress off the tunnel (release-blocking)
status: IN_PROGRESS
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

- [x] Tunnel-down scenario: zero eD2K TCP / Kad UDP egress off the tunnel observed.
- [x] Control/REST plane on the local IP still functions.
- [x] Test runs blocking in CI and fails if the data plane leaks.

## Implementation (2026-07-05)

The dynamic **observed-egress** gate landed via a test-only `egress-audit` cargo
feature: an audit recorder at the single P2P socket chokepoint
(`emulebb-kad-net/src/socket_opts/egress_audit.rs`, hooked in
`pin_egress_to_interface`) captures every P2P socket's bound local address and
the interface index its egress was pinned to.
`crates/emulebb-core/tests/vpn_leak_egress.rs` asserts three scenarios:
- **tunnel up** — every P2P socket is bound to the tunnel IP and pinned to the
  tunnel interface index (so no datagram/segment can leave a non-tunnel iface);
- **tunnel down** — ZERO P2P sockets open (empty audit) while REST/status answer;
- **tunnel pulled mid-run** — no NEW P2P socket opens (steady-state fail-closed).

Wired blocking into CI via the `test-vpn-leak` step of
`tools/rust_quality_gate.py ci-test`
(`cargo test -p emulebb-core --features egress-audit --test vpn_leak_egress --
--test-threads=1`; serial because the 3 scenarios share the global recorder).
`tools/check_rust_client_policy.py` guards the feature as test-only (never in a
crate's `default` feature set, never referenced by the daemon binary).

**Remaining (additive evidence, NOT release-blocking now that socket-truth gates
CI on both OSes):** an optional Linux-only wire-truth CI job (dummy tunnel iface +
tcpdump asserting zero off-tunnel frames), and the operator Windows wire-truth
`tools/vpn_leak_local_gate.py` (pktmon on the physical NIC with a real hide.me
tunnel pull), recorded during the Phase-4 soak.

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
