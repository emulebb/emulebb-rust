---
id: RUST-FEAT-003
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/3
title: VPN — pin eD2K TCP egress to the tunnel interface (fail-closed)
status: OPEN
priority: Major
category: feature
labels: [vpn, ed2k, tcp, anonymity, binding]
milestone: phase-0
created: 2026-06-14
source: suite forward program (note 10 anonymity); VPN binding parity
---

> Workflow status is tracked in GitHub: https://github.com/emulebb/emulebb-rust/issues/3. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-003 - VPN — pin eD2K TCP egress to the tunnel interface (fail-closed)

## Summary

Egress-pin the eD2K TCP data plane to the VPN tunnel interface so the real IP can
never reach a peer, matching the eMule binding model. Kad UDP egress pinning is
already done via `IP_UNICAST_IF`; eD2K TCP is the remaining gap. This closes the
network-level anonymity guarantee that defines "anonymous" for the suite (note 10).

## Why This Matters

The suite's only anonymity mechanism is fail-closed VPN binding; there is no
protocol-level overlay. An unpinned eD2K TCP socket can leak the real IP into a
swarm, which violates the safety substrate. This is a Phase 0 hardening blocker
for calling rust "perfectly functional".

## Current State

- Kad UDP is egress-pinned to the tunnel `ifIndex` (`IP_UNICAST_IF`; socket2 is
  Unix-only for this, so Windows uses raw `windows-sys setsockopt`).
- eD2K TCP connect/listen sockets are not yet pinned to the tunnel ifIndex. See
  [[vpn-binding-solid-ip-unicast-if]].

## Intended Shape

- Apply the same `IP_UNICAST_IF` egress pin to eD2K TCP connect (and listen where
  applicable), using the live tunnel ifIndex; never loopback/wildcard for the data
  plane. Control plane stays on the local IP. UPnP/port-forwarding over the VPN
  interface must remain allowed ([[vpn-guard-allows-upnp-over-vpn]]).

## Scope Constraints

- Data plane only (eD2K TCP); control/REST plane unchanged.
- IPv4-only; reuse the existing Kad UDP pin implementation pattern.

## Acceptance Criteria

- [ ] eD2K TCP outbound connects are pinned to the tunnel ifIndex (fail-closed:
      no tunnel → no eD2K TCP egress).
- [ ] eD2K TCP listener bound consistently with the VPN binding model.
- [ ] UPnP/port-forwarding over the VPN interface still works.
- [ ] A static/bind-policy test asserts eD2K TCP egress is tunnel-pinned.

## Validation

- Unit/static: bind-policy assertions extend the existing VPN binding tests.
- Local: verify connect uses the tunnel ifIndex; verify no egress when the tunnel
  is down.

## Notes

- Pairs with the existing Kad UDP pin. Mirrors eMule parity.
