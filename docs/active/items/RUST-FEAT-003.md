---
id: RUST-FEAT-003
workflow: github
github_issue: https://github.com/emulebb/emulebb-rust/issues/3
title: VPN — pin eD2K TCP egress to the tunnel interface (fail-closed)
status: DONE
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
- eD2K TCP outbound connects and listener bind now use the configured P2P bind IP
  path, and VPN Guard confirmation now requires the effective bind IP to be on
  the named bind interface or on a detected VPN-looking interface.
- eD2K peer TCP, server TCP, and server UDP helper sockets now require the
  configured bind IP to resolve to a local interface index before any public P2P
  egress can be pinned; unresolved bind IPs fail closed instead of degrading to
  unpinned egress.
- Kad UDP startup, legacy Kad TCP firewall probes, and accepted eD2K TCP sockets
  now use the same fail-closed bind-index rule before public P2P payloads can
  leave the process.
- UPnP/IGD discovery and port-forwarding are pinned to the VPN interface: SSDP
  discovery binds its multicast egress to `nat.bind_ip` and the forwarded
  internal target resolves to the VPN bind IP (the gateway-reported LAN IP never
  overrides it). UPnP intentionally sits outside the eD2K/Kad egress pins because
  UPnP-over-VPN is allowed ([[vpn-guard-allows-upnp-over-vpn]]); it must not fall
  back to the unbound default route. Static bind-policy coverage lives in
  `emulebb_ed2k::nat::miniupnpc::tests` (`discovery_pins_multicast_to_configured_vpn_interface`,
  `unspecified_mapping_forwards_to_configured_vpn_bind_ip`), complementing the
  existing live hide.me evidence (the indefinite-lease 725 workaround).
- Remaining work is live validation that fail-closed behavior holds when the
  tunnel is absent (tracked by `RUST-FEAT-005`).
- Parity closure note 2026-06-19: static bind-index coverage and public
  VPN-bound smoke evidence are sufficient for core MFC parity closure, but they
  do not close the suite safety claim. The dynamic tunnel-down no-egress gate is
  tracked by `RUST-FEAT-005` and remains release-blocking.

## Intended Shape

- Apply the same `IP_UNICAST_IF` egress pin to eD2K TCP connect (and listen where
  applicable), using the live tunnel ifIndex; never loopback/wildcard for the data
  plane. Control plane stays on the local IP. UPnP/port-forwarding over the VPN
  interface must remain allowed ([[vpn-guard-allows-upnp-over-vpn]]).

## Scope Constraints

- Data plane only (eD2K TCP); control/REST plane unchanged.
- IPv4-only; reuse the existing Kad UDP pin implementation pattern.

## Acceptance Criteria

- [x] eD2K TCP outbound connects use the configured P2P bind path.
- [x] eD2K TCP outbound connects are proven pinned to the tunnel ifIndex (fail-closed:
      no tunnel → no eD2K TCP egress).
- [x] eD2K TCP listener bound consistently with the VPN binding model.
- [x] UPnP/port-forwarding over the VPN interface still works (discovery +
      forward target pinned to `nat.bind_ip`; static bind-policy tests in
      `nat::miniupnpc::tests` plus live hide.me evidence).
- [x] A static/bind-policy test asserts eD2K TCP egress is tunnel-pinned.
- [x] Static bind-index coverage proves unassigned bind IPs fail closed before
      public eD2K TCP/UDP egress pinning.
- [x] Kad UDP/probe paths require the resolved tunnel ifIndex instead of
      accepting optional/no-op egress pinning.

## Validation

- Unit/static: bind-policy assertions extend the existing VPN binding tests.
- Local: verify connect uses the tunnel ifIndex; verify no egress when the tunnel
  is down.
- Core parity close: keep the hide.me live-wire proof manual/nonblocking and
  require `RUST-FEAT-005` before claiming automated no-leak safety.

## Notes

- Pairs with the existing Kad UDP pin. Mirrors eMule parity.
