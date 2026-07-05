---
id: RUST-FEAT-034
workflow: local
title: VPN Guard active egress verification - bound HTTP + STUN public-IP probes (eMuleBB PublicIpProbe parity)
status: DONE
priority: Major
category: feature
labels: [vpn-guard, security, parity, ed2k, kad, rest]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: converged-soak VPN-guard review (2026-07-05) - the client, not the harness, must verify its public egress
---

# RUST-FEAT-034 - VPN Guard active egress verification (HTTP + STUN)

## Summary

Bring the rust VPN Guard to eMuleBB-MFC `PublicIpProbe` parity: the **client**
actively verifies its public egress two independent ways, each source-bound and
`IP_UNICAST_IF`-pinned to the tunnel interface (identical to the eD2k/Kad
data-plane sockets), and gates on the allowlist:

- **UDP/STUN** bound probe (`StartBoundStunIpv4Probe`) — rust already had the
  bound + pinned `stun_probe`; now surfaced as a guard leg.
- **TCP/HTTP** bound probe (`StartBoundPublicIpv4Probe`) — new
  `emulebb-ed2k/src/public_ip_probe.rs::http_probe`, provider list mirroring
  `PublicIpProbeSeams.h` (api.ipify.org, ipv4.icanhazip.com, checkip.amazonaws.com,
  v4.ident.me, ipecho.net/plain).

## Why This Matters

The prior guard trusted the *learned* public IP (server OP_IDCHANGE / STUN
fallback) against the allowlist. MFC instead **actively probes both the TCP and
UDP egress** and requires each to resolve an allowlisted public IP
(`VpnGuardPolicySeams::IsProbeResultAllowed` = `!checkRequired || (succeeded &&
allowed)`), failing the cycle closed otherwise. An earlier attempt put a STUN/HTTP
prober in the Python soak harness — wrong: that validates a Python socket's exit,
not the client's, and duplicates logic that belongs in the client.

## What Landed

- `public_ip_probe.rs`: bound+pinned HTTP probe + `BoundProbeResult`
  (`SBoundPublicIpv4ProbeResult` subset) + STUN delegation.
- `vpn_guard.rs`: `EgressProbeReport` + `egress_probe_block_reason`
  (MFC verdict: each attempted probe must succeed AND land in the allowlist;
  unattempted is skipped; no CIDR gate = nothing to verify). Folded into the
  guard verdict; probe-confirmed `public_ip` + `egress_verified` exposed.
- `network_binding.rs`: `run_vpn_guard_egress_probe` (runs both legs bound to the
  tunnel bind IP; no-op without a CIDR gate / resolved bind IP).
- `vpn_guard_monitor.rs`: startup egress gate + ~5-min runtime re-probe; existing
  fail-closed exit path reacts to an egress-verdict failure (mirrors
  `ExitForVpnGuardFailure`).
- REST `vpnGuard`: `publicIp`, `egressVerified`, `egressBlockReason`, `stunProbe`,
  `httpProbe`; `/api/v1` contract 1.1.0 -> 1.2.0 (additive).

## Acceptance Criteria

- [x] Bound + pinned HTTP probe (TCP) alongside the bound + pinned STUN probe (UDP).
- [x] Guard verdict requires both to resolve an allowlisted public IP; fail-closed.
- [x] Startup + runtime cadence in the daemon monitor.
- [x] Probe results + verdict exposed over REST for the harness to read.
- [x] Unit tests: HTTP body parse, verdict table (in-range / out-of-range / probe
      failure / unattempted). clippy + fmt + policy green.

## Notes

The soak harness reads this REST verdict (no Python probing) - see the
converged-soak harness change and [[emulebb-rust-release-0-1-0-beta-1]].
