use std::{net::Ipv4Addr, sync::atomic::Ordering};

use emulebb_ed2k::NetworkInterface;
use emulebb_ed2k::public_ip_probe::BoundProbeResult;
use ipnet::Ipv4Net;

use crate::{Ed2kNetworkConfig, VpnGuardConfig, VpnGuardProbeStatus, VpnGuardStatus};

/// Latest bound egress-probe outcomes (STUN UDP + HTTP TCP), mirroring eMuleBB's
/// dual `PublicIpProbe`. Populated by the guard monitor's active egress probe and
/// consumed by [`status`] for the verdict + REST surface. Default = not yet probed.
#[derive(Debug, Clone, Default)]
pub struct EgressProbeReport {
    pub stun: BoundProbeResult,
    pub http: BoundProbeResult,
}

fn probe_status(probe: &BoundProbeResult) -> VpnGuardProbeStatus {
    VpnGuardProbeStatus {
        attempted: probe.attempted,
        succeeded: probe.succeeded,
        public_ip: probe.public_ip.map(|ip| ip.to_string()),
        provider: probe.provider.clone(),
        error: probe.error.clone(),
    }
}

pub(crate) fn status(
    network: &Ed2kNetworkConfig,
    public_ip: Option<Ipv4Addr>,
    report: &EgressProbeReport,
) -> VpnGuardStatus {
    let guard = &network.vpn_guard;
    let blocking = is_blocking_mode(guard);
    let vpn_interface_bound = network
        .vpn_interface_bound_runtime
        .as_ref()
        .map(|runtime| runtime.load(Ordering::SeqCst))
        .unwrap_or(network.vpn_interface_bound);
    let interface_block_reason = if blocking && !vpn_interface_bound {
        Some("public P2P bind is not VPN-confirmed".to_string())
    } else {
        None
    };
    // Active egress verdict: when blocking with a CIDR gate, at least one bound
    // public IPv4 probe (STUN UDP or HTTP TCP) must resolve an allowlisted public
    // IP. Any successful probe that resolves an out-of-range IP still fails closed.
    let egress_block = blocking
        .then(|| egress_probe_block_reason(guard, report))
        .flatten();
    // The learned reachability IP (server OP_IDCHANGE / STUN fallback) still gates
    // even before the active probes have run, so the guard is never open at startup.
    let learned_block = blocking
        .then(|| public_ip_block_reason(guard, public_ip))
        .flatten();
    let cidr_gate = !guard.allowed_public_ip_cidrs.trim().is_empty();
    let egress_verified =
        blocking && cidr_gate && egress_block.is_none() && egress_probe_verified(guard, report);
    let startup_block_reason = interface_block_reason
        .or(egress_block.clone())
        .or(learned_block)
        .unwrap_or_default();
    let probed_ip = report
        .http
        .public_ip
        .or(report.stun.public_ip)
        .or(public_ip)
        .map(|ip| ip.to_string());
    VpnGuardStatus {
        enabled: guard.enabled,
        mode: if blocking { "block" } else { "off" }.to_string(),
        allowed_public_ip_cidrs: guard.allowed_public_ip_cidrs.clone(),
        startup_blocked: !startup_block_reason.is_empty(),
        startup_block_reason,
        public_ip: probed_ip,
        egress_verified,
        egress_block_reason: egress_block.unwrap_or_default(),
        stun_probe: probe_status(&report.stun),
        http_probe: probe_status(&report.http),
    }
}

/// Bound egress verdict. With no CIDR gate there is nothing to verify (`None`).
/// Unattempted probes are skipped. A successful out-of-range probe fails closed;
/// otherwise one successful allowlisted probe is enough, so a transient STUN-only
/// or HTTP-only provider outage does not sink the whole P2P startup.
pub(crate) fn egress_probe_block_reason(
    guard: &VpnGuardConfig,
    report: &EgressProbeReport,
) -> Option<String> {
    if guard.allowed_public_ip_cidrs.trim().is_empty() {
        return None;
    }
    let mut attempted_failures = Vec::new();
    let mut allowlisted_success = false;
    for (label, probe) in [("STUN", &report.stun), ("HTTP", &report.http)] {
        if !probe.attempted {
            continue;
        }
        if !probe.succeeded {
            let detail = probe.error.as_deref().unwrap_or("no public IP resolved");
            attempted_failures.push(format!("{label}: {detail}"));
            continue;
        }
        if let Some(reason) = public_ip_block_reason(guard, probe.public_ip) {
            return Some(format!("{label} egress {reason}"));
        }
        allowlisted_success = true;
    }
    if allowlisted_success {
        return None;
    }
    if attempted_failures.is_empty() {
        None
    } else {
        Some(format!(
            "VPN Guard bound public IPv4 probes failed: {}",
            attempted_failures.join("; ")
        ))
    }
}

pub(crate) fn egress_probe_verified(guard: &VpnGuardConfig, report: &EgressProbeReport) -> bool {
    if guard.allowed_public_ip_cidrs.trim().is_empty() {
        return false;
    }
    [report.stun.public_ip, report.http.public_ip]
        .into_iter()
        .flatten()
        .any(|ip| public_ip_block_reason(guard, Some(ip)).is_none())
}

fn is_blocking_mode(guard: &VpnGuardConfig) -> bool {
    // Master parity (ParseModePreferenceText / GetVpnGuardModeRestToken): only
    // the "Block" token enables guarding; every other text maps to "off".
    guard.enabled && guard.mode.eq_ignore_ascii_case("block")
}

pub fn binding_confirmed(
    bind_ip: Ipv4Addr,
    bind_interface: Option<&str>,
    interfaces: &[NetworkInterface],
) -> bool {
    let bind_ip_text = bind_ip.to_string();
    let ip_on_vpn_candidate = interfaces.iter().any(|iface| {
        iface.is_vpn_candidate
            && iface
                .addresses
                .iter()
                .any(|address| address.address == bind_ip_text)
    });
    let named_interface_matches = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|name| {
            interfaces.iter().any(|iface| {
                iface.name.trim().eq_ignore_ascii_case(name)
                    && iface
                        .addresses
                        .iter()
                        .any(|address| address.address == bind_ip_text)
            })
        });

    ip_on_vpn_candidate || named_interface_matches
}

pub(crate) fn public_ip_block_reason(
    guard: &VpnGuardConfig,
    public_ip: Option<Ipv4Addr>,
) -> Option<String> {
    let cidrs = guard.allowed_public_ip_cidrs.trim();
    if cidrs.is_empty() {
        return None;
    }

    let mut networks = Vec::new();
    for token in cidrs
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let Ok(network) = parse_allowed_public_ipv4_range(token) else {
            return Some(format!("invalid VPN Guard allowed public IP CIDR: {token}"));
        };
        if !is_public_ipv4_range_only(&network) {
            return Some(format!(
                "VPN Guard allowed public IP CIDR is not public IPv4: {token}"
            ));
        }
        networks.push(network);
    }

    let public_ip = public_ip?;
    if networks.iter().any(|network| network.contains(&public_ip)) {
        return None;
    }
    (!networks.is_empty())
        .then(|| format!("public IP {public_ip} is outside VPN Guard allowed public IP CIDRs"))
}

fn parse_allowed_public_ipv4_range(token: &str) -> Result<Ipv4Net, ()> {
    token
        .parse::<Ipv4Net>()
        .or_else(|_| {
            token
                .parse::<Ipv4Addr>()
                .map_err(|_| ())
                .and_then(|ip| Ipv4Net::new(ip, 32).map_err(|_| ()))
        })
        .map_err(|_| ())
}

fn is_public_ipv4_range_only(network: &Ipv4Net) -> bool {
    let non_public = [
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xffff_ffff, 32),
    ];
    non_public.iter().all(|(base, prefix)| {
        !ipv4_ranges_overlap(
            u32::from(network.network()),
            network.prefix_len(),
            *base,
            *prefix,
        )
    })
}

fn ipv4_ranges_overlap(
    first_base: u32,
    first_prefix: u8,
    second_base: u32,
    second_prefix: u8,
) -> bool {
    let shared_prefix = first_prefix.min(second_prefix);
    let mask = if shared_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(shared_prefix))
    };
    (first_base & mask) == (second_base & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(cidrs: &str) -> VpnGuardConfig {
        VpnGuardConfig {
            enabled: true,
            mode: "block".to_string(),
            allowed_public_ip_cidrs: cidrs.to_string(),
        }
    }

    fn probe(succeeded: bool, ip: Option<Ipv4Addr>, attempted: bool) -> BoundProbeResult {
        BoundProbeResult {
            attempted,
            succeeded,
            public_ip: ip,
            provider: "http://test/".to_string(),
            error: (!succeeded).then(|| "unreachable".to_string()),
        }
    }

    #[test]
    fn egress_verdict_none_without_cidr_gate() {
        // No CIDR gate → nothing to verify even if a probe resolved an odd IP.
        let report = EgressProbeReport {
            stun: probe(true, Some(Ipv4Addr::new(1, 1, 1, 1)), true),
            http: probe(true, Some(Ipv4Addr::new(1, 1, 1, 1)), true),
        };
        assert!(egress_probe_block_reason(&guard(""), &report).is_none());
    }

    #[test]
    fn egress_verdict_allows_in_range_and_blocks_out_of_range() {
        let guard = guard("176.10.104.0/22");
        let allowed = Ipv4Addr::new(176, 10, 104, 9);
        let leaked = Ipv4Addr::new(8, 8, 8, 8);
        // Both probes resolve an allowlisted IP -> verified.
        let ok = EgressProbeReport {
            stun: probe(true, Some(allowed), true),
            http: probe(true, Some(allowed), true),
        };
        assert!(egress_probe_block_reason(&guard, &ok).is_none());
        assert!(egress_probe_verified(&guard, &ok));
        // HTTP probe resolves an out-of-allowlist IP → a leak is reported.
        let leak = EgressProbeReport {
            stun: probe(true, Some(allowed), true),
            http: probe(true, Some(leaked), true),
        };
        assert!(
            egress_probe_block_reason(&guard, &leak)
                .unwrap()
                .contains("HTTP egress")
        );
        assert!(egress_probe_verified(&guard, &leak));
    }

    #[test]
    fn egress_verdict_accepts_one_successful_probe_but_fails_when_all_attempts_fail() {
        let guard = guard("176.10.104.0/22");
        let allowed = Ipv4Addr::new(176, 10, 104, 9);
        // STUN can be down while HTTP verifies the same bound IPv4 egress.
        let http_only = EgressProbeReport {
            stun: probe(false, None, true),
            http: probe(true, Some(allowed), true),
        };
        assert!(egress_probe_block_reason(&guard, &http_only).is_none());
        assert!(egress_probe_verified(&guard, &http_only));
        // All attempted probes failing still fails closed.
        let failed = EgressProbeReport {
            stun: probe(false, None, true),
            http: probe(false, None, true),
        };
        assert!(
            egress_probe_block_reason(&guard, &failed)
                .unwrap()
                .contains("bound public IPv4 probes failed")
        );
        assert!(!egress_probe_verified(&guard, &failed));
        // A not-yet-attempted probe is skipped and is not verified.
        let unattempted = EgressProbeReport::default();
        assert!(egress_probe_block_reason(&guard, &unattempted).is_none());
        assert!(!egress_probe_verified(&guard, &unattempted));
    }

    #[test]
    fn public_ip_cidr_allows_matching_ip_and_blocks_mismatch() {
        let guard = guard("8.8.8.0/24");

        assert!(public_ip_block_reason(&guard, Some(Ipv4Addr::new(8, 8, 8, 8))).is_none());
        assert!(
            public_ip_block_reason(&guard, Some(Ipv4Addr::new(1, 1, 1, 1)))
                .unwrap()
                .contains("outside VPN Guard allowed public IP CIDRs")
        );
    }

    #[test]
    fn mode_only_blocks_for_block_token() {
        let mut guard = guard("");
        guard.mode = "enforce".to_string();
        assert!(!is_blocking_mode(&guard));

        guard.mode = "Block".to_string();
        assert!(is_blocking_mode(&guard));

        guard.enabled = false;
        assert!(!is_blocking_mode(&guard));
    }

    #[test]
    fn public_ip_cidr_allows_host_address_without_prefix() {
        let guard = guard("8.8.8.8");

        assert!(public_ip_block_reason(&guard, Some(Ipv4Addr::new(8, 8, 8, 8))).is_none());
        assert!(
            public_ip_block_reason(&guard, Some(Ipv4Addr::new(8, 8, 8, 9)))
                .unwrap()
                .contains("outside VPN Guard allowed public IP CIDRs")
        );
    }

    #[test]
    fn public_ip_cidr_waits_for_public_ip_observation_and_reports_invalid_cidr() {
        assert!(public_ip_block_reason(&guard("8.8.8.0/24"), None).is_none());
        assert!(
            public_ip_block_reason(&guard("not-a-cidr"), Some(Ipv4Addr::new(203, 0, 113, 5)))
                .unwrap()
                .contains("invalid VPN Guard allowed public IP CIDR")
        );
    }

    #[test]
    fn public_ip_cidr_rejects_non_ipv4_and_non_public_ranges_before_matching() {
        assert!(
            public_ip_block_reason(&guard("2001:db8::/32"), Some(Ipv4Addr::new(8, 8, 8, 8)))
                .unwrap()
                .contains("invalid VPN Guard allowed public IP CIDR")
        );
        assert!(
            public_ip_block_reason(&guard("10.0.0.0/8"), Some(Ipv4Addr::new(10, 1, 2, 3)))
                .unwrap()
                .contains("not public IPv4")
        );
        assert!(
            public_ip_block_reason(
                &guard("8.8.8.0/24 not-a-cidr"),
                Some(Ipv4Addr::new(8, 8, 8, 8))
            )
            .unwrap()
            .contains("invalid VPN Guard allowed public IP CIDR")
        );
    }
}
