use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::{Ed2kNetworkConfig, VpnGuardConfig, VpnGuardStatus};

pub(crate) fn status(network: &Ed2kNetworkConfig, public_ip: Option<Ipv4Addr>) -> VpnGuardStatus {
    let guard = &network.vpn_guard;
    let blocking = is_blocking_mode(guard);
    let interface_block_reason = if blocking && !network.vpn_interface_bound {
        Some("public P2P bind is not VPN-confirmed".to_string())
    } else {
        None
    };
    let public_ip_block_reason = blocking
        .then(|| public_ip_block_reason(guard, public_ip))
        .flatten();
    let startup_block_reason = interface_block_reason
        .or(public_ip_block_reason)
        .unwrap_or_default();
    VpnGuardStatus {
        enabled: guard.enabled,
        mode: if blocking { "block" } else { "off" }.to_string(),
        allowed_public_ip_cidrs: guard.allowed_public_ip_cidrs.clone(),
        startup_blocked: !startup_block_reason.is_empty(),
        startup_block_reason,
    }
}

fn is_blocking_mode(guard: &VpnGuardConfig) -> bool {
    // Master parity (ParseModePreferenceText / GetVpnGuardModeRestToken): only
    // the "Block" token enables guarding; every other text maps to "off".
    guard.enabled && guard.mode.eq_ignore_ascii_case("block")
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

    let Some(public_ip) = public_ip else {
        return Some("public IP is unknown for VPN Guard allowed public IP CIDRs".to_string());
    };
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
    fn public_ip_cidr_blocks_until_public_ip_is_known_and_reports_invalid_cidr() {
        assert!(
            public_ip_block_reason(&guard("8.8.8.0/24"), None)
                .unwrap()
                .contains("public IP is unknown")
        );
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
