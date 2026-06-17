use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::{Ed2kNetworkConfig, VpnGuardConfig, VpnGuardStatus};

pub(crate) fn status(network: &Ed2kNetworkConfig, public_ip: Option<Ipv4Addr>) -> VpnGuardStatus {
    let guard = &network.vpn_guard;
    // Master parity (GetVpnGuardModeRestToken): the REST mode token is "block"
    // when guarding is enabled in a blocking mode, otherwise "off".
    let blocking = guard.enabled
        && (guard.mode.eq_ignore_ascii_case("block") || guard.mode.eq_ignore_ascii_case("enforce"));
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

pub(crate) fn public_ip_block_reason(
    guard: &VpnGuardConfig,
    public_ip: Option<Ipv4Addr>,
) -> Option<String> {
    let cidrs = guard.allowed_public_ip_cidrs.trim();
    if cidrs.is_empty() {
        return None;
    }
    let public_ip = public_ip?;

    let public_addr = IpAddr::V4(public_ip);
    let mut found_cidr = false;
    for token in cidrs
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        found_cidr = true;
        let Ok(network) = token.parse::<IpNet>() else {
            return Some(format!("invalid VPN Guard allowed public IP CIDR: {token}"));
        };
        if network.contains(&public_addr) {
            return None;
        }
    }

    found_cidr
        .then(|| format!("public IP {public_ip} is outside VPN Guard allowed public IP CIDRs"))
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
        let guard = guard("203.0.113.0/24");

        assert!(public_ip_block_reason(&guard, Some(Ipv4Addr::new(203, 0, 113, 5))).is_none());
        assert!(
            public_ip_block_reason(&guard, Some(Ipv4Addr::new(198, 51, 100, 5)))
                .unwrap()
                .contains("outside VPN Guard allowed public IP CIDRs")
        );
    }

    #[test]
    fn public_ip_cidr_defers_until_public_ip_is_known_and_reports_invalid_cidr() {
        assert!(public_ip_block_reason(&guard("203.0.113.0/24"), None).is_none());
        assert!(
            public_ip_block_reason(&guard("not-a-cidr"), Some(Ipv4Addr::new(203, 0, 113, 5)))
                .unwrap()
                .contains("invalid VPN Guard allowed public IP CIDR")
        );
    }
}
