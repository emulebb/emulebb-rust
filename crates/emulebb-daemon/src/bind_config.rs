use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use emulebb_core::vpn_guard::binding_confirmed;
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface};

use crate::DaemonProfile;

/// A transient startup prerequisite, distinct from invalid or ambiguous binding settings.
#[derive(Debug, PartialEq, Eq)]
pub enum NetworkStartupError {
    DefaultRouteUnavailable,
}

impl std::fmt::Display for NetworkStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefaultRouteUnavailable => formatter.write_str(
                "network.p2p.bindIp or network.p2p.bindInterface is required because no default-route IPv4 interface was detected; \
                 while stopped, use --profile PATH settings set network.p2p.bindInterface NAME",
            ),
        }
    }
}

impl std::error::Error for NetworkStartupError {}

impl DaemonProfile {
    /// Preserve the original operator route selection before resolving its source IP.
    pub(crate) fn egress_route(&self) -> emulebb_ed2k::networking::EgressRoute {
        use emulebb_ed2k::networking::EgressRoute;
        if self.p2p_bind_ip.is_none()
            && self
                .p2p_bind_interface
                .as_deref()
                .is_none_or(|name| name.trim().is_empty())
            && !self.vpn_guard.enabled
            && self.vpn_guard.mode.eq_ignore_ascii_case("off")
        {
            EgressRoute::DirectSystemRoute
        } else {
            EgressRoute::StrictInterface
        }
    }

    pub(crate) fn resolve_p2p_bind_ip_from_interfaces(
        &self,
        interfaces: &[NetworkInterface],
    ) -> Result<Ipv4Addr> {
        let bind_interface = self
            .p2p_bind_interface
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(bind_interface) = bind_interface {
            match resolve_p2p_bind_interface_ip(interfaces, bind_interface) {
                Ok(bind_ip) => return Ok(bind_ip),
                Err(error) => {
                    if let Some(candidate) = self.p2p_bind_ip
                        && self.vpn_guard_blocks_p2p()
                    {
                        return Ok(candidate);
                    }
                    return Err(error);
                }
            }
        }

        if let Some(candidate) = self.p2p_bind_ip {
            return Ok(candidate);
        }
        if !self.vpn_guard_blocks_p2p() {
            return resolve_default_route_ip(interfaces);
        }
        bail!(
            "network.p2p.bindIp or network.p2p.bindInterface is required when VPN Guard blocks public P2P"
        );
    }

    pub(crate) fn vpn_binding_confirmed(
        &self,
        bind_ip: Ipv4Addr,
        interfaces: &[NetworkInterface],
    ) -> bool {
        binding_confirmed(bind_ip, self.p2p_bind_interface.as_deref(), interfaces)
    }

    fn vpn_guard_blocks_p2p(&self) -> bool {
        self.vpn_guard.enabled && self.vpn_guard.mode.eq_ignore_ascii_case("block")
    }
}

fn resolve_default_route_ip(interfaces: &[NetworkInterface]) -> Result<Ipv4Addr> {
    let candidates = interfaces
        .iter()
        .filter(|iface| iface.has_default_route && !iface.is_loopback)
        .flat_map(|iface| {
            iface.addresses.iter().filter_map(|address| {
                matches!(address.family, InterfaceAddressFamily::Ipv4)
                    .then(|| address.address.parse::<Ipv4Addr>().ok())
                    .flatten()
                    .filter(|address| !address.is_loopback() && !address.is_unspecified())
            })
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [address] => Ok(*address),
        [] => Err(NetworkStartupError::DefaultRouteUnavailable.into()),
        _ => bail!(
            "network.p2p.bindIp or network.p2p.bindInterface is required because multiple default-route IPv4 interfaces were detected; \
             while the daemon is stopped, run emulebb-rust --profile <PATH> settings set network.p2p.bindInterface <NAME>"
        ),
    }
}

pub(crate) fn resolve_p2p_bind_interface_ip(
    interfaces: &[NetworkInterface],
    bind_interface: &str,
) -> Result<Ipv4Addr> {
    let iface = find_unique_interface(interfaces, bind_interface)?;
    let Some(address) = iface
        .addresses
        .iter()
        .find(|address| matches!(address.family, InterfaceAddressFamily::Ipv4))
    else {
        bail!("network.p2p.bindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
    address.address.parse::<Ipv4Addr>().with_context(|| {
        format!(
            "network.p2p.bindInterface {bind_interface:?} resolved to non-IPv4 address {:?}",
            address.address
        )
    })
}

fn find_unique_interface<'a>(
    interfaces: &'a [NetworkInterface],
    bind_interface: &str,
) -> Result<&'a NetworkInterface> {
    let exact_matches = interfaces
        .iter()
        .filter(|iface| iface.name.trim().eq_ignore_ascii_case(bind_interface))
        .collect::<Vec<_>>();
    let matches = if exact_matches.is_empty() {
        interfaces
            .iter()
            .filter(|iface| interface_token_matches(iface, bind_interface))
            .collect::<Vec<_>>()
    } else {
        exact_matches
    };
    let mut matches = matches.into_iter();
    let Some(iface) = matches.next() else {
        bail!("network.p2p.bindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
    if matches.next().is_some() {
        bail!("network.p2p.bindInterface {bind_interface:?} is ambiguous");
    }
    Ok(iface)
}

fn interface_token_matches(iface: &NetworkInterface, bind_interface: &str) -> bool {
    let token = bind_interface.trim().to_ascii_lowercase();
    if token.is_empty() {
        return false;
    }
    iface.name.to_ascii_lowercase().contains(&token)
        || iface
            .description
            .as_deref()
            .is_some_and(|description| description.to_ascii_lowercase().contains(&token))
}

#[cfg(test)]
mod route_intent_tests {
    use super::*;
    use emulebb_ed2k::networking::EgressRoute;

    #[test]
    fn only_unconfigured_and_disabled_off_profile_uses_system_route() {
        let mut profile = DaemonProfile::default();
        assert_eq!(profile.egress_route(), EgressRoute::DirectSystemRoute);
        profile.p2p_bind_interface = Some("  ".into());
        assert_eq!(profile.egress_route(), EgressRoute::DirectSystemRoute);
        profile.p2p_bind_interface = Some("tunnel".into());
        assert_eq!(profile.egress_route(), EgressRoute::StrictInterface);
        profile.p2p_bind_interface = None;
        profile.p2p_bind_ip = Some(Ipv4Addr::LOCALHOST);
        assert_eq!(profile.egress_route(), EgressRoute::StrictInterface);
        profile.p2p_bind_ip = None;
        profile.vpn_guard.enabled = true;
        assert_eq!(profile.egress_route(), EgressRoute::StrictInterface);
        profile.vpn_guard.enabled = false;
        profile.vpn_guard.mode = "block".into();
        assert_eq!(profile.egress_route(), EgressRoute::StrictInterface);
        profile.vpn_guard.mode = "unknown".into();
        assert_eq!(profile.egress_route(), EgressRoute::StrictInterface);
    }
}
