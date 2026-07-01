use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use emulebb_core::vpn_guard::binding_confirmed;
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface};

use crate::DaemonConfig;

impl DaemonConfig {
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
        bail!("p2pBindIp or p2pBindInterface is required when ED2K servers are configured");
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
        bail!("p2pBindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
    address.address.parse::<Ipv4Addr>().with_context(|| {
        format!(
            "p2pBindInterface {bind_interface:?} resolved to non-IPv4 address {:?}",
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
        bail!("p2pBindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
    if matches.next().is_some() {
        bail!("p2pBindInterface {bind_interface:?} is ambiguous");
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
