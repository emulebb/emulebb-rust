use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface};

pub(crate) fn ensure_p2p_bind_ip_on_interface(
    interfaces: &[NetworkInterface],
    bind_interface: &str,
    bind_ip: Ipv4Addr,
) -> Result<()> {
    let iface = find_unique_interface(interfaces, bind_interface)?;
    let bind_ip_text = bind_ip.to_string();
    if iface
        .addresses
        .iter()
        .any(|address| address.address == bind_ip_text)
    {
        return Ok(());
    }
    bail!("p2pBindIp {bind_ip} is not assigned to p2pBindInterface {bind_interface:?}");
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
    let mut matches = interfaces
        .iter()
        .filter(|iface| iface.name.trim().eq_ignore_ascii_case(bind_interface));
    let Some(iface) = matches.next() else {
        bail!("p2pBindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
    if matches.next().is_some() {
        bail!("p2pBindInterface {bind_interface:?} is ambiguous");
    }
    Ok(iface)
}
