use std::net::Ipv4Addr;

use anyhow::{Result, bail};
use emulebb_ed2k::NetworkInterface;

pub(crate) fn ensure_p2p_bind_ip_on_interface(
    interfaces: &[NetworkInterface],
    bind_interface: &str,
    bind_ip: Ipv4Addr,
) -> Result<()> {
    let Some(iface) = interfaces.iter().find(|iface| iface.name == bind_interface) else {
        bail!("p2pBindInterface {bind_interface:?} did not resolve to an IPv4 address");
    };
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
