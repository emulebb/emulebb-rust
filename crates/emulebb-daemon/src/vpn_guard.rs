use std::net::Ipv4Addr;

use emulebb_ed2k::NetworkInterface;

pub(crate) fn binding_confirmed(
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
