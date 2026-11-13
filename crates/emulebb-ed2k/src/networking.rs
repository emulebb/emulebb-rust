//! Local network interface inventory and bind selection helpers.

use std::collections::{HashMap, HashSet};
#[cfg(any(target_os = "android", test))]
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::{Context, Result};
use if_addrs::{IfAddr, get_if_addrs};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod windows_routes;

/// Address family for one interface address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceAddressFamily {
    Ipv4,
}

/// One IP address assigned to a local network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterfaceAddress {
    pub family: InterfaceAddressFamily,
    pub address: String,
}

/// Local network interface view used for bind diagnostics and selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub addresses: Vec<NetworkInterfaceAddress>,
    pub is_loopback: bool,
    pub is_vpn_candidate: bool,
    pub has_default_route: bool,
}

/// State of an operator-facing interface binding choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceSelectionState {
    Pending,
    Confirmed,
    Applied,
    Error,
}

/// Persistable interface binding choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceBindingSelection {
    pub bind_interface: Option<String>,
    pub bind_ip: Option<String>,
    pub selection_confirmed: bool,
}

/// Serializable interface binding status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceBindingReport {
    pub recommended_interface_name: Option<String>,
    pub bind_interface: Option<String>,
    pub resolved_bind_ip: Option<String>,
    pub selection_confirmed: bool,
    pub ready: bool,
    pub state: InterfaceSelectionState,
    pub last_error: Option<String>,
}

/// Internal binding status used before conversion to a report.
#[derive(Debug, Clone)]
pub struct ResolvedInterfaceBindingReport {
    pub bind_interface: Option<String>,
    pub bind_ip: Option<String>,
    pub recommended_interface_name: Option<String>,
    pub selection_confirmed: bool,
    pub ready: bool,
    pub state: InterfaceSelectionState,
    pub last_error: Option<String>,
}

/// Combined local network report for control and P2P binding diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkReport {
    #[serde(default)]
    pub interfaces: Vec<NetworkInterface>,
    pub control: InterfaceBindingReport,
    pub p2p: InterfaceBindingReport,
}

/// Returns local network interfaces with address and common routing hints.
pub fn detect_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut by_name = HashMap::<String, NetworkInterface>::new();
    #[cfg(not(target_os = "android"))]
    let default_routes = platform_default_route_interfaces();
    for iface in get_if_addrs()? {
        let IfAddr::V4(ref v4) = iface.addr else {
            continue;
        };
        let description = platform_description(&iface.name);
        let entry = by_name
            .entry(iface.name.clone())
            .or_insert_with(|| NetworkInterface {
                name: iface.name.clone(),
                description,
                addresses: Vec::new(),
                is_loopback: iface.is_loopback(),
                is_vpn_candidate: is_vpn_like(&iface.name),
                has_default_route: false,
            });
        entry.is_vpn_candidate =
            entry.is_vpn_candidate || entry.description.as_deref().is_some_and(is_vpn_like);
        #[cfg(windows)]
        {
            entry.has_default_route = iface
                .index
                .is_some_and(|index| default_routes.contains(&index));
        }
        #[cfg(not(any(windows, target_os = "android")))]
        {
            entry.has_default_route = default_routes.contains(&iface.name);
        }
        entry.addresses.push(NetworkInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: v4.ip.to_string(),
        });
    }

    let mut interfaces = by_name.into_values().collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    #[cfg(target_os = "android")]
    {
        let routes = android_route_hint_interfaces(&interfaces, android_route_source);
        for interface in &mut interfaces {
            interface.has_default_route = routes.contains(&interface.name);
        }
    }
    Ok(interfaces)
}

/// Recommends a bind interface, preferring VPN-looking IPv4 interfaces.
#[must_use]
pub fn recommend_interface(interfaces: &[NetworkInterface]) -> Option<String> {
    interfaces
        .iter()
        .find(|iface| iface.is_vpn_candidate && iface.addresses.iter().any(is_ipv4_address))
        .or_else(|| {
            interfaces.iter().find(|iface| {
                iface.has_default_route
                    && !iface.is_loopback
                    && iface.addresses.iter().any(is_ipv4_address)
            })
        })
        .or_else(|| {
            interfaces
                .iter()
                .find(|iface| !iface.is_loopback && iface.addresses.iter().any(is_ipv4_address))
        })
        .map(|iface| iface.name.clone())
}

/// Resolves a bind IP from an explicit IP override or selected interface name.
#[must_use]
pub fn resolve_bind_ip(
    interfaces: &[NetworkInterface],
    bind_interface: Option<&str>,
    bind_ip_override: Option<&str>,
) -> Option<String> {
    if let Some(bind_ip) = bind_ip_override.map(str::trim).filter(|ip| !ip.is_empty()) {
        return Some(bind_ip.to_string());
    }
    let selected_name = bind_interface?.trim();
    if selected_name.is_empty() {
        return None;
    }
    interfaces
        .iter()
        .find(|iface| iface.name.trim().eq_ignore_ascii_case(selected_name))
        .and_then(|iface| {
            iface
                .addresses
                .iter()
                .find(|address| matches!(address.family, InterfaceAddressFamily::Ipv4))
        })
        .map(|address| address.address.clone())
}

/// Resolves the OS interface index that owns `bind_ip`, for `IP_UNICAST_IF`
/// egress pinning (eMule `ApplyConfiguredIpv4UnicastInterface`). Returns `None`
/// when no local interface advertises that IPv4 address. The index lets the P2P
/// sockets pin egress to the VPN/tunnel interface so split-tunnel routing cannot
/// leak traffic onto the LAN.
#[must_use]
pub fn resolve_bind_if_index(bind_ip: std::net::Ipv4Addr) -> Option<u32> {
    get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|iface| match iface.addr {
            IfAddr::V4(ref v4) if v4.ip == bind_ip => iface.index,
            _ => None,
        })
}

/// Fail-closed bind index resolver for public P2P sockets. A missing index
/// would leave egress unpinned on platforms that support per-socket routing.
pub fn require_bind_if_index(bind_ip: std::net::Ipv4Addr, purpose: &str) -> Result<u32> {
    resolve_bind_if_index(bind_ip)
        .filter(|index| *index != 0)
        .with_context(|| {
            format!("{purpose} bind IP {bind_ip} is not assigned to a local interface")
        })
}

/// Converts a resolved binding to the serializable report shape.
#[must_use]
pub fn build_interface_binding_report(
    binding: &ResolvedInterfaceBindingReport,
) -> InterfaceBindingReport {
    InterfaceBindingReport {
        recommended_interface_name: binding.recommended_interface_name.clone(),
        bind_interface: binding.bind_interface.clone(),
        resolved_bind_ip: binding.bind_ip.clone(),
        selection_confirmed: binding.selection_confirmed,
        ready: binding.ready,
        state: binding.state,
        last_error: binding.last_error.clone(),
    }
}

fn is_ipv4_address(address: &NetworkInterfaceAddress) -> bool {
    matches!(address.family, InterfaceAddressFamily::Ipv4)
}

fn is_vpn_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "tun",
        "tap",
        "wireguard",
        "wg",
        "openvpn",
        "hide.me",
        "nord",
        "proton",
        "tailscale",
        "zerotier",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

#[cfg(windows)]
fn platform_description(interface_name: &str) -> Option<String> {
    ipconfig::get_adapters()
        .ok()?
        .into_iter()
        .find(|adapter| {
            adapter.friendly_name().eq_ignore_ascii_case(interface_name)
                || adapter.adapter_name().eq_ignore_ascii_case(interface_name)
        })
        .map(|adapter| {
            let friendly = adapter.friendly_name().to_string();
            let description = adapter.description().to_string();
            if friendly.eq_ignore_ascii_case(&description) {
                friendly
            } else {
                format!("{friendly} ({description})")
            }
        })
}

#[cfg(not(windows))]
fn platform_description(_interface_name: &str) -> Option<String> {
    None
}

#[cfg(windows)]
fn platform_default_route_interfaces() -> HashSet<u32> {
    match windows_routes::default_route_indices() {
        Ok(indices) => indices,
        Err(error) => {
            // WHY: route inventory failure must be visible without disabling a
            // valid explicit bind, which needs interface addresses, not a default route.
            tracing::warn!(error = ?error, "could not inspect Windows IPv4 default routes; configure an explicit P2P bind interface");
            HashSet::new()
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_default_route_interfaces() -> HashSet<String> {
    std::fs::read_to_string("/proc/net/route")
        .map(|routes| parse_linux_default_route_interfaces(&routes))
        .unwrap_or_default()
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_default_route_interfaces(routes: &str) -> HashSet<String> {
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let columns = line.split_whitespace().collect::<Vec<_>>();
            if columns.len() < 8 {
                return None;
            }
            let destination = u32::from_str_radix(columns[1], 16).ok()?;
            let flags = u32::from_str_radix(columns[3], 16).ok()?;
            let mask = u32::from_str_radix(columns[7], 16).ok()?;
            (destination == 0 && mask == 0 && flags & 1 != 0).then(|| columns[0].to_string())
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn platform_default_route_interfaces() -> HashSet<String> {
    Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_macos_default_route_interface(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_default_route_interface(route: &str) -> HashSet<String> {
    route
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| {
            (key.trim() == "interface")
                .then(|| value.split_whitespace().next().map(str::to_string))
                .flatten()
        })
        .into_iter()
        .collect()
}

#[cfg(target_os = "android")]
fn android_route_source(destination: SocketAddrV4) -> std::io::Result<Ipv4Addr> {
    // WHY: Android restricts route-table access. UDP connect selects the native
    // per-UID kernel route without sending a datagram, DNS query or handshake.
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(destination)?;
    if let std::net::IpAddr::V4(source) = socket.local_addr()?.ip() {
        Ok(source)
    } else {
        Err(std::io::Error::other("route source is not IPv4"))
    }
}

#[cfg(any(target_os = "android", test))]
fn android_route_hint_interfaces(
    interfaces: &[NetworkInterface],
    mut lookup: impl FnMut(SocketAddrV4) -> std::io::Result<Ipv4Addr>,
) -> HashSet<String> {
    // These global references are never contacted. Agreement is a conservative
    // route hint, not Internet reachability or VPN verification. Split routing,
    // unavailable routes and ambiguous inventory must retain explicit binding.
    let sources = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        .map(|reference| lookup(SocketAddrV4::new(reference, 9)));
    let [Ok(source), Ok(other)] = sources else {
        return HashSet::new();
    };
    if source != other
        || source.is_unspecified()
        || source.is_loopback()
        || source.is_multicast()
        || source.is_broadcast()
    {
        return HashSet::new();
    }
    let mut owners = interfaces.iter().filter(|interface| {
        !interface.is_loopback
            && interface.addresses.iter().any(|address| {
                matches!(address.family, InterfaceAddressFamily::Ipv4)
                    && address.address.parse::<Ipv4Addr>().ok() == Some(source)
            })
    });
    let Some(owner) = owners.next() else {
        return HashSet::new();
    };
    if owners.next().is_some() {
        return HashSet::new();
    }
    [owner.name.clone()].into()
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "macos",
    target_os = "android"
)))]
fn platform_default_route_interfaces() -> HashSet<String> {
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::{
        InterfaceAddressFamily, InterfaceSelectionState, NetworkInterface, NetworkInterfaceAddress,
        ResolvedInterfaceBindingReport, android_route_hint_interfaces,
        build_interface_binding_report, parse_linux_default_route_interfaces,
        parse_macos_default_route_interface, recommend_interface, require_bind_if_index,
        resolve_bind_if_index, resolve_bind_ip,
    };
    use if_addrs::IfAddr;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn iface(name: &str, vpn: bool, default_route: bool, ip: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: None,
            addresses: vec![NetworkInterfaceAddress {
                family: InterfaceAddressFamily::Ipv4,
                address: ip.to_string(),
            }],
            is_loopback: false,
            is_vpn_candidate: vpn,
            has_default_route: default_route,
        }
    }

    #[test]
    fn linux_default_route_inventory_requires_an_up_zero_mask_route() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                      eth0 00000000 0100000A 0003 0 0 0 00000000 0 0 0\n\
                      tun0 00000000 00000000 0000 0 0 0 00000000 0 0 0\n\
                      eth1 00000000 00000000 0001 0 0 0 00FFFFFF 0 0 0\n";
        assert_eq!(
            parse_linux_default_route_interfaces(routes),
            ["eth0".to_string()].into()
        );
    }

    #[test]
    fn macos_default_route_inventory_reads_interface_field() {
        let route = "   route to: default\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0\n";
        assert_eq!(
            parse_macos_default_route_interface(route),
            ["en0".to_string()].into()
        );
    }

    #[test]
    fn android_route_hint_queries_only_two_fixed_reference_tuples() {
        let source = Ipv4Addr::new(192, 0, 2, 15);
        let interfaces = [
            iface("vpn-looking", true, false, "10.10.10.2"),
            iface("wlan0", false, false, "192.0.2.15"),
        ];
        let mut queried = Vec::new();
        let routes = android_route_hint_interfaces(&interfaces, |destination| {
            queried.push(destination);
            Ok(source)
        });
        assert_eq!(routes, ["wlan0".to_string()].into());
        assert_eq!(
            queried,
            [
                SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 9),
                SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 9),
            ]
        );
        assert!(
            interfaces
                .iter()
                .all(|interface| !interface.has_default_route)
        );
    }

    #[test]
    fn android_route_hint_accepts_private_kernel_selected_sources() {
        let interfaces = [iface("tun0", true, false, "10.10.10.2")];
        assert_eq!(
            android_route_hint_interfaces(&interfaces, |_| Ok(Ipv4Addr::new(10, 10, 10, 2))),
            ["tun0".to_string()].into()
        );
    }

    #[test]
    fn android_route_hint_requires_both_lookups_to_succeed() {
        let interfaces = [iface("wlan0", false, false, "192.0.2.15")];
        for failing_lookup in [0, 1] {
            let mut calls = 0;
            let routes = android_route_hint_interfaces(&interfaces, |_| {
                let current = calls;
                calls += 1;
                if current == failing_lookup {
                    Err(std::io::ErrorKind::NetworkUnreachable.into())
                } else {
                    Ok(Ipv4Addr::new(192, 0, 2, 15))
                }
            });
            assert!(routes.is_empty());
            assert_eq!(calls, 2);
        }
    }

    #[test]
    fn android_route_hint_rejects_different_per_destination_sources() {
        let interfaces = [
            iface("wlan0", false, false, "192.0.2.15"),
            iface("tun0", true, false, "10.10.10.2"),
        ];
        assert!(
            android_route_hint_interfaces(&interfaces, |destination| {
                Ok(if *destination.ip() == Ipv4Addr::new(1, 1, 1, 1) {
                    Ipv4Addr::new(192, 0, 2, 15)
                } else {
                    Ipv4Addr::new(10, 10, 10, 2)
                })
            })
            .is_empty()
        );
    }

    #[test]
    fn android_route_hint_rejects_non_unicast_or_missing_inventory_sources() {
        for source in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let interfaces = [iface("invalid", false, false, &source.to_string())];
            assert!(android_route_hint_interfaces(&interfaces, |_| Ok(source)).is_empty());
        }
        let source = Ipv4Addr::new(192, 0, 2, 15);
        assert!(android_route_hint_interfaces(&[], |_| Ok(source)).is_empty());
        assert!(
            android_route_hint_interfaces(&[iface("wlan0", false, false, "192.0.2.16")], |_| Ok(
                source
            ))
            .is_empty()
        );
    }

    #[test]
    fn android_route_hint_rejects_ambiguous_or_loopback_ownership() {
        let source = Ipv4Addr::new(192, 0, 2, 15);
        let interfaces = [
            iface("wlan0", false, false, "192.0.2.15"),
            iface("tun0", true, false, "192.0.2.15"),
        ];
        assert!(android_route_hint_interfaces(&interfaces, |_| Ok(source)).is_empty());
        let mut loopback = iface("lo", false, false, "192.0.2.15");
        loopback.is_loopback = true;
        assert!(android_route_hint_interfaces(&[loopback], |_| Ok(source)).is_empty());
    }

    #[test]
    fn android_route_hint_preserves_all_interface_addresses_for_bind_policy() {
        let mut interface = iface("wlan0", false, false, "192.0.2.15");
        interface.addresses.push(NetworkInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: "192.0.2.16".to_string(),
        });
        let before = interface.clone();
        assert_eq!(
            android_route_hint_interfaces(std::slice::from_ref(&interface), |_| {
                Ok(Ipv4Addr::new(192, 0, 2, 15))
            }),
            ["wlan0".to_string()].into()
        );
        assert_eq!(interface, before);
    }

    #[test]
    fn recommend_interface_prefers_vpn() {
        let interfaces = vec![
            iface("Ethernet", false, true, "192.0.2.10"),
            iface("hide.me", true, false, "10.10.10.2"),
        ];

        assert_eq!(recommend_interface(&interfaces).as_deref(), Some("hide.me"));
    }

    #[test]
    fn resolve_bind_ip_prefers_override() {
        let interfaces = vec![iface("hide.me", true, false, "10.10.10.2")];

        assert_eq!(
            resolve_bind_ip(&interfaces, Some("hide.me"), Some(" 10.99.99.2 ")).as_deref(),
            Some("10.99.99.2")
        );
    }

    #[test]
    fn resolve_bind_ip_matches_interface_case_insensitively() {
        let interfaces = vec![iface("hide.me", true, false, "10.10.10.2")];

        assert_eq!(
            resolve_bind_ip(&interfaces, Some(" HIDE.ME "), None).as_deref(),
            Some("10.10.10.2")
        );
    }

    #[test]
    fn resolve_bind_ip_allows_any_override_without_interface_selection() {
        assert_eq!(
            resolve_bind_ip(&[], None, Some("0.0.0.0")).as_deref(),
            Some("0.0.0.0")
        );
    }

    #[test]
    fn resolve_bind_if_index_matches_a_present_address_and_rejects_absent() {
        // An IP not assigned to any local interface resolves to no index.
        assert_eq!(
            resolve_bind_if_index(std::net::Ipv4Addr::new(203, 0, 113, 234)),
            None
        );
        let err = require_bind_if_index(std::net::Ipv4Addr::new(203, 0, 113, 234), "test")
            .expect_err("unassigned bind IP must fail closed");
        assert!(
            err.to_string()
                .contains("not assigned to a local interface")
        );
        // Self-consistency: any V4 address the OS reports (with an index) must
        // resolve back to that same index. Skips hosts where no indexed V4 exists.
        if let Some((ip, index)) = if_addrs::get_if_addrs().ok().and_then(|ifaces| {
            ifaces.into_iter().find_map(|iface| match iface.addr {
                IfAddr::V4(ref v4) => iface.index.map(|idx| (v4.ip, idx)),
                _ => None,
            })
        }) {
            assert_eq!(resolve_bind_if_index(ip), Some(index));
            assert_eq!(require_bind_if_index(ip, "test").unwrap(), index);
        }
    }

    #[test]
    fn build_interface_binding_report_preserves_selection_state() {
        let binding = ResolvedInterfaceBindingReport {
            bind_interface: Some("hide.me".to_string()),
            bind_ip: Some("10.10.10.2".to_string()),
            recommended_interface_name: Some("hide.me".to_string()),
            selection_confirmed: true,
            ready: true,
            state: InterfaceSelectionState::Applied,
            last_error: None,
        };

        let report = build_interface_binding_report(&binding);

        assert!(report.ready);
        assert_eq!(report.bind_interface.as_deref(), Some("hide.me"));
        assert_eq!(report.resolved_bind_ip.as_deref(), Some("10.10.10.2"));
    }
}
