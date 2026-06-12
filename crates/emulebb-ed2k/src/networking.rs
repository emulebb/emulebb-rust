//! Local network interface inventory and bind selection helpers.

use std::collections::HashMap;
#[cfg(windows)]
use std::net::IpAddr;

use anyhow::Result;
use if_addrs::{IfAddr, get_if_addrs};
use serde::{Deserialize, Serialize};

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
        entry.has_default_route =
            entry.has_default_route || platform_has_default_route(&iface.name);
        entry.addresses.push(NetworkInterfaceAddress {
            family: InterfaceAddressFamily::Ipv4,
            address: v4.ip.to_string(),
        });
    }

    let mut interfaces = by_name.into_values().collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
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
    if let Some(bind_ip) = bind_ip_override.filter(|ip| !ip.trim().is_empty()) {
        return Some(bind_ip.to_string());
    }
    let selected_name = bind_interface?;
    interfaces
        .iter()
        .find(|iface| iface.name == selected_name)
        .and_then(|iface| {
            iface
                .addresses
                .iter()
                .find(|address| matches!(address.family, InterfaceAddressFamily::Ipv4))
        })
        .map(|address| address.address.clone())
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
        .find(|adapter| adapter.adapter_name() == interface_name)
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
fn platform_has_default_route(interface_name: &str) -> bool {
    ipconfig::get_adapters()
        .ok()
        .into_iter()
        .flatten()
        .find(|adapter| adapter.adapter_name() == interface_name)
        .is_some_and(|adapter| {
            adapter
                .gateways()
                .iter()
                .any(|gateway| *gateway != IpAddr::from([0, 0, 0, 0]))
        })
}

#[cfg(not(windows))]
fn platform_has_default_route(_interface_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{
        InterfaceAddressFamily, InterfaceSelectionState, NetworkInterface, NetworkInterfaceAddress,
        ResolvedInterfaceBindingReport, build_interface_binding_report, recommend_interface,
        resolve_bind_ip,
    };

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
            resolve_bind_ip(&interfaces, Some("hide.me"), Some("10.99.99.2")).as_deref(),
            Some("10.99.99.2")
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
