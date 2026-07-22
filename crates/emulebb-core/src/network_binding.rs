//! REST-facing P2P bind status derivation.

use std::net::Ipv4Addr;

use emulebb_ed2k::{InterfaceAddressFamily, NetworkInterface, detect_interfaces};

use crate::{EmulebbCore, VpnGuardStatus, vpn_guard};

/// REST-facing snapshot of the configured and resolved P2P network binding.
#[derive(Debug, Clone, Default)]
pub struct NetworkBindingStatus {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub server_udp_port: u16,
    pub configured_address: String,
    pub configured_interface_id: String,
    pub configured_interface_name: String,
    pub active_configured_address: String,
    pub active_interface_id: String,
    pub active_interface_name: String,
    pub active_interface_index: u32,
    pub resolve_result: String,
}

impl EmulebbCore {
    /// Resolved VPN-guard state for the REST status surfaces.
    pub fn vpn_guard_status(&self) -> VpnGuardStatus {
        let Some(network) = self.ed2k_network.as_ref() else {
            return VpnGuardStatus::off();
        };
        let report = self
            .vpn_guard_egress
            .lock()
            .map(|report| report.clone())
            .unwrap_or_default();
        vpn_guard::status(network, self.ed2k_reachability.get(), &report)
    }

    /// Run the bound dual-plane egress probe (STUN UDP + HTTP TCP) and store the
    /// result, mirroring eMuleBB's `PublicIpProbe` gate: both legs are source-bound
    /// and egress-pinned to the tunnel interface, so the observed public IP is the
    /// real P2P egress. Called by the VPN Guard monitor (startup + runtime). No-op
    /// (records nothing) when there is no resolved bind IP to probe from.
    pub async fn run_vpn_guard_egress_probe(&self) {
        let Some(network) = self.ed2k_network.as_ref() else {
            return;
        };
        // Only probe when there is a public-IP CIDR gate to verify; without one
        // there is nothing to check and no reason to emit external probe traffic.
        if network.vpn_guard.allowed_public_ip_cidrs.trim().is_empty() {
            return;
        }
        let bind_ip = network.bind_ip;
        if bind_ip.is_unspecified() || bind_ip.is_loopback() {
            return;
        }
        let timeout = std::time::Duration::from_secs(6);
        tracing::info!(
            bind_ip = %bind_ip,
            "VPN Guard egress probe starting (STUN UDP and HTTP IPv4)"
        );
        let (stun, http) = tokio::join!(
            emulebb_ed2k::public_ip_probe::stun_probe_bound(bind_ip, timeout),
            emulebb_ed2k::public_ip_probe::http_probe(bind_ip, timeout),
        );
        tracing::info!(
            stun_succeeded = stun.succeeded,
            stun_provider = %stun.provider,
            stun_public_ip = ?stun.public_ip,
            http_succeeded = http.succeeded,
            http_provider = %http.provider,
            http_public_ip = ?http.public_ip,
            "VPN Guard egress probe finished"
        );
        if let Ok(mut report) = self.vpn_guard_egress.lock() {
            *report = vpn_guard::EgressProbeReport { stun, http };
        }
    }

    /// Current configured/resolved P2P binding snapshot for REST status surfaces.
    pub fn network_binding_status(&self) -> Option<NetworkBindingStatus> {
        let network = self.ed2k_network.as_ref()?;
        let configured_address = network
            .p2p_bind_ip
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let configured_interface = network.p2p_bind_interface.clone().unwrap_or_default();
        let (active_interface_name, active_interface_index, resolve_result) =
            resolve_network_binding_snapshot(
                network.p2p_bind_interface.as_deref(),
                network.p2p_bind_ip,
                &detect_interfaces().unwrap_or_default(),
            );
        Some(NetworkBindingStatus {
            tcp_port: network.listen_port,
            udp_port: network.kad_bind_addr.port(),
            // Rust currently uses ephemeral bound sockets for eD2K server UDP
            // helpers, so there is no stable user-configured server UDP port.
            server_udp_port: 0,
            configured_address: configured_address.clone(),
            configured_interface_id: configured_interface.clone(),
            configured_interface_name: configured_interface,
            active_configured_address: configured_address,
            active_interface_id: active_interface_name.clone(),
            active_interface_name,
            active_interface_index,
            resolve_result,
        })
    }
}

fn resolve_network_binding_snapshot(
    bind_interface: Option<&str>,
    bind_ip: Option<Ipv4Addr>,
    interfaces: &[NetworkInterface],
) -> (String, u32, String) {
    let configured_interface = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(configured_interface) = configured_interface else {
        let Some(bind_ip) = bind_ip else {
            return (String::new(), 0, "default".to_string());
        };
        let index = emulebb_ed2k::networking::resolve_bind_if_index(bind_ip).unwrap_or(0);
        let result = if index == 0 {
            "addressnotfound"
        } else {
            "resolved"
        };
        return (String::new(), index, result.to_string());
    };

    let mut matches = interfaces
        .iter()
        .filter(|iface| iface.name.trim().eq_ignore_ascii_case(configured_interface));
    let Some(iface) = matches.next() else {
        return (
            configured_interface.to_string(),
            0,
            "interfacenotfound".to_string(),
        );
    };
    if matches.next().is_some() {
        return (
            configured_interface.to_string(),
            0,
            "interfacenameambiguous".to_string(),
        );
    }

    let Some(first_ipv4) = iface
        .addresses
        .iter()
        .find(|address| matches!(address.family, InterfaceAddressFamily::Ipv4))
    else {
        return (iface.name.clone(), 0, "interfacehasnoaddress".to_string());
    };
    if let Some(bind_ip) = bind_ip {
        let bind_ip_text = bind_ip.to_string();
        if !iface
            .addresses
            .iter()
            .any(|address| address.address == bind_ip_text)
        {
            return (
                iface.name.clone(),
                0,
                "addressnotfoundoninterface".to_string(),
            );
        }
    }

    let resolved_ip = bind_ip
        .or_else(|| first_ipv4.address.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let index = emulebb_ed2k::networking::resolve_bind_if_index(resolved_ip).unwrap_or(0);
    let result = if index == 0 {
        "addressnotfound"
    } else {
        "resolved"
    };
    (iface.name.clone(), index, result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_ed2k::NetworkInterfaceAddress;

    fn iface(name: &str, ip: &str) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: None,
            addresses: vec![NetworkInterfaceAddress {
                family: InterfaceAddressFamily::Ipv4,
                address: ip.to_string(),
            }],
            is_loopback: false,
            is_vpn_candidate: true,
            has_default_route: false,
        }
    }

    #[test]
    fn interface_only_binding_uses_the_named_interface_address() {
        let (name, _index, result) = resolve_network_binding_snapshot(
            Some("hide.me"),
            None,
            &[iface("hide.me", "10.0.0.2")],
        );

        assert_eq!(name, "hide.me");
        assert_eq!(result, "addressnotfound");
    }

    #[test]
    fn interface_and_ip_binding_rejects_mismatch() {
        let (name, index, result) = resolve_network_binding_snapshot(
            Some("hide.me"),
            Some(Ipv4Addr::new(192, 0, 2, 10)),
            &[iface("hide.me", "10.0.0.2")],
        );

        assert_eq!(name, "hide.me");
        assert_eq!(index, 0);
        assert_eq!(result, "addressnotfoundoninterface");
    }

    #[test]
    fn missing_binding_reports_default() {
        let (name, index, result) = resolve_network_binding_snapshot(None, None, &[]);

        assert_eq!(name, "");
        assert_eq!(index, 0);
        assert_eq!(result, "default");
    }
}
