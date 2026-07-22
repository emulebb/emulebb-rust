use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};

use crate::{EmulebbCore, KadNode, NetworkStatus, kad_status_from_running};

impl EmulebbCore {
    pub async fn set_kad_running(&self, running: bool) {
        self.state.lock().await.kad_running = running;
    }

    pub async fn start_kad(&self) -> Result<NetworkStatus> {
        tracing::info!("Kad start requested");
        // The Kademlia network must be enabled (eMule thePrefs.GetNetworkKademlia());
        // when off, Kad is refused / not started.
        ensure!(
            self.state.lock().await.core_settings.network_kademlia,
            "Kademlia network is disabled in settings.core (networkKademlia=false)"
        );
        let guard = self.vpn_guard_status();
        if guard.startup_blocked {
            tracing::warn!(
                reason = %guard.startup_block_reason,
                "Kad start blocked by VPN Guard"
            );
            anyhow::bail!("blocked by VPN guard: {}", guard.startup_block_reason);
        }
        self.set_kad_running(true).await;
        let status = kad_status_from_running(self.state.lock().await.kad_running);
        tracing::info!(running = status.running, "Kad start accepted");
        Ok(status)
    }

    pub async fn bootstrap_kad(&self, address: &str, port: u16) -> Result<NetworkStatus> {
        ensure!(!address.trim().is_empty(), "address must not be empty");
        ensure!(port != 0, "port must be between 1 and 65535");
        self.start_kad().await
    }

    pub async fn kad_nodes(&self) -> Vec<KadNode> {
        let Some(dht) = self.ed2k_dht_node().await else {
            return Vec::new();
        };
        dht.routing_contacts_snapshot()
            .await
            .into_iter()
            .map(|contact| {
                let resolution = self.host_name_resolution_for_ip(contact.ip);
                KadNode {
                    node_id: contact.node_id,
                    ip: contact.ip.to_string(),
                    host_name: resolution.host_name,
                    host_name_status: resolution.host_name_status,
                    host_name_resolved_at: resolution.host_name_resolved_at,
                    host_name_error: resolution.host_name_error,
                    udp_port: contact.udp_port,
                    tcp_port: contact.tcp_port,
                    kad_version: contact.kad_version,
                    verified: contact.verified,
                    contact_type: contact.contact_type.to_string(),
                    probe_type: contact.probe_type,
                    udp_key_known: contact.udp_key_known,
                    hello_source_udp_port: contact.hello_source_udp_port,
                    udp_firewalled: contact.udp_firewalled,
                    tcp_firewalled: contact.tcp_firewalled,
                    received_hello_packet: contact.received_hello_packet,
                    bootstrap: contact.bootstrap,
                    created_at: DateTime::<Utc>::from(contact.created_at),
                    last_seen: DateTime::<Utc>::from(contact.last_seen),
                }
            })
            .collect()
    }
}
