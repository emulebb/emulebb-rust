use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::Result;
use emulebb_ed2k::config::{Ed2kRuntimeConfig, Ed2kServerEntry};
use emulebb_ed2k::ed2k_server::Ed2kServerConnectPlan;
use emulebb_ed2k::ed2k_transfer::Ed2kTransferRuntime;

use super::{
    EmulebbCore, ServerInfo, parse_server_endpoint,
    views::{
        apply_server_connection_flags, apply_server_live_details, apply_server_update,
        server_info_from_parts,
    },
};

impl EmulebbCore {
    pub async fn servers(&self) -> Vec<ServerInfo> {
        let connection = self.ed2k_server_connection_view().await;
        let state = self.state.lock().await;
        let mut server_map = BTreeMap::<String, ServerInfo>::new();
        if let Some(network) = self.ed2k_network.as_ref() {
            for entry in &network.ed2k.server_entries {
                let endpoint = format!("{}:{}", entry.host, entry.port);
                let mut server = server_info_from_parts(
                    &entry.host,
                    entry.port,
                    entry.name.as_deref(),
                    entry.description.as_deref(),
                    entry.static_server,
                    connection.0.as_deref(),
                    connection.1.as_deref(),
                );
                server.priority = entry.normalized_priority().to_string();
                server.enabled = !state.disabled_servers.contains(&endpoint);
                apply_server_update(&mut server, state.server_control_overrides.get(&endpoint));
                server_map.insert(endpoint, server);
            }
            for endpoint in &network.ed2k.server_endpoints {
                if server_map.contains_key(endpoint) {
                    continue;
                }
                if let Ok((address, port)) = parse_server_endpoint(endpoint) {
                    let mut server = server_info_from_parts(
                        &address,
                        port,
                        None,
                        None,
                        true,
                        connection.0.as_deref(),
                        connection.1.as_deref(),
                    );
                    server.enabled = !state.disabled_servers.contains(endpoint);
                    apply_server_update(&mut server, state.server_control_overrides.get(endpoint));
                    server_map.insert(endpoint.clone(), server);
                }
            }
        }
        for (endpoint, server) in &state.servers {
            let mut server = server.clone();
            server.enabled = !state.disabled_servers.contains(endpoint);
            apply_server_update(&mut server, state.server_control_overrides.get(endpoint));
            apply_server_connection_flags(
                &mut server,
                connection.0.as_deref(),
                connection.1.as_deref(),
            );
            server_map.insert(endpoint.clone(), server);
        }
        if let Some(endpoint) = connection.0.as_deref().or(connection.1.as_deref())
            && let Some(server) = server_map.get_mut(endpoint)
        {
            apply_server_live_details(server, &connection.2);
        }
        server_map
            .into_values()
            .map(|mut server| {
                self.apply_hostname_to_server(&mut server);
                server
            })
            .collect::<Vec<_>>()
    }

    pub(crate) async fn effective_ed2k_config(
        &self,
        base: &Ed2kRuntimeConfig,
    ) -> Result<Ed2kRuntimeConfig> {
        effective_config(
            base,
            self.ed2k_network.as_deref(),
            &self.state,
            &self.ed2k_reachability,
            None,
        )
        .await
    }

    pub(crate) async fn refresh_ed2k_server_connect_plan(&self) -> Result<()> {
        ServerPlanPublisher::new(self).refresh().await
    }
}

/// Small retained publication context; it does not keep the Core alive.
#[derive(Clone)]
pub(crate) struct ServerPlanPublisher {
    mutation_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    network: Option<std::sync::Arc<crate::Ed2kNetworkConfig>>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::core_state::CoreState>>,
    runtime: std::sync::Arc<tokio::sync::Mutex<Option<crate::Ed2kRuntime>>>,
    reachability: crate::ExternalReachability,
    transfers: std::sync::Arc<Ed2kTransferRuntime>,
}

impl ServerPlanPublisher {
    pub(crate) fn new(core: &EmulebbCore) -> Self {
        Self {
            mutation_gate: core.server_mutation_gate.clone(),
            network: core.ed2k_network.clone(),
            state: core.state.clone(),
            runtime: core.ed2k_runtime.clone(),
            reachability: core.ed2k_reachability.clone(),
            transfers: core.ed2k_transfers.clone(),
        }
    }

    pub(crate) async fn lock_mutation(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.mutation_gate.clone().lock_owned().await
    }

    pub(crate) async fn refresh(&self) -> Result<()> {
        let Some(network) = self.network.as_ref() else {
            return Ok(());
        };
        let config = effective_config(
            &network.ed2k,
            Some(network),
            &self.state,
            &self.reachability,
            Some(&self.transfers),
        )
        .await?;
        let runtime_guard = self.runtime.lock().await;
        let Some(runtime) = runtime_guard.as_ref() else {
            return Ok(());
        };
        let mode = runtime.server_connect_plan.borrow().mode().clone();
        let next = Ed2kServerConnectPlan::new(config, mode);
        let unchanged = *runtime.server_connect_plan.borrow() == next;
        if !unchanged {
            runtime.server_connect_plan.send_replace(next);
        }
        Ok(())
    }
}

async fn effective_config(
    base: &Ed2kRuntimeConfig,
    network: Option<&crate::Ed2kNetworkConfig>,
    state: &std::sync::Arc<tokio::sync::Mutex<crate::core_state::CoreState>>,
    reachability: &crate::ExternalReachability,
    peer_routes: Option<&Ed2kTransferRuntime>,
) -> Result<Ed2kRuntimeConfig> {
    let mut config = base.clone();
    // Route intent belongs to the active runtime, not persisted server settings.
    config.egress_route = network.map_or(
        emulebb_ed2k::networking::EgressRoute::StrictInterface,
        |network| network.egress_route,
    );
    let state = state.lock().await;
    if let Some(transfers) = peer_routes {
        publish_known_server_endpoints(transfers, base, &state);
    }
    config.server_entries.retain(|entry| {
        let endpoint = format!("{}:{}", entry.host, entry.port);
        !state.disabled_servers.contains(&endpoint)
    });
    config
        .server_endpoints
        .retain(|endpoint| !state.disabled_servers.contains(endpoint));
    // Index only endpoint identity, not rich server metadata. Repeated linear
    // searches would make each directory publication quadratic in catalog size.
    let mut entry_indices = HashMap::with_capacity(config.server_entries.len());
    for (index, entry) in config.server_entries.iter().enumerate() {
        entry_indices
            .entry(format!("{}:{}", entry.host, entry.port).to_ascii_lowercase())
            .or_insert(index);
    }
    for (endpoint, server) in &state.servers {
        if state.disabled_servers.contains(endpoint) {
            continue;
        }
        let persisted = Ed2kServerEntry {
            host: server.address.clone(),
            port: server.port,
            name: Some(server.name.clone()).filter(|name| !name.is_empty()),
            description: Some(server.description.clone())
                .filter(|description| !description.is_empty()),
            dynamic_host: Some(server.dyn_ip.clone()).filter(|host| !host.is_empty()),
            udp_flags: server.udp_flags.unwrap_or_default(),
            udp_key: server.udp_key.unwrap_or_default(),
            udp_key_ip: server.udp_key_ip.unwrap_or_default(),
            obfuscation_port_tcp: server.obfuscation_tcp_port.unwrap_or_default(),
            obfuscation_port_udp: server.obfuscation_udp_port.unwrap_or_default(),
            soft_files: u32::try_from(server.soft_files).unwrap_or(u32::MAX),
            hard_files: u32::try_from(server.hard_files).unwrap_or(u32::MAX),
            priority: server.priority.clone(),
            static_server: server.static_server,
        };
        let identity = endpoint.to_ascii_lowercase();
        if let Some(index) = entry_indices.get(&identity) {
            let existing = &mut config.server_entries[*index];
            // Persisted live metadata supersedes stale static config for the
            // same endpoint while preserving its configured host spelling.
            let host = existing.host.clone();
            *existing = persisted;
            existing.host = host;
        } else {
            // Carry the full persisted record even when `server_endpoints`
            // already names it: configured_server_entries uses this richer
            // record for key/port selection and offer-file limits.
            entry_indices.insert(identity, config.server_entries.len());
            config.server_entries.push(persisted);
        }
    }
    let public_client_id = reachability.get().map(|ip| u32::from_le_bytes(ip.octets()));
    for entry in &mut config.server_entries {
        let key_is_current = entry.udp_key != 0
            && entry.udp_key_ip != 0
            && public_client_id == Some(entry.udp_key_ip);
        if !key_is_current {
            // Keep the binding IP for diagnostics/persistence, but do not
            // offer a stale key to the runtime after a public-IP change.
            entry.udp_key = 0;
        }
    }
    Ok(config)
}

pub(super) fn publish_known_server_endpoints(
    transfers: &Ed2kTransferRuntime,
    base: &Ed2kRuntimeConfig,
    state: &crate::core_state::CoreState,
) {
    let configured = base.server_entries.iter().filter_map(|entry| {
        let key = format!("{}:{}", entry.host, entry.port);
        (!state.disabled_servers.contains(&key)).then_some((entry.host.as_str(), entry.port))
    });
    let numeric_configured = base
        .server_endpoints
        .iter()
        .filter(|endpoint| !state.disabled_servers.contains(endpoint.as_str()))
        .filter_map(|endpoint| endpoint.parse::<SocketAddrV4>().ok());
    // Disabled persisted servers remain known. Deleted rows have no record
    // here, and their tombstone also suppresses stale configuration entries.
    let persisted = state
        .servers
        .values()
        .map(|server| (server.address.as_str(), server.port));
    let from_addresses = configured.chain(persisted).filter_map(|(address, port)| {
        address
            .parse::<Ipv4Addr>()
            .ok()
            .map(|ip| SocketAddrV4::new(ip, port))
    });
    transfers.replace_known_server_endpoints(
        from_addresses
            .chain(numeric_configured)
            .filter(|endpoint| endpoint.port() != 0),
    );
}
