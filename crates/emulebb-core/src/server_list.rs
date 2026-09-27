use std::collections::BTreeMap;

use anyhow::Result;
use emulebb_ed2k::config::{Ed2kRuntimeConfig, Ed2kServerEntry};

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
                    true,
                    connection.0.as_deref(),
                    connection.1.as_deref(),
                );
                server.enabled = !state.disabled_servers.contains(&endpoint);
                apply_server_update(&mut server, state.server_overrides.get(&endpoint));
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
                    apply_server_update(&mut server, state.server_overrides.get(endpoint));
                    server_map.insert(endpoint.clone(), server);
                }
            }
        }
        for (endpoint, server) in &state.servers {
            let mut server = server.clone();
            server.enabled = !state.disabled_servers.contains(endpoint);
            apply_server_update(&mut server, state.server_overrides.get(endpoint));
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
        target_endpoint: Option<&str>,
    ) -> Result<Ed2kRuntimeConfig> {
        if let Some(target) = target_endpoint {
            let _ = parse_server_endpoint(target)?;
        }
        let mut config = base.clone();
        let state = self.state.lock().await;
        config.reconnect_enabled = state.core_settings.reconnect;
        config.safe_server_connect = state.core_settings.safe_server_connect;
        config.server_entries.retain(|entry| {
            let endpoint = format!("{}:{}", entry.host, entry.port);
            !state.disabled_servers.contains(&endpoint)
                && target_endpoint.is_none_or(|target| target.eq_ignore_ascii_case(&endpoint))
        });
        config.server_endpoints.retain(|endpoint| {
            !state.disabled_servers.contains(endpoint)
                && target_endpoint.is_none_or(|target| target.eq_ignore_ascii_case(endpoint))
        });
        for (endpoint, server) in &state.servers {
            if state.disabled_servers.contains(endpoint)
                || target_endpoint.is_some_and(|target| !target.eq_ignore_ascii_case(endpoint))
            {
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
            };
            if let Some(existing) = config.server_entries.iter_mut().find(|entry| {
                format!("{}:{}", entry.host, entry.port).eq_ignore_ascii_case(endpoint)
            }) {
                // Persisted live metadata supersedes stale static config for the
                // same endpoint while preserving its configured host spelling.
                let host = existing.host.clone();
                *existing = persisted;
                existing.host = host;
            } else {
                // Carry the full persisted record even when `server_endpoints`
                // already names it: configured_server_entries uses this richer
                // record for key/port selection and offer-file limits.
                config.server_entries.push(persisted);
            }
        }
        let public_client_id = self
            .ed2k_reachability
            .get()
            .map(|ip| u32::from_le_bytes(ip.octets()));
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
}
