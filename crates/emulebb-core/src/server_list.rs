use std::collections::BTreeMap;

use anyhow::Result;
use emulebb_ed2k::config::{Ed2kConfig, Ed2kServerEntry};

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
            for entry in &network.config.server_entries {
                let endpoint = format!("{}:{}", entry.host, entry.port);
                if state.disabled_servers.contains(&endpoint) {
                    continue;
                }
                let mut server = server_info_from_parts(
                    &entry.host,
                    entry.port,
                    entry.name.as_deref(),
                    entry.description.as_deref(),
                    true,
                    connection.0.as_deref(),
                    connection.1.as_deref(),
                );
                apply_server_update(&mut server, state.server_overrides.get(&endpoint));
                server_map.insert(endpoint, server);
            }
            for endpoint in &network.config.server_endpoints {
                if state.disabled_servers.contains(endpoint) || server_map.contains_key(endpoint) {
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
                    apply_server_update(&mut server, state.server_overrides.get(endpoint));
                    server_map.insert(endpoint.clone(), server);
                }
            }
        }
        for (endpoint, server) in &state.servers {
            if !state.disabled_servers.contains(endpoint) {
                let mut server = server.clone();
                apply_server_update(&mut server, state.server_overrides.get(endpoint));
                apply_server_connection_flags(
                    &mut server,
                    connection.0.as_deref(),
                    connection.1.as_deref(),
                );
                server_map.insert(endpoint.clone(), server);
            }
        }
        if let Some(endpoint) = connection.0.as_deref().or(connection.1.as_deref())
            && let Some(server) = server_map.get_mut(endpoint)
        {
            apply_server_live_details(server, &connection.2);
        }
        server_map.into_values().collect::<Vec<_>>()
    }

    pub(crate) async fn effective_ed2k_config(
        &self,
        base: &Ed2kConfig,
        target_endpoint: Option<&str>,
    ) -> Result<Ed2kConfig> {
        if let Some(target) = target_endpoint {
            let _ = parse_server_endpoint(target)?;
        }
        let mut config = base.clone();
        let state = self.state.lock().await;
        config.reconnect_enabled = state.preferences.reconnect;
        config.safe_server_connect = state.preferences.safe_server_connect;
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
            let exists = config.server_entries.iter().any(|entry| {
                format!("{}:{}", entry.host, entry.port).eq_ignore_ascii_case(endpoint)
            }) || config
                .server_endpoints
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(endpoint));
            if !exists {
                // Carry the full server record (incl. the persisted soft/hard file
                // limits) so the OP_OFFERFILES batch can honor the server's soft
                // limit (server_offer_file_limit) instead of the flat 200 default.
                config.server_entries.push(Ed2kServerEntry {
                    host: server.address.clone(),
                    port: server.port,
                    name: Some(server.name.clone()).filter(|name| !name.is_empty()),
                    description: Some(server.description.clone())
                        .filter(|description| !description.is_empty()),
                    udp_flags: 0,
                    udp_key: 0,
                    udp_key_ip: 0,
                    obfuscation_port_tcp: 0,
                    obfuscation_port_udp: 0,
                    soft_files: u32::try_from(server.soft_files).unwrap_or(u32::MAX),
                    hard_files: u32::try_from(server.hard_files).unwrap_or(u32::MAX),
                });
            }
        }
        Ok(config)
    }
}
