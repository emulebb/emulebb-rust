use std::collections::BTreeMap;

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
}
