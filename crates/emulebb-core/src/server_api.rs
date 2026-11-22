use super::*;

impl EmulebbCore {
    pub async fn server(&self, endpoint: &str) -> Option<ServerInfo> {
        let (address, port) = parse_server_endpoint(endpoint).ok()?;
        let connection = self.ed2k_server_connection_view().await;
        let mut server = {
            let state = self.state.lock().await;
            // Common feedback reads clone one row, never the whole directory.
            let cached = state.servers.get(endpoint).or_else(|| {
                state
                    .servers
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(endpoint))
                    .map(|(_, row)| row)
            });
            let mut server = if let Some(cached) = cached {
                cached.clone()
            } else {
                let network = self.ed2k_network.as_ref()?;
                let entry =
                    network.ed2k.server_entries.iter().find(|entry| {
                        entry.port == port && entry.host.eq_ignore_ascii_case(&address)
                    });
                if let Some(entry) = entry {
                    let mut server = server_info_from_parts(
                        &entry.host,
                        port,
                        entry.name.as_deref(),
                        entry.description.as_deref(),
                        entry.static_server,
                        None,
                        None,
                    );
                    server.priority = entry.normalized_priority().to_string();
                    server
                } else {
                    let configured = network
                        .ed2k
                        .server_endpoints
                        .iter()
                        .find(|configured| configured.eq_ignore_ascii_case(endpoint))?;
                    let (address, port) = parse_server_endpoint(configured).ok()?;
                    server_info_from_parts(&address, port, None, None, true, None, None)
                }
            };
            server.enabled = !state.disabled_servers.contains(&server.endpoint);
            let update = state.server_control_overrides.get(&server.endpoint);
            crate::views::apply_server_update(&mut server, update);
            server
        };
        crate::views::apply_server_connection_flags(
            &mut server,
            connection.0.as_deref(),
            connection.1.as_deref(),
        );
        if server.current {
            crate::views::apply_server_live_details(&mut server, &connection.2);
        }
        self.apply_hostname_to_server(&mut server);
        Some(server)
    }

    /// Merge servers discovered from an `OP_SERVERLIST` reply into the server
    /// store (eMule `CServerSocket::ProcessPacket` OP_SERVERLIST -> AddServer).
    /// New `(ip, port)` servers are added at low priority; existing ones (by
    /// endpoint, including config + dynamic + disabled) are skipped. A
    /// previously dead-dropped server is NOT silently re-added: it stays in
    /// `disabled_servers` so we do not re-add what we just dropped.
    pub(crate) async fn merge_discovered_ed2k_servers(&self, servers: Vec<(Ipv4Addr, u16)>) {
        let _server_mutation = self.server_mutation_gate.lock().await;
        if servers.is_empty() {
            return;
        }
        // eMule `CServerSocket::ProcessPacket` OP_SERVERLIST adds advertised
        // servers only when `thePrefs.GetAddServersFromServer()` is set. The
        // daemon-resolved eD2K runtime config is the sole owner of that policy.
        if !self
            .ed2k_network
            .as_ref()
            .is_some_and(|network| network.ed2k.add_servers_from_server)
        {
            return;
        }
        let connection = self.ed2k_server_connection_view().await;
        let mut added = 0usize;
        for (ip, port) in servers {
            if port == 0 {
                continue;
            }
            let endpoint = format!("{ip}:{port}");
            let disabled = self.state.lock().await.disabled_servers.contains(&endpoint);
            if disabled || self.server(&endpoint).await.is_some() {
                continue;
            }
            let mut server = server_info_from_parts(
                &ip.to_string(),
                port,
                None,
                None,
                false,
                connection.0.as_deref(),
                connection.1.as_deref(),
            );
            server.priority = "low".to_string();
            if profile_state::persist_server(&self.metadata_store, &server, true).is_err() {
                continue;
            }
            let mut state = self.state.lock().await;
            state.disabled_servers.remove(&endpoint);
            state.servers.insert(endpoint, server);
            drop(state);
            added += 1;
        }
        if added > 0 {
            tracing::info!("added {added} ED2K server(s) discovered via OP_SERVERLIST");
            if let Err(error) = self.refresh_ed2k_server_connect_plan().await {
                tracing::warn!("failed to refresh ED2K server plan after discovery: {error}");
            }
        }
    }

    /// Resolve a feedback-event endpoint (which may be the configured host:port
    /// or the resolved ip:port) to the matching stored server endpoint key.
    async fn resolve_server_event_endpoint(&self, endpoint: &str) -> Option<String> {
        if let Some(server) = self.server(endpoint).await {
            let state = self.state.lock().await;
            // WHY: delayed feedback from a removed runtime endpoint must not
            // recreate a resource from the startup connection configuration.
            return (!state.disabled_servers.contains(&server.endpoint)
                || state.servers.contains_key(&server.endpoint))
            .then_some(server.endpoint);
        }
        // Fall back to matching the resolved host:port against each server's
        // configured address (handles a DNS-named server whose event carries the
        // resolved IP, or vice versa, when the literal forms differ).
        let (event_host, event_port) = parse_server_endpoint(endpoint).ok()?;
        let state = self.state.lock().await;
        state
            .servers
            .values()
            .filter(|server| {
                server.port == event_port
                    && (server.address == event_host || server.ip == event_host)
            })
            .min_by(|left, right| left.endpoint.cmp(&right.endpoint))
            .map(|server| server.endpoint.clone())
    }

    /// Apply classified failure policy before touching durable server health.
    /// Unlike stock eMule's broad Winsock error bucket, local/VPN, timeout,
    /// protocol, and established-session failures remain eligible for retry.
    pub(crate) async fn note_ed2k_server_connection_failed(
        &self,
        endpoint: &str,
        failure: &emulebb_ed2k::ed2k_server::Ed2kServerFailure,
        dead_server_retries: u32,
    ) {
        if !failure.counts_toward_dead_server() {
            tracing::debug!(
                endpoint,
                phase = failure.phase.as_str(),
                reason = failure.reason.as_str(),
                action = "ignored",
                detail = %failure.detail,
                "ignored ED2K server failure for dead-server accounting"
            );
            return;
        }
        tracing::debug!(
            endpoint,
            phase = failure.phase.as_str(),
            reason = failure.reason.as_str(),
            action = "account",
            detail = %failure.detail,
            "accounting ED2K server failure"
        );
        self.note_ed2k_server_connect_failed(endpoint, dead_server_retries)
            .await;
    }

    /// Increment a confirmed-refusal count and drop a non-static dead server at
    /// the configured threshold. Static servers are retained.
    pub(crate) async fn note_ed2k_server_connect_failed(
        &self,
        endpoint: &str,
        dead_server_retries: u32,
    ) {
        let _server_mutation = self.server_mutation_gate.lock().await;
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
            tracing::debug!(
                endpoint,
                action = "unknown_endpoint",
                "ED2K server failure ignored"
            );
            return;
        };
        let Some(mut server_info) = self.server(&stored_endpoint).await else {
            return;
        };
        let threshold = dead_server_retries.max(1);
        let (fail_count, reached) = {
            let mut state = self.state.lock().await;
            let count = state
                .server_fail_counts
                .entry(stored_endpoint.clone())
                .or_insert(0);
            *count += 1;
            let fail_count = *count;
            // Reflect the live fail-count in the dynamic store / REST view.
            if let Some(server) = state.servers.get_mut(&stored_endpoint) {
                server.failed_count = fail_count;
            }
            (fail_count, fail_count >= threshold)
        };
        if reached && !server_info.static_server {
            // eMule drops a dead non-static server from the active list. Keep
            // the row visible as disabled so operators can inspect or re-enable it.
            server_info.failed_count = fail_count;
            server_info.enabled = false;
            let _ = profile_state::persist_server(&self.metadata_store, &server_info, false);
            let mut state = self.state.lock().await;
            state.servers.insert(stored_endpoint.clone(), server_info);
            state.server_control_overrides.remove(&stored_endpoint);
            state.server_fail_counts.remove(&stored_endpoint);
            state.disabled_servers.insert(stored_endpoint.clone());
            drop(state);
            tracing::info!(
                endpoint = %stored_endpoint,
                action = "disabled",
                fail_count,
                threshold,
                "dropped dead ED2K server"
            );
            if let Err(error) = self.refresh_ed2k_server_connect_plan().await {
                tracing::warn!(
                    "failed to refresh ED2K server plan after dead-server drop: {error}"
                );
            }
        } else {
            tracing::debug!(
                endpoint = %stored_endpoint,
                action = if server_info.static_server { "counted_static" } else { "incremented" },
                fail_count,
                threshold,
                static_server = server_info.static_server,
                "recorded ED2K server refusal"
            );
        }
    }

    /// Clear a server's failure count after a successful connect (eMule resets the
    /// count on a successful response/connect).
    pub(crate) async fn note_ed2k_server_connect_succeeded(&self, endpoint: &str) {
        let _server_mutation = self.server_mutation_gate.lock().await;
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
            return;
        };
        let mut state = self.state.lock().await;
        state.server_fail_counts.remove(&stored_endpoint);
        if let Some(server) = state.servers.get_mut(&stored_endpoint) {
            server.failed_count = 0;
        }
    }

    pub(crate) async fn note_ed2k_server_metadata(
        &self,
        endpoint: &str,
        name: Option<String>,
        description: Option<String>,
        dynamic_host: Option<String>,
        version: Option<String>,
        auxiliary_ports: Vec<u16>,
    ) -> Option<String> {
        let _server_mutation = self.server_mutation_gate.lock().await;
        let stored_endpoint = self.resolve_server_event_endpoint(endpoint).await?;
        let mut server = self.server(&stored_endpoint).await?;
        if let Some(name) = name {
            server.name = name;
        }
        if let Some(description) = description {
            server.description = description;
        }
        if let Some(dynamic_host) = dynamic_host {
            server.dyn_ip = dynamic_host;
        }
        if let Some(version) = version {
            server.version = version;
        }
        if !auxiliary_ports.is_empty() {
            server.auxiliary_ports = auxiliary_ports;
        }
        let enabled = !self
            .state
            .lock()
            .await
            .disabled_servers
            .contains(&stored_endpoint);
        server.enabled = enabled;
        if let Err(error) = profile_state::persist_server(&self.metadata_store, &server, enabled) {
            tracing::warn!(
                "failed to persist ED2K server UDP description for {stored_endpoint}: {error}"
            );
            return None;
        }
        self.state
            .lock()
            .await
            .servers
            .insert(stored_endpoint.clone(), server);
        if let Err(error) = self.refresh_ed2k_server_connect_plan().await {
            tracing::warn!("failed to refresh ED2K server plan after metadata update: {error}");
        }
        Some(stored_endpoint)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "flat challenge-validated server status event"
    )]
    pub(crate) async fn note_ed2k_server_status(
        &self,
        endpoint: &str,
        users: u32,
        files: u32,
        max_users: u32,
        low_id_users: u32,
        ping_ms: u32,
        soft_files: u32,
        hard_files: u32,
        udp_flags: u32,
        udp_key: u32,
        udp_key_ip: u32,
        obfuscation_port_tcp: u16,
        obfuscation_port_udp: u16,
    ) -> Option<String> {
        let _server_mutation = self.server_mutation_gate.lock().await;
        let stored_endpoint = self.resolve_server_event_endpoint(endpoint).await?;
        let mut server = self.server(&stored_endpoint).await?;
        server.users = u64::from(users);
        server.files = u64::from(files);
        server.max_users = u64::from(max_users);
        server.low_id_users = u64::from(low_id_users);
        server.ping = ping_ms;
        server.soft_files = u64::from(soft_files);
        server.hard_files = u64::from(hard_files);
        server.udp_flags = (udp_flags != 0).then_some(udp_flags);
        server.udp_key = (udp_key != 0).then_some(udp_key);
        server.udp_key_ip = (udp_key_ip != 0).then_some(udp_key_ip);
        server.obfuscation_tcp_port = (obfuscation_port_tcp != 0).then_some(obfuscation_port_tcp);
        server.obfuscation_udp_port = (obfuscation_port_udp != 0).then_some(obfuscation_port_udp);
        let enabled = !self
            .state
            .lock()
            .await
            .disabled_servers
            .contains(&stored_endpoint);
        server.enabled = enabled;
        if let Err(error) = profile_state::persist_server(&self.metadata_store, &server, enabled) {
            tracing::warn!(
                "failed to persist ED2K server UDP status for {stored_endpoint}: {error}"
            );
            return None;
        }
        self.state
            .lock()
            .await
            .servers
            .insert(stored_endpoint.clone(), server);
        if let Err(error) = self.refresh_ed2k_server_connect_plan().await {
            tracing::warn!("failed to refresh ED2K server plan after status update: {error}");
        }
        Some(stored_endpoint)
    }

    /// Endpoints whose consecutive-failure count is at or over the dead-server
    /// retry threshold, so a UDP source/keyword walk can skip them exactly like
    /// eMule (`GetFailedCount() >= GetDeadServerRetries()`, DownloadQueue.cpp:1798
    /// / ServerList.cpp:265). Non-static servers are dropped from the list on
    /// reaching the threshold, so in practice this surfaces static servers that
    /// keep accumulating failures. Endpoints that do not parse as `ip:port` are
    /// skipped (the walk matches configured entries by resolved address:port).
    pub(crate) async fn ed2k_dead_server_endpoints(
        &self,
        dead_server_retries: u32,
    ) -> Vec<SocketAddr> {
        let threshold = dead_server_retries.max(1);
        let state = self.state.lock().await;
        state
            .server_fail_counts
            .iter()
            .filter(|(_, count)| **count >= threshold)
            .filter_map(|(endpoint, _)| endpoint.parse::<SocketAddr>().ok())
            .collect()
    }
}
