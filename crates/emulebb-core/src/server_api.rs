use super::*;

impl EmulebbCore {
    pub async fn server(&self, endpoint: &str) -> Option<ServerInfo> {
        self.servers()
            .await
            .into_iter()
            .find(|server| server.endpoint.eq_ignore_ascii_case(endpoint))
    }

    pub async fn add_server(&self, request: ServerCreate) -> Result<ServerInfo> {
        let endpoint = server_endpoint_from_create(&request)?;
        let connection = self.ed2k_server_connection_view().await;
        let mut server = server_info_from_parts(
            &request.address,
            request.port,
            request.name.as_deref(),
            None,
            request.static_server.unwrap_or(false),
            connection.0.as_deref(),
            connection.1.as_deref(),
        );
        if let Some(priority) = request.priority.as_deref() {
            server.priority = validate_server_priority(priority)?.to_string();
        }
        server.enabled = true;
        profile_state::persist_server(&self.metadata_store, &server, true)?;
        let mut state = self.state.lock().await;
        state.disabled_servers.remove(&endpoint);
        state.servers.insert(endpoint, server.clone());
        drop(state);
        if request.connect.unwrap_or(false) {
            let _ = self.connect_ed2k_server(&server.endpoint).await?;
        }
        Ok(server)
    }

    pub async fn update_server(
        &self,
        endpoint: &str,
        request: ServerUpdate,
    ) -> Result<Option<ServerInfo>> {
        let Some(mut server) = self.server(endpoint).await else {
            return Ok(None);
        };
        validate_server_update(&request)?;
        apply_server_update(&mut server, Some(&request));
        let mut state = self.state.lock().await;
        let enabled = request
            .enabled
            .unwrap_or_else(|| !state.disabled_servers.contains(&server.endpoint));
        server.enabled = enabled;
        profile_state::persist_server(&self.metadata_store, &server, enabled)?;
        if enabled {
            state.disabled_servers.remove(&server.endpoint);
        } else {
            state.disabled_servers.insert(server.endpoint.clone());
        }
        state
            .servers
            .insert(server.endpoint.clone(), server.clone());
        state
            .server_overrides
            .insert(server.endpoint.clone(), request);
        let disconnect_current = !enabled && server.current;
        drop(state);
        if disconnect_current {
            self.disconnect_ed2k().await;
            return Ok(self.server(&server.endpoint).await);
        }
        Ok(Some(server))
    }

    pub async fn remove_server(&self, endpoint: &str) -> Result<Option<ServerInfo>> {
        let Some(mut server) = self.server(endpoint).await else {
            return Ok(None);
        };
        server.enabled = false;
        profile_state::persist_server(&self.metadata_store, &server, false)?;
        {
            let mut state = self.state.lock().await;
            state
                .servers
                .insert(server.endpoint.clone(), server.clone());
            state.server_overrides.remove(&server.endpoint);
            state.disabled_servers.insert(server.endpoint.clone());
        }
        if server.current {
            self.disconnect_ed2k().await;
        }
        Ok(Some(server))
    }

    /// Merge servers discovered from an `OP_SERVERLIST` reply into the server
    /// store (eMule `CServerSocket::ProcessPacket` OP_SERVERLIST -> AddServer).
    /// New `(ip, port)` servers are added at low priority; existing ones (by
    /// endpoint, including config + dynamic + disabled) are skipped. A
    /// previously dead-dropped server is NOT silently re-added: it stays in
    /// `disabled_servers` so we do not re-add what we just dropped.
    pub(crate) async fn merge_discovered_ed2k_servers(&self, servers: Vec<(Ipv4Addr, u16)>) {
        if servers.is_empty() {
            return;
        }
        // eMule `CServerSocket::ProcessPacket` OP_SERVERLIST adds advertised
        // servers only when `thePrefs.GetAddServersFromServer()` is set (default
        // on). Honor the same preference so an operator can turn auto-add off.
        if !self.state.lock().await.preferences.add_servers_from_server {
            return;
        }
        let existing: HashSet<String> = self
            .servers()
            .await
            .into_iter()
            .map(|server| server.endpoint)
            .collect();
        let disabled: HashSet<String> = {
            let state = self.state.lock().await;
            state.disabled_servers.clone()
        };
        let connection = self.ed2k_server_connection_view().await;
        let mut added = 0usize;
        for (ip, port) in servers {
            if port == 0 {
                continue;
            }
            let endpoint = format!("{ip}:{port}");
            if existing.contains(&endpoint) || disabled.contains(&endpoint) {
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
        }
    }

    /// Resolve a feedback-event endpoint (which may be the configured host:port
    /// or the resolved ip:port) to the matching stored server endpoint key.
    async fn resolve_server_event_endpoint(&self, endpoint: &str) -> Option<String> {
        let servers = self.servers().await;
        // Exact endpoint match first.
        if let Some(server) = servers
            .iter()
            .find(|server| server.endpoint.eq_ignore_ascii_case(endpoint))
        {
            return Some(server.endpoint.clone());
        }
        // Fall back to matching the resolved host:port against each server's
        // configured address (handles a DNS-named server whose event carries the
        // resolved IP, or vice versa, when the literal forms differ).
        let (event_host, event_port) = parse_server_endpoint(endpoint).ok()?;
        servers
            .into_iter()
            .find(|server| {
                server.port == event_port
                    && (server.address == event_host || server.ip == event_host)
            })
            .map(|server| server.endpoint)
    }

    /// Increment a server's consecutive-failure count and drop a non-static dead
    /// server at the `dead_server_retries` threshold (eMule
    /// `CServerList::ServerStats`: `IncFailedCount` + RemoveServer when
    /// `GetFailedCount() >= GetDeadServerRetries()`). Static servers are kept.
    pub(crate) async fn note_ed2k_server_connect_failed(
        &self,
        endpoint: &str,
        dead_server_retries: u32,
    ) {
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
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
            state.server_overrides.remove(&stored_endpoint);
            state.server_fail_counts.remove(&stored_endpoint);
            state.disabled_servers.insert(stored_endpoint.clone());
            drop(state);
            tracing::info!(
                "dropped dead ED2K server {stored_endpoint} (fail_count={fail_count} >= dead_server_retries={threshold})"
            );
        } else {
            tracing::debug!(
                "ED2K server {stored_endpoint} connect failed (fail_count={fail_count}, static={})",
                server_info.static_server
            );
        }
    }

    /// Clear a server's failure count after a successful connect (eMule resets the
    /// count on a successful response/connect).
    pub(crate) async fn note_ed2k_server_connect_succeeded(&self, endpoint: &str) {
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
    ) {
        let Some(stored_endpoint) = self.resolve_server_event_endpoint(endpoint).await else {
            return;
        };
        let Some(mut server) = self.server(&stored_endpoint).await else {
            return;
        };
        if let Some(name) = name {
            server.name = name;
        }
        if let Some(description) = description {
            server.description = description;
        }
        let enabled = !self
            .state
            .lock()
            .await
            .disabled_servers
            .contains(&stored_endpoint);
        server.enabled = enabled;
        let _ = profile_state::persist_server(&self.metadata_store, &server, enabled);
        self.state
            .lock()
            .await
            .servers
            .insert(stored_endpoint, server);
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
