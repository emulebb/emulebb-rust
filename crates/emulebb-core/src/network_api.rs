use super::*;

impl EmulebbCore {
    pub async fn import_kad_nodes_url(&self, url: &str) -> Result<bool> {
        let url = validate_url_import(url)?;
        match fetch_url_bytes(&url).await {
            Ok(bytes) => Ok(self.import_kad_nodes_bytes(&bytes).await.unwrap_or(0) > 0),
            Err(error) => {
                tracing::warn!("nodes.dat import fetch failed url={url}: {error:#}");
                Ok(false)
            }
        }
    }

    /// Parse a `nodes.dat` payload and add its contacts to the running Kad node.
    pub async fn import_kad_nodes_bytes(&self, data: &[u8]) -> Result<usize> {
        let contacts = emulebb_kad_dht::bootstrap::parse_nodes_dat(data)
            .map_err(|error| anyhow::anyhow!("nodes.dat import failed: {error}"))?;
        ensure!(
            !contacts.is_empty(),
            "nodes.dat contains no usable contacts"
        );

        let path = self
            .ed2k_network
            .as_ref()
            .and_then(|network| network.kad_nodes_dat_path.clone());
        if let Some(path) = path {
            let bytes = data.to_vec();
            tokio::task::spawn_blocking(move || write_nodes_dat_atomic(&path, &bytes))
                .await
                .context("nodes.dat persistence worker failed")??;
        }

        if let Some(dht) = self.ed2k_dht_node().await {
            dht.import_nodes_dat(data)
                .await
                .map_err(|error| anyhow::anyhow!("nodes.dat import failed: {error}"))?;
        }
        Ok(contacts.len())
    }

    pub async fn import_server_met_url(&self, url: &str) -> Result<bool> {
        let url = validate_url_import(url)?;
        match fetch_url_bytes(&url).await {
            Ok(bytes) => Ok(self.import_server_met_bytes(&bytes).await.unwrap_or(0) > 0),
            Err(error) => {
                tracing::warn!("server.met import fetch failed url={url}: {error:#}");
                Ok(false)
            }
        }
    }

    /// Parse a `server.met` payload and add its servers to the server list.
    pub async fn import_server_met_bytes(&self, data: &[u8]) -> Result<usize> {
        let servers = parse_server_met(data)?;
        let mut added = 0usize;
        for server in servers {
            let request = ServerCreate {
                address: server.ip.to_string(),
                port: server.port,
                name: server.name,
                priority: None,
                static_server: None,
                connect: None,
            };
            if self.add_server(request).await.is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    pub async fn recheck_kad_firewall(&self) -> NetworkStatus {
        // Trigger an immediate Kad UDP firewall self-check round when the driver
        // is running, so the REST recheck actually drives a fresh probe instead of
        // only reporting status (oracle CUDPFirewallTester::ReCheckFirewallUDP).
        {
            let runtime = self.ed2k_runtime.lock().await;
            if let Some(signal) = runtime
                .as_ref()
                .and_then(|rt| rt.kad_firewall_recheck.as_ref())
            {
                signal.notify_one();
            }
        }
        // Master parity (kad/recheck_firewall -> PostWebGuiInteraction): the recheck
        // request is "queued" whenever Kad is running, independent of whether the
        // live ed2k networking runtime is up (the GUI accepts the interaction post).
        let mut status = kad_status_from_running(self.state.lock().await.kad_running);
        status.operation_queued = Some(status.running);
        status.already_running = Some(false);
        status
    }

    pub async fn connect_ed2k(&self) -> Result<NetworkStatus> {
        self.connect_ed2k_to_server(None, false).await
    }

    /// Start the application auto-connect lane. This is distinct from the
    /// operator-facing generic connect action because stock applies its
    /// static-server-only preference only to automatic connection attempts.
    pub async fn auto_connect_ed2k(&self) -> Result<NetworkStatus> {
        self.connect_ed2k_to_server(None, true).await
    }

    pub async fn connect_ed2k_server(&self, endpoint: &str) -> Result<Option<NetworkStatus>> {
        let Some(server) = self.server(endpoint).await else {
            return Ok(None);
        };
        if !server.enabled {
            return Ok(None);
        }
        self.connect_ed2k_to_server(Some(endpoint), false)
            .await
            .map(Some)
    }

    async fn connect_ed2k_to_server(
        &self,
        endpoint: Option<&str>,
        automatic_connection: bool,
    ) -> Result<NetworkStatus> {
        tracing::info!(
            endpoint = endpoint.unwrap_or("auto"),
            "ED2K connect requested"
        );
        let core_settings = self.state.lock().await.core_settings.clone();
        // The eD2k network must be enabled (eMule thePrefs.GetNetworkED2K()); when
        // off, the server connect is refused and no eD2k auto-ops run.
        ensure!(
            core_settings.network_ed2k,
            "eD2k network is disabled in settings.core (networkEd2k=false)"
        );
        let kad_network_enabled = core_settings.network_kademlia;
        let guard = self.vpn_guard_status();
        if guard.startup_blocked {
            tracing::warn!(
                reason = %guard.startup_block_reason,
                "ED2K connect blocked by VPN Guard"
            );
            anyhow::bail!("blocked by VPN guard: {}", guard.startup_block_reason);
        }
        let Some(network) = self.ed2k_network.clone() else {
            anyhow::bail!("ED2K network is not configured");
        };
        let config = self.effective_ed2k_config(&network.ed2k, endpoint).await?;
        if config.server_entries.is_empty() && config.server_endpoints.is_empty() {
            anyhow::bail!("ED2K connect requires at least one configured server");
        }

        let mut runtime_guard = self.ed2k_runtime.lock().await;
        if let Some(runtime) = runtime_guard.as_ref() {
            runtime.server_enabled.store(true, Ordering::SeqCst);
            let mut reconnect_needed = false;
            if let Some(endpoint) = endpoint {
                let requested_endpoint = endpoint.parse::<SocketAddr>().ok();
                let same_live_endpoint = {
                    let server_state = runtime.server_state.read().await;
                    requested_endpoint.is_some_and(|requested| {
                        server_state.endpoint == Some(requested)
                            && (server_state.connected || server_state.connecting)
                    })
                };
                *runtime.target_server_endpoint.write().await = Some(endpoint.to_string());
                // WHY: an explicit REST/UI server connect must interrupt the
                // current background session and make the loop try that endpoint
                // next, matching MFC's directed ConnectToServer behavior. Asking
                // for the already-live endpoint is a status-confirming no-op; do
                // not drop a healthy persistent server session just because a
                // controller re-sent the same connect command.
                reconnect_needed = !same_live_endpoint;
            }
            let server_state = runtime.server_state.read().await;
            if !server_state.connected && !server_state.connecting {
                // WHY: REST connect must behave like eMule's explicit connect button.
                // A disconnected background session can otherwise sit in its normal
                // reconnect backoff while the controller observes a no-op response.
                reconnect_needed = true;
            }
            drop(server_state);
            if reconnect_needed {
                runtime.server_reconnect_signal.notify_one();
            }
            drop(runtime_guard);
            let status = self.ed2k_status().await;
            tracing::info!(
                running = status.running,
                connected = status.connected,
                "ED2K connect request applied to running runtime"
            );
            return Ok(status);
        }

        // Start this session's background-download task set from empty (FIX B3):
        // any handles left from a previous session were aborted on disconnect, so
        // a fresh JoinSet keeps the per-session abort scoped and reconnect-safe.
        {
            let mut download_tasks = self.ed2k_download_tasks.lock().await;
            download_tasks.abort_all();
            *download_tasks = JoinSet::new();
        }

        let (search_handle, search_inbox) = new_ed2k_server_search_channel(32);
        let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
        let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
        let kad_buddy = Arc::new(Mutex::new(KadBuddyState::new()));
        // Persistent Kad buddy-socket registry shared by inbound dispatch,
        // listener, outbound buddy link, and buddy-management loop.
        let buddy_registry = BuddySocketRegistry::new();
        // Cancellation handle for the currently-spawned outbound buddy link task
        // (LOWID-G8). The inbound dispatch (handle_kad_find_buddy_res) installs a
        // fresh token when it spawns a link; the buddy-management loop cancels it
        // when the buddy relationship is no longer warranted (HighID / Kad
        // disconnect), so the link + its keepalive pings stop promptly.
        let buddy_link_cancel: Arc<std::sync::Mutex<Option<CancellationToken>>> =
            Arc::new(std::sync::Mutex::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));
        let nat = Arc::new(
            NatManagerBuilder::new(network.nat_config.clone())
                .with_mappings(ed2k_nat_mappings(&network))
                .with_providers(built_in_upnp_port_mapping_providers())
                .build(),
        );
        nat.start().await?;
        // Connection ordering (VPN guard -> UPnP await -> P2P sockets -> connect):
        // the eD2k server login must announce an already-forwarded listen port to
        // win HighID on the FIRST connect, and when UPnP is active the public P2P
        // sockets should not exist before the mapping gate completes. NAT mapping
        // only needs the intended ports, so await one reconcile now (bounded) and
        // copy the gateway-granted external ports into reachability before binding
        // Kad UDP or the eD2K TCP listener. Profiles that intentionally run
        // best-effort can set nat.requireInitialMapping=false.
        if network.nat_config.enabled {
            match tokio::time::timeout(ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT, nat.reconcile_now())
                .await
            {
                Ok(Ok(())) => {
                    let status = nat.status().await;
                    crate::ed2k_net_drivers::sync_advertised_ports_from_nat(
                        &status,
                        &self.ed2k_reachability,
                        network.listen_port,
                        network.kad_bind_addr.port(),
                    );
                    tracing::info!(
                        "UPnP initial reconcile complete before ED2K login: advertised_tcp_port={} advertised_udp_port={}",
                        self.ed2k_reachability
                            .advertised_tcp_port(network.listen_port),
                        self.ed2k_reachability
                            .advertised_udp_port(network.kad_bind_addr.port()),
                    );
                }
                Ok(Err(error)) => {
                    if network.nat_config.require_initial_mapping {
                        let _ = nat.stop().await;
                        bail!("UPnP initial reconcile failed before ED2K/Kad startup: {error:#}");
                    }
                    tracing::warn!(
                        "UPnP initial reconcile failed before ED2K login; connecting with internal ports (may be LowID until UPnP succeeds): {error:#}"
                    );
                }
                Err(_) => {
                    if network.nat_config.require_initial_mapping {
                        let _ = nat.stop().await;
                        bail!(
                            "UPnP initial reconcile timed out after {}s before ED2K/Kad startup",
                            ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT.as_secs()
                        );
                    }
                    tracing::warn!(
                        "UPnP initial reconcile timed out after {}s before ED2K login; connecting with internal ports (may be LowID until UPnP succeeds)",
                        ED2K_UPNP_INITIAL_RECONCILE_TIMEOUT.as_secs(),
                    );
                }
            }
        }
        let configured_bootstrap_endpoints_text =
            configured_kad_bootstrap_endpoints_text(&network.kad_bootstrap_endpoints);
        let kad_bind_if_index =
            emulebb_ed2k::networking::require_bind_if_index(network.bind_ip, "Kad UDP")?;
        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(network.kad_bind_addr),
            obfuscation_enabled: network.ed2k.obfuscation_enabled,
            bootstrap_min_routing_contacts: network.kad_bootstrap_min_routing_contacts.max(1),
            max_concurrent_searches: KAD_SHARED_FILE_PUBLISH_DHT_SEARCH_CAP,
            nodes_dat: current_kad_nodes_dat(&network),
            nodes_text: configured_bootstrap_endpoints_text.clone(),
            class_budgets: kad_rpc_class_budgets(),
            // Pin Kad UDP egress to the VPN bind interface (IP_UNICAST_IF).
            bind_if_index: Some(kad_bind_if_index),
            ..DhtConfig::default()
        })
        .await
        .context("failed to initialize Kad runtime for ED2K listener")?;
        // Bridge the live ed2k IpFilter into the Kad traversal layer so per-RES
        // contacts from filtered/banned IPs are dropped (oracle
        // KademliaUDPListener.cpp:830-857). The IpFilter lives in emulebb-ed2k
        // which depends on emulebb-kad-dht, so core (depending on both) bridges it
        // via a closure hook rather than moving the filter across the boundary.
        {
            let kad_ip_filter = network.ip_filter.clone();
            dht.set_ip_filter(std::sync::Arc::new(move |ip| kad_ip_filter.is_filtered(ip)));
        }
        // Seed `CKadUDPKey` binding state before any bootstrap packet can use a
        // restored key. This may be unknown at startup; the sync task below
        // applies server/STUN changes as reachability learns or clears it.
        dht.set_public_ip_for_udp_keys(self.ed2k_reachability.get())
            .await;
        let ed2k_bind_addr = SocketAddr::new(IpAddr::V4(network.bind_ip), network.listen_port);
        let ed2k_listener =
            Arc::new(TcpListener::bind(ed2k_bind_addr).await.with_context(|| {
                format!("failed to bind eD2k TCP listener on {ed2k_bind_addr}")
            })?);
        let hello_identity = self.ed2k_hello_identity(&network);
        let mut tasks = Vec::new();
        // The Kad socket is also the stock eD2K client-UDP socket. Its receive
        // loop stays active even when Kad routing itself is disabled so
        // OP_PORTTEST and other client-UDP traffic remain reachable.
        tasks.push(dht.clone().start());
        dht.set_running(self.state.lock().await.kad_running);
        {
            tasks.push(tokio::spawn(run_kad_udp_key_public_ip_sync(
                dht.clone(),
                self.ed2k_reachability.clone(),
                Arc::clone(&shutdown),
            )));
        }
        tasks.push(tokio::spawn(hostname_lookup::run_hostname_lookup_loop(
            self.clone(),
            Arc::clone(&shutdown),
        )));
        // "Reconnect now" signal: the advertised-ports sync fires it when the
        // external port changes (UPnP ready / remapped) so the server loop re-logs
        // in with the new HighID callback port instead of waiting for a reconnect.
        let server_reconnect_signal = Arc::new(tokio::sync::Notify::new());
        let server_enabled = Arc::new(AtomicBool::new(true));
        let target_server_endpoint = Arc::new(RwLock::new(endpoint.map(str::to_string)));
        // Keep the advertised external eD2k TCP + UDP ports in sync with the NAT
        // mappings so peers/servers can reach us (incoming TCP + HighID callback)
        // and locate us for UDP source-reask by (ip, udp_port) even when the
        // gateway remaps the external ports.
        tasks.push(tokio::spawn(run_advertised_ports_sync(
            Arc::clone(&nat),
            self.ed2k_reachability.clone(),
            Arc::clone(&server_reconnect_signal),
            network.listen_port,
            network.kad_bind_addr.port(),
            Arc::clone(&shutdown),
        )));
        // Always drive the bootstrap self-lookup, not only when explicit bootstrap
        // nodes are configured: the routing table can be populated from an imported
        // nodes.dat alone, and eMule (`CKademlia::Process`) bootstraps off the
        // table itself. Gating this on configured nodes left a nodes.dat-only node
        // permanently unbootstrapped, so every downstream loop (firewall check,
        // routing maintenance, hello-intro, publish) stayed dormant behind their
        // `is_bootstrapped()` guards and Kad never reached connected.
        if kad_network_enabled {
            tasks.push(tokio::spawn(run_configured_kad_bootstrap(
                dht.clone(),
                Arc::clone(&shutdown),
            )));
        }
        if kad_network_enabled && network.kad_publish_shared_files {
            tasks.push(tokio::spawn(run_kad_shared_file_publish_loop(
                KadPublishLoopRuntime {
                    dht: dht.clone(),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    metadata_store: self.metadata_store.clone(),
                    diagnostics: Arc::clone(&self.kad_publish_diagnostics),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    kad_buddy: Arc::clone(&kad_buddy),
                    network: network.clone(),
                    kad_notes_dirty: Arc::clone(&self.kad_notes_dirty),
                },
                Arc::clone(&shutdown),
            )));
        }
        // Periodic routing-table maintenance (oracle CRoutingZone timers): bucket
        // refresh (OnBigTimer -> RandomLookup) + dead-contact expiry and
        // stale-contact HELLO re-probe (OnSmallTimer).
        if kad_network_enabled && network.kad_routing_maintenance_enabled {
            tasks.push(tokio::spawn(
                kad_routing_maintenance::run_kad_routing_maintenance_loop(
                    dht.clone(),
                    Arc::clone(&ed2k_listener),
                    Arc::clone(&server_state),
                    Arc::clone(&kad_firewall),
                    Arc::clone(&shutdown),
                ),
            ));
        }
        if kad_network_enabled
            && let (Some(kad_local_store), Some(kad_snoop_queue)) = (
                self.kad_local_store.as_ref().map(Arc::clone),
                self.kad_snoop_queue.as_ref().map(Arc::clone),
            )
        {
            tasks.push(tokio::spawn(run_kad_local_store_loop(
                KadLocalStoreRuntime {
                    dht: dht.clone(),
                    local_store: kad_local_store,
                    metadata_store: self.metadata_store.clone(),
                    snoop_queue: Arc::clone(&kad_snoop_queue),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    reachability: self.ed2k_reachability.clone(),
                    kad_buddy: Arc::clone(&kad_buddy),
                    buddy_registry: buddy_registry.clone(),
                    buddy_link_cancel: Arc::clone(&buddy_link_cancel),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    reask_handle: Arc::clone(&self.ed2k_reask_handle),
                    network: network.clone(),
                },
                Arc::clone(&shutdown),
            )));
            tasks.push(tokio::spawn(run_kad_passive_replay_loop(
                dht.clone(),
                Arc::clone(&kad_snoop_queue),
                Arc::clone(&self.index),
                Arc::clone(&self.ed2k_transfers),
                Arc::clone(&shutdown),
                PassiveReplayWorker::Source,
            )));
            tasks.push(tokio::spawn(run_kad_passive_replay_loop(
                dht.clone(),
                kad_snoop_queue,
                Arc::clone(&self.index),
                Arc::clone(&self.ed2k_transfers),
                Arc::clone(&shutdown),
                PassiveReplayWorker::General,
            )));
        }
        // Kad LowID buddy/firewalled-callback driver (default on). It seeks a
        // buddy when we are firewalled; inbound FINDBUDDY/CALLBACK packets are
        // dispatched by the local-store loop above, which owns the same
        // `kad_buddy` state.
        if kad_network_enabled && network.kad_buddy_enabled {
            tasks.push(tokio::spawn(run_kad_buddy_loop(
                KadBuddyRuntime {
                    dht: dht.clone(),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    kad_buddy: Arc::clone(&kad_buddy),
                    buddy_registry: buddy_registry.clone(),
                    buddy_link_cancel: Arc::clone(&buddy_link_cancel),
                    network: network.clone(),
                },
                Arc::clone(&shutdown),
            )));
        }
        let port_test_registry = PortTestRegistry::new();
        tasks.push(tokio::spawn(run_ed2k_listener(Ed2kListenerOptions {
            listener: Arc::clone(&ed2k_listener),
            dht: dht.clone(),
            server_state: Arc::clone(&server_state),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&network.secure_ident),
            transfer_runtime: Arc::clone(&self.ed2k_transfers),
            hello_identity,
            shutdown: Arc::clone(&shutdown),
            ip_filter: network.ip_filter.clone(),
            reachability: self.ed2k_reachability.clone(),
            buddy_registry: buddy_registry.clone(),
            port_test_registry: port_test_registry.clone(),
        })));
        // Learned public-IP cell (eMule theApp public IP), shared by the server
        // loop (sets it from OP_IDCHANGE) and the UDP reask loop (obfuscation key).
        let ed2k_public_ip = self.ed2k_reachability.clone();
        // Select the advertised eD2k client identity (eMule Community by default,
        // or the real emule-rust mod when the operator opts in). Process-wide;
        // read lazily when each hello is encoded.
        set_publish_rust_identity(config.publish_emule_rust_identity);
        let enable_udp_reask = config.enable_udp_reask;
        let reask_user_hash = network.user_hash;
        // Server-list feedback channel (eMule `CServerSocket`/`CServerList`): the
        // session reports discovered servers (OP_SERVERLIST) and connect/ping
        // outcomes; this consumer applies them to the core's persisted store.
        let dead_server_retries = config.dead_server_retries;
        let (server_list_events_tx, server_list_events_rx) = ed2k_server_list_event_channel();
        tasks.push(tokio::spawn(run_ed2k_server_loop(Ed2kServerLoopOptions {
            bind_ip: network.bind_ip,
            nat: Arc::clone(&nat),
            config,
            automatic_connection,
            hello_identity,
            shared_catalog: self.ed2k_transfers.shared_catalog(),
            state: Arc::clone(&server_state),
            search_inbox,
            kad_firewall: Arc::clone(&kad_firewall),
            shutdown: Arc::clone(&shutdown),
            server_enabled: Arc::clone(&server_enabled),
            public_ip: ed2k_public_ip.clone(),
            reconnect_signal: Arc::clone(&server_reconnect_signal),
            target_server_endpoint: Arc::clone(&target_server_endpoint),
            server_list_events: Some(server_list_events_tx),
        })));
        tasks.push(tokio::spawn(
            Self::run_ed2k_shared_catalog_demand_publish_loop(
                self.clone(),
                self.ed2k_transfers.shared_publish_demand_signal(),
                Arc::clone(&shutdown),
            ),
        ));
        tasks.push(tokio::spawn(run_ed2k_server_list_events(
            self.clone(),
            server_list_events_rx,
            dead_server_retries,
            Arc::clone(&shutdown),
        )));
        {
            // udp_version 4 matches our advertised hello ET_UDPVER. The client
            // UDP ingress always runs for OP_PORTTEST; source-reask commands and
            // ticks remain gated by `enable_udp_reask`.
            let (reask_handle, reask_commands) = reask_command_channel();
            if enable_udp_reask {
                *self.ed2k_reask_handle.lock().unwrap() = Some(reask_handle);
            }
            // Typed loop->core event channel (libtorrent-alert style) for re-engage.
            let (reask_events_tx, reask_events_rx) = reask_event_channel();
            tasks.push(tokio::spawn(run_ed2k_udp_reask_loop(
                dht.clone(),
                Arc::clone(&self.ed2k_transfers),
                reask_commands,
                reask_events_tx,
                reask_user_hash,
                4,
                ed2k_public_ip.clone(),
                network.ip_filter.clone(),
                buddy_registry.clone(),
                port_test_registry,
                enable_udp_reask,
                Arc::clone(&shutdown),
            )));
            // Re-engage consumer: when a reask reports a low queue rank, the loop
            // hands the source back and signals here to reconnect over TCP now.
            if enable_udp_reask {
                tasks.push(tokio::spawn(run_ed2k_reask_reengage(
                    self.clone(),
                    reask_events_rx,
                    crate::ed2k_net_drivers::ReaskReengageContext {
                        bind_ip: network.bind_ip,
                        hello_identity,
                        ed2k_listener: Arc::clone(&ed2k_listener),
                        server_state: Arc::clone(&server_state),
                        kad_firewall: Arc::clone(&kad_firewall),
                        direct_callback_limiter: Arc::new(
                            crate::callback_tracker::DirectCallbackRateLimiter::new(),
                        ),
                    },
                    Arc::clone(&shutdown),
                )));
            } else {
                drop(reask_events_rx);
            }
            // Public-IP fallback (H2): the reask obfuscation key is our public IP
            // (eMule EncryptSendClient). It is normally learned from the server
            // (OP_IDCHANGE), but in Kad-only / pre-connect / LowID it is unknown,
            // which would block obfuscated reasks. STUN-probe the data-plane egress
            // and fill it only when still unknown (set_if_unset), so the server
            // path keeps precedence (eMule GetPublicIP order: server, then Kad/STUN).
            if enable_udp_reask {
                tasks.push(tokio::spawn(run_ed2k_public_ip_probe(
                    network.bind_ip,
                    ed2k_public_ip.clone(),
                    Arc::clone(&shutdown),
                )));
            }
            // One-shot NAT-type health signal (STUN mapping-behavior): logs whether
            // our advertised UDP port will match what peers observe (cone) or is
            // fragile (symmetric). Informational; reask degrades to TCP either way.
            if enable_udp_reask {
                tasks.push(tokio::spawn(run_ed2k_nat_type_probe(
                    network.bind_ip,
                    Arc::clone(&shutdown),
                )));
            }
        }
        // Requester-side Kad UDP firewall self-check driver (oracle CUDPFirewallTester).
        // Drives FIREWALLED2_REQ-independent OP_FWCHECKUDPREQ rounds against open
        // v6+ helpers and feeds the peer-confirmed external UDP port back into
        // reachability. Off only when the operator disables it.
        let kad_firewall_recheck = if kad_network_enabled && network.kad_udp_firewall_check_enabled
        {
            let recheck_signal = Arc::new(tokio::sync::Notify::new());
            tasks.push(tokio::spawn(
                kad_udp_firewall_check::run_kad_udp_firewall_check_loop(
                    kad_udp_firewall_check::KadUdpFirewallCheckOptions {
                        dht: dht.clone(),
                        ed2k_listener: Arc::clone(&ed2k_listener),
                        server_state: Arc::clone(&server_state),
                        kad_firewall: Arc::clone(&kad_firewall),
                        reachability: self.ed2k_reachability.clone(),
                        network: network.clone(),
                        recheck_signal: Arc::clone(&recheck_signal),
                        shutdown: Arc::clone(&shutdown),
                    },
                ),
            ));
            Some(recheck_signal)
        } else {
            None
        };
        // Requester-side Kad TCP firewall recheck driver (oracle FirewalledCheck
        // / GetRecheckIP). Asks open v6+ helpers to TCP connect-back via
        // KADEMLIA2_FIREWALLED2_REQ and derives a TCP-firewalled verdict from the
        // open acks + FIREWALLED_RES, so a pure-Kad node (no eD2k server) still
        // detects LowID and seeks a buddy. Off only when the operator disables it.
        if kad_network_enabled && network.kad_tcp_firewall_check_enabled {
            tasks.push(tokio::spawn(
                kad_tcp_firewall_check::run_kad_tcp_firewall_check_loop(
                    kad_tcp_firewall_check::KadTcpFirewallCheckOptions {
                        dht: dht.clone(),
                        ed2k_listener: Arc::clone(&ed2k_listener),
                        server_state: Arc::clone(&server_state),
                        kad_firewall: Arc::clone(&kad_firewall),
                        network: network.clone(),
                        shutdown: Arc::clone(&shutdown),
                    },
                ),
            ));
        }
        *runtime_guard = Some(Ed2kRuntime {
            search_handle,
            server_state,
            server_enabled,
            dht,
            kad_nodes_dat_path: network.kad_nodes_dat_path.clone(),
            kad_firewall: Arc::clone(&kad_firewall),
            nat,
            shutdown,
            server_reconnect_signal,
            target_server_endpoint,
            kad_firewall_recheck,
            tasks,
            download_tasks: Arc::clone(&self.ed2k_download_tasks),
        });
        drop(runtime_guard);
        self.queue_ed2k_shared_catalog_publish();
        let status = self.ed2k_status().await;
        tracing::info!(
            running = status.running,
            connected = status.connected,
            "ED2K runtime started for connect request"
        );
        Ok(status)
    }

    /// Disconnect only the eD2K server session. Kad, the shared UDP socket,
    /// peer transfers, and NAT state remain available for an independent
    /// server reconnect.
    pub async fn disconnect_ed2k_server(&self) -> NetworkStatus {
        let state = {
            let runtime_guard = self.ed2k_runtime.lock().await;
            runtime_guard.as_ref().map(|runtime| {
                runtime.server_enabled.store(false, Ordering::SeqCst);
                runtime.server_reconnect_signal.notify_one();
                Arc::clone(&runtime.server_state)
            })
        };
        if let Some(state) = state {
            *state.write().await = Ed2kServerState::default();
        }
        self.ed2k_status().await
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        // Drop the reask detach handle so post-disconnect downloads stay on TCP
        // and the closed command channel lets the (aborted) loop wind down.
        *self.ed2k_reask_handle.lock().unwrap() = None;
        // FIX (detached-reask lease leak): release every outstanding download
        // source lease. Sources detached onto the reask loop free their lease only
        // via a SourceReleased event, which is never emitted when the loop breaks
        // on shutdown / command-channel close; without this reset those endpoints
        // would stay leased across reconnect and acquire_*_leases would defer them
        // forever. Safe (no race): disconnect fully tears the stack down before any
        // reconnect rebuilds it.
        {
            let mut state = self.state.lock().await;
            for endpoint in state.download_source_registry.reset_leases() {
                state.active_download_peer_endpoints.remove(&endpoint);
            }
        }
        if let Some(runtime) = self.ed2k_runtime.lock().await.take() {
            runtime.shutdown.store(true, Ordering::SeqCst);
            // Capture the final reachability value and persist the live routing
            // sample before aborting the Kad tasks. A write failure must not
            // strand shutdown, but it is visible in logs and the previous file
            // remains intact because replacement is atomic.
            runtime
                .dht
                .set_public_ip_for_udp_keys(self.ed2k_reachability.get())
                .await;
            if let Some(path) = runtime.kad_nodes_dat_path.as_deref() {
                match persist_kad_nodes_dat(&runtime.dht, path).await {
                    Ok(contacts) => tracing::info!(
                        contacts,
                        path = %path.display(),
                        "persisted Kad routing sample"
                    ),
                    Err(error) => tracing::warn!(
                        path = %path.display(),
                        "failed to persist Kad routing sample: {error:#}"
                    ),
                }
            }
            for task in runtime.tasks {
                task.abort();
            }
            // Abort this session's detached background-download tasks (FIX B3) so
            // downloads do not survive disconnect or orphan on shutdown.
            runtime.download_tasks.lock().await.abort_all();
            // WHY: REST disconnect must not hang behind network cleanup after a failed
            // server dial; the runtime has already been removed and tasks aborted.
            let _ = tokio::time::timeout(Duration::from_secs(2), runtime.nat.stop()).await;
        }
        self.ed2k_status().await
    }
}

fn current_kad_nodes_dat(network: &Ed2kNetworkConfig) -> Option<Vec<u8>> {
    let persisted = network
        .kad_nodes_dat_path
        .as_deref()
        .and_then(|path| fs::read(path).ok())
        .filter(|bytes| {
            emulebb_kad_dht::bootstrap::parse_nodes_dat(bytes)
                .is_ok_and(|contacts| !contacts.is_empty())
        });
    persisted.or_else(|| network.kad_nodes_dat.clone())
}

/// Keep persisted Kad receiver-key bindings aligned with the single live
/// public-IP source used by server login, STUN and firewall checks.
async fn run_kad_udp_key_public_ip_sync(
    dht: DhtNode,
    reachability: ExternalReachability,
    shutdown: Arc<AtomicBool>,
) {
    let mut observed = dht.public_ip_for_udp_keys();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !shutdown.load(Ordering::Relaxed) {
        interval.tick().await;
        let current = reachability.get();
        if current != observed {
            dht.set_public_ip_for_udp_keys(current).await;
            observed = current;
        }
    }
}

async fn persist_kad_nodes_dat(dht: &DhtNode, path: &Path) -> Result<usize> {
    let bytes = dht
        .encode_nodes_dat_snapshot()
        .await
        .context("failed to encode live Kad routing sample")?;
    let contacts = bytes
        .get(8..12)
        .and_then(|raw| raw.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or_default() as usize;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || write_nodes_dat_atomic(&path, &bytes))
        .await
        .context("Kad nodes.dat persistence worker failed")??;
    Ok(contacts)
}

fn write_nodes_dat_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().context("nodes.dat path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create nodes.dat directory {}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("nodes.dat path has no UTF-8 file name")?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("failed to create temporary {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write temporary {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary {}", temporary.display()))?;
        drop(file);
        replace_file_atomically(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file_atomically(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file_atomically(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both buffers are NUL-terminated UTF-16 paths and remain alive
    // for the call. MoveFileExW atomically replaces an existing destination on
    // the same volume; the temporary is deliberately created beside it.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod nodes_dat_persistence_tests {
    use super::*;
    use emulebb_kad_proto::{KadUdpKey, NodeId};
    use emulebb_kad_routing::Contact;

    #[tokio::test]
    async fn learned_contact_is_atomically_persisted_and_reloaded_on_restart() {
        let directory =
            std::env::temp_dir().join(format!("emulebb-nodes-dat-restart-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("nodes.dat");
        fs::write(&path, b"previous-valid-destination").unwrap();

        let public_ip: Ipv4Addr = "198.51.100.120".parse().unwrap();
        let peer: SocketAddr = "203.0.113.120:46120".parse().unwrap();
        let node_id = NodeId::from_bytes([0x78; 16]);
        let first = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        first.set_public_ip_for_udp_keys(Some(public_ip)).await;
        first.register_peer_key(peer, 0xA1B2_C3D4);
        let mut learned = Contact::new(node_id, "203.0.113.120".parse().unwrap(), 46120, 46121, 10);
        learned.verified = true;
        first.add_contact(learned).await.unwrap();

        let bytes = first.encode_nodes_dat_snapshot().await.unwrap();
        write_nodes_dat_atomic(&path, &bytes).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);

        let restarted = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            nodes_dat: Some(fs::read(&path).unwrap()),
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let restored = restarted.routing_contacts().await;
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].id, node_id);
        assert_eq!(restored[0].udp_key, KadUdpKey::new(0xA1B2_C3D4));
        assert_eq!(restored[0].udp_key_ip, Some(public_ip));
        assert!(restored[0].verified);
        assert_eq!(restarted.known_peer_key(peer), None);
        restarted.set_public_ip_for_udp_keys(Some(public_ip)).await;
        assert_eq!(
            restarted.known_peer_key(peer),
            Some(KadUdpKey::new(0xA1B2_C3D4))
        );

        drop(restarted);
        drop(first);
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&directory).unwrap();
    }
}
