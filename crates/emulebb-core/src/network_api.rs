use super::*;

/// Periodic expiry prune cadence for shared in-memory client state, mirroring
/// eMule `CClientList::Process` `BAN_CLEANUP_TIME` = `MIN2MS(20)` (20 minutes).
const ED2K_CLIENT_STATE_PRUNE_INTERVAL: Duration = Duration::from_secs(20 * 60);

struct Ed2kStartupCandidate {
    nat: Option<Arc<NatManager>>,
    reachability: Option<ReachabilityRuntimeLease>,
}

impl Ed2kStartupCandidate {
    fn new(nat: Arc<NatManager>, reachability: &ReachabilityRuntimeAuthority) -> Self {
        Self {
            nat: Some(nat),
            reachability: Some(reachability.begin_runtime()),
        }
    }

    fn nat(&self) -> &Arc<NatManager> {
        self.nat
            .as_ref()
            .expect("ED2K startup candidate must own NAT until installation")
    }

    fn reachability_writer(&self) -> RuntimeReachabilityWriter {
        self.reachability
            .as_ref()
            .expect("ED2K startup candidate must own reachability until installation")
            .writer()
    }

    async fn rollback(mut self, startup_error: anyhow::Error) -> anyhow::Error {
        if let Some(reachability) = self.reachability.as_mut() {
            reachability.retire();
        }
        if let Some(nat) = self.nat.as_ref()
            && let Err(cleanup_error) = nat.stop().await
        {
            tracing::warn!(
                %cleanup_error,
                %startup_error,
                "ED2K startup rollback could not stop NAT cleanly"
            );
        }
        self.nat.take();
        self.reachability.take();
        startup_error
    }

    fn install(mut self) -> (Arc<NatManager>, ReachabilityRuntimeLease) {
        let nat = self
            .nat
            .take()
            .expect("ED2K startup candidate must own NAT until installation");
        let reachability = self
            .reachability
            .take()
            .expect("ED2K startup candidate must own reachability until installation");
        (nat, reachability)
    }
}

async fn retire_ed2k_server_task(mut server_task: JoinHandle<()>) {
    match tokio::time::timeout(ED2K_SERVER_RETIRE_TIMEOUT, &mut server_task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) if error.is_cancelled() => {}
        Ok(Err(error)) => {
            tracing::warn!("ED2K server supervisor failed during retirement: {error}")
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = ED2K_SERVER_RETIRE_TIMEOUT.as_millis(),
                "ED2K server supervisor exceeded retirement deadline; aborting"
            );
            server_task.abort();
            let _ = server_task.await;
        }
    }
}

/// Prune expired ban and tracked-identity entries until shutdown.
async fn run_ed2k_client_state_prune_loop(
    ban_store: Arc<emulebb_ed2k::ban_store::BanStore>,
    tracked_client_identities: Arc<
        emulebb_ed2k::tracked_client_identity::TrackedClientIdentityStore,
    >,
    shutdown: Arc<AtomicBool>,
    interval: Duration,
) {
    run_ed2k_client_state_prune_loop_with_clock(
        ban_store,
        tracked_client_identities,
        shutdown,
        interval,
        std::time::Instant::now,
    )
    .await;
}

async fn run_ed2k_client_state_prune_loop_with_clock(
    ban_store: Arc<emulebb_ed2k::ban_store::BanStore>,
    tracked_client_identities: Arc<
        emulebb_ed2k::tracked_client_identity::TrackedClientIdentityStore,
    >,
    shutdown: Arc<AtomicBool>,
    interval: Duration,
    mut now: impl FnMut() -> std::time::Instant,
) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let now = now();
        ban_store.prune_expired(now);
        tracked_client_identities.prune_expired(now);
    }
}

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
        if let Some(endpoint) = endpoint {
            let _ = parse_server_endpoint(endpoint)?;
        }
        let config = self.effective_ed2k_config(&network.ed2k).await?;
        if config.server_entries.is_empty() && config.server_endpoints.is_empty() {
            anyhow::bail!("ED2K connect requires at least one configured server");
        }
        let connect_mode = match endpoint {
            Some(endpoint) => Ed2kServerConnectMode::Directed(endpoint.to_string()),
            None if automatic_connection => Ed2kServerConnectMode::Automatic,
            None => Ed2kServerConnectMode::Manual,
        };
        let next_connect_plan = Ed2kServerConnectPlan::new(config.clone(), connect_mode);

        let mut runtime_guard = self.ed2k_runtime.lock().await;
        if let Some(runtime) = runtime_guard.as_ref() {
            runtime.server_control.enable();
            let same_live_endpoint = if let Some(endpoint) = endpoint {
                let requested_endpoint = endpoint.parse::<SocketAddr>().ok();
                {
                    let server_state = runtime.server_state.read().await;
                    requested_endpoint.is_some_and(|requested| {
                        server_state.endpoint == Some(requested)
                            && (server_state.connected || server_state.connecting)
                    })
                }
            } else {
                false
            };
            if same_live_endpoint {
                // WHY: a repeated directed connect to the already-live endpoint
                // is a status-confirming no-op, but still refreshes directory and
                // policy data without canceling the healthy session.
                let current = runtime.server_connect_plan.borrow().clone();
                if current != next_connect_plan {
                    runtime.server_connect_plan.send_replace(next_connect_plan);
                }
            } else {
                // A watch publication is both the complete selection generation
                // and the scheduler wakeup. Pending attempts from the previous
                // generation are canceled before the new mode can select a winner.
                runtime.server_connect_plan.send_replace(next_connect_plan);
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

        abort_and_drain_download_tasks(&self.ed2k_download_tasks).await;

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
        let buddy_manager_wake = Arc::new(tokio::sync::Notify::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let startup_candidate = Ed2kStartupCandidate::new(
            Arc::new(
                NatManagerBuilder::new(network.nat_config.clone())
                    .with_mappings(ed2k_nat_mappings(&network))
                    .with_providers(built_in_port_mapping_providers())
                    .build(),
            ),
            &self.ed2k_reachability_authority,
        );
        let reachability_writer = startup_candidate.reachability_writer();
        // Connection ordering (VPN guard -> NAT await -> P2P sockets -> connect):
        // the eD2k server login must announce an already-forwarded listen port to
        // win HighID on the FIRST connect, and when UPnP is active the public P2P
        // sockets should not exist before the mapping gate completes. NAT mapping
        // only needs the intended ports, so await the background task's initial
        // reconcile (bounded) and
        // copy the gateway-granted external ports into reachability before binding
        // Kad UDP or the eD2K TCP listener. Profiles that intentionally run
        // best-effort can set nat.requireInitialMapping=false.
        if network.nat_config.enabled {
            let initial_reconcile = tokio::time::timeout(
                ED2K_NAT_INITIAL_RECONCILE_TIMEOUT,
                startup_candidate.nat().start(),
            )
            .await;
            match initial_reconcile {
                Ok(Ok(())) => {
                    let status = startup_candidate.nat().status().await;
                    crate::ed2k_net_drivers::sync_advertised_ports_from_nat(
                        &status,
                        &reachability_writer,
                        network.listen_port,
                        network.kad_bind_addr.port(),
                    );
                    let ports = self
                        .ed2k_reachability
                        .snapshot()
                        .advertised_ports(network.listen_port, network.kad_bind_addr.port());
                    tracing::info!(
                        "NAT initial reconcile complete before ED2K login: advertised_tcp_port={} advertised_udp_port={}",
                        ports.tcp,
                        ports.udp,
                    );
                }
                Ok(Err(error)) => {
                    if network.nat_config.require_initial_mapping {
                        let error = anyhow::anyhow!(
                            "NAT initial reconcile failed before ED2K/Kad startup: {error:#}"
                        );
                        return Err(startup_candidate.rollback(error).await);
                    }
                    tracing::warn!(
                        "NAT initial reconcile failed before ED2K login; connecting with internal ports (may be LowID until mapping succeeds): {error:#}"
                    );
                }
                Err(_) => {
                    if network.nat_config.require_initial_mapping {
                        let error = anyhow::anyhow!(
                            "NAT initial reconcile timed out after {}s before ED2K/Kad startup",
                            ED2K_NAT_INITIAL_RECONCILE_TIMEOUT.as_secs()
                        );
                        return Err(startup_candidate.rollback(error).await);
                    }
                    tracing::warn!(
                        "NAT initial reconcile timed out after {}s before ED2K login; connecting with internal ports (may be LowID until mapping succeeds)",
                        ED2K_NAT_INITIAL_RECONCILE_TIMEOUT.as_secs(),
                    );
                }
            }
        } else {
            if let Err(error) = startup_candidate.nat().start().await {
                return Err(startup_candidate.rollback(error).await);
            }
        }
        let prerequisites = async {
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
                nodes_text: configured_bootstrap_endpoints_text,
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
            Ok::<_, anyhow::Error>((dht, ed2k_listener))
        }
        .await;
        let (dht, ed2k_listener) = match prerequisites {
            Ok(prerequisites) => prerequisites,
            Err(error) => return Err(startup_candidate.rollback(error).await),
        };
        let (nat, reachability) = startup_candidate.install();
        let hello_identity = self.ed2k_hello_identity(&network);
        let (callback_sessions, callback_session_inbox) = ed2k_callback_session_channel();
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
        // Reclaim expired ban and reconnect-identity entries on the master's
        // shared client-list maintenance cadence (RUST-BUG-115/116).
        tasks.push(tokio::spawn(run_ed2k_client_state_prune_loop(
            self.ed2k_transfers.ban_store(),
            self.ed2k_transfers.tracked_client_identities(),
            Arc::clone(&shutdown),
            ED2K_CLIENT_STATE_PRUNE_INTERVAL,
        )));
        // "Reconnect now" signal: the advertised-ports sync fires it when the
        // external port changes (UPnP ready / remapped) so the server loop re-logs
        // in with the new HighID callback port instead of waiting for a reconnect.
        let (server_control, server_control_rx) = ed2k_server_control_channel(true);
        let (server_connect_plan, server_connect_plan_rx) =
            tokio::sync::watch::channel(next_connect_plan);
        // Keep the advertised external eD2k TCP + UDP ports in sync with the NAT
        // mappings so peers/servers can reach us (incoming TCP + HighID callback)
        // and locate us for UDP source-reask by (ip, udp_port) even when the
        // gateway remaps the external ports.
        tasks.push(tokio::spawn(run_advertised_ports_sync(
            Arc::clone(&nat),
            self.ed2k_reachability.clone(),
            reachability_writer.clone(),
            server_control.clone(),
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
                    reachability_writer: reachability_writer.clone(),
                    kad_buddy: Arc::clone(&kad_buddy),
                    buddy_registry: buddy_registry.clone(),
                    buddy_link_cancel: Arc::clone(&buddy_link_cancel),
                    buddy_manager_wake: Arc::clone(&buddy_manager_wake),
                    transfer_runtime: Arc::clone(&self.ed2k_transfers),
                    callback_sessions: callback_sessions.clone(),
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
                    buddy_manager_wake: Arc::clone(&buddy_manager_wake),
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
            server_search: search_handle.clone(),
            kad_firewall: Arc::clone(&kad_firewall),
            secure_ident: Arc::clone(&network.secure_ident),
            transfer_runtime: Arc::clone(&self.ed2k_transfers),
            hello_identity,
            shutdown: Arc::clone(&shutdown),
            ip_filter: network.ip_filter.clone(),
            reachability: self.ed2k_reachability.clone(),
            buddy_registry: buddy_registry.clone(),
            port_test_registry: port_test_registry.clone(),
            callback_sessions: callback_sessions.clone(),
            callback_session_inbox,
            callback_timeout: Duration::from_secs(network.ed2k.callback_timeout_secs.max(1)),
            detect_tcp_error_flooder: network.ed2k.detect_tcp_error_flooder,
            tcp_error_flooder_interval: Duration::from_secs(
                u64::from(network.ed2k.tcp_error_flooder_interval_minutes).saturating_mul(60),
            ),
            tcp_error_flooder_threshold: network.ed2k.tcp_error_flooder_threshold,
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
        let server_task = tokio::spawn(run_ed2k_server_loop(Ed2kServerLoopOptions {
            bind_ip: network.bind_ip,
            nat: Arc::clone(&nat),
            server_connect_plan: server_connect_plan_rx,
            hello_identity,
            shared_catalog: self.ed2k_transfers.shared_catalog(),
            state: Arc::clone(&server_state),
            search_inbox,
            kad_firewall: Arc::clone(&kad_firewall),
            shutdown: Arc::clone(&shutdown),
            server_control: server_control_rx,
            public_ip: ed2k_public_ip.clone(),
            reachability_writer: reachability_writer.clone(),
            server_list_events: Some(server_list_events_tx),
            callback_sessions: callback_sessions.clone(),
        }));
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
            // Typed client-UDP loop->core event channel (libtorrent-alert style)
            // for source re-engage and direct callbacks.
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
            // Always consume client-UDP events: re-engage events exist only when
            // reask is enabled, while direct callbacks remain independent of that
            // optimization and must be handled whenever Kad is live.
            tasks.push(tokio::spawn(run_ed2k_reask_reengage(
                self.clone(),
                reask_events_rx,
                crate::ed2k_net_drivers::ReaskReengageContext {
                    dht: dht.clone(),
                    callback_sessions: callback_sessions.clone(),
                    ed2k_listener: Arc::clone(&ed2k_listener),
                    server_state: Arc::clone(&server_state),
                    kad_firewall: Arc::clone(&kad_firewall),
                    direct_callback_limiter: Arc::new(
                        crate::callback_tracker::DirectCallbackRateLimiter::new(),
                    ),
                },
                Arc::clone(&shutdown),
            )));
            // Public-IP fallback (H2): the reask obfuscation key is our public IP
            // (eMule EncryptSendClient). It is normally learned from the server
            // (OP_IDCHANGE), but in Kad-only / pre-connect / LowID it is unknown,
            // which would block obfuscated reasks. STUN-probe the data-plane egress
            // and fill it only when still unknown (set_if_unset), so the server
            // path keeps precedence (eMule GetPublicIP order: server, then Kad/STUN).
            if enable_udp_reask || kad_network_enabled {
                tasks.push(tokio::spawn(run_ed2k_public_ip_probe(
                    network.bind_ip,
                    ed2k_public_ip.clone(),
                    reachability_writer.clone(),
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
                        reachability_writer: reachability_writer.clone(),
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
            server_control,
            dht,
            kad_nodes_dat_path: network.kad_nodes_dat_path.clone(),
            kad_firewall: Arc::clone(&kad_firewall),
            reachability,
            nat,
            shutdown,
            server_connect_plan,
            server_task,
            kad_firewall_recheck,
            tasks,
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
    pub async fn disconnect_ed2k_server(&self) -> Result<NetworkStatus> {
        let runtime_guard = self.ed2k_runtime.lock().await;
        if let Some(runtime) = runtime_guard.as_ref() {
            tokio::time::timeout(
                ED2K_SERVER_RETIRE_TIMEOUT,
                runtime.server_control.disable_and_wait(),
            )
            .await
            .context("timed out waiting for ED2K server session retirement")?
            .context("failed to retire ED2K server session")?;
        }
        drop(runtime_guard);
        Ok(self.ed2k_status().await)
    }

    pub async fn disconnect_ed2k(&self) -> NetworkStatus {
        // Drop the reask detach handle so post-disconnect downloads stay on TCP
        // and the closed command channel lets the (aborted) loop wind down.
        *self.ed2k_reask_handle.lock().unwrap() = None;
        if let Some(mut runtime) = self.ed2k_runtime.lock().await.take() {
            let final_public_ip = self.ed2k_reachability.get();
            runtime.reachability.retire();
            runtime.shutdown.store(true, Ordering::SeqCst);
            runtime.server_control.wake_supervisor();
            // Capture the final reachability value and persist the live routing
            // sample before aborting the Kad tasks. A write failure must not
            // strand shutdown, but it is visible in logs and the previous file
            // remains intact because replacement is atomic.
            runtime
                .dht
                .set_public_ip_for_udp_keys(final_public_ip)
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
            let Ed2kRuntime {
                server_task,
                tasks,
                nat,
                ..
            } = runtime;
            retire_ed2k_server_task(server_task).await;
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            // WHY: REST disconnect must not hang behind network cleanup after a failed
            // server dial; the runtime has already been removed and tasks aborted.
            let _ = tokio::time::timeout(Duration::from_secs(2), nat.stop()).await;
        }
        abort_and_drain_download_tasks(&self.ed2k_download_tasks).await;
        // Release detached-reask and active-worker source leases only after every
        // tracked download task has stopped, so no worker can reacquire a lease
        // after the reset while disconnect is still completing.
        {
            let mut state = self.state.lock().await;
            for endpoint in state.download_source_registry.reset_leases() {
                state.active_download_peer_endpoints.remove(&endpoint);
            }
        }
        self.ed2k_status().await
    }
}

async fn abort_and_drain_download_tasks(download_tasks: &Arc<Mutex<JoinSet<()>>>) {
    let mut tasks = download_tasks.lock().await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
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
mod ed2k_startup_candidate_tests {
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use emulebb_ed2k::{
        MappedEndpoint, MappingExposure, MappingSpec, NatConfig, NatStatus, PCP_NATPMP_BACKEND,
        PortMappingProvider, TransportProtocol,
    };

    use super::*;

    struct StartupProvider {
        release_calls: AtomicUsize,
    }

    struct TaskDropProbe(Arc<AtomicBool>);

    impl Drop for TaskDropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl PortMappingProvider for StartupProvider {
        fn name(&self) -> &'static str {
            PCP_NATPMP_BACKEND
        }

        fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            config: &'life1 NatConfig,
            mappings: &'life2 [MappingSpec],
            status: Arc<RwLock<NatStatus>>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                let mut status = status.write().await;
                status.enabled = true;
                status.backend = Some(PCP_NATPMP_BACKEND.to_string());
                status.mappings = mappings
                    .iter()
                    .map(|mapping| MappedEndpoint {
                        name: mapping.name.clone(),
                        protocol: mapping.protocol,
                        local_addr: mapping.local_addr,
                        external_addr: mapping.local_addr,
                        lease_expires_in_secs: config.lease_duration_secs,
                        backend: PCP_NATPMP_BACKEND.to_string(),
                    })
                    .collect();
                Ok(())
            })
        }

        fn release<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            _config: &'life1 NatConfig,
            _mappings: &'life2 [MappedEndpoint],
            _status: Arc<RwLock<NatStatus>>,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async move {
                self.release_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn failed_post_nat_startup_releases_mapping_and_clears_reachability() {
        let provider = Arc::new(StartupProvider {
            release_calls: AtomicUsize::new(0),
        });
        let nat = Arc::new(
            NatManagerBuilder::new(NatConfig {
                enabled: true,
                backend_order: vec![PCP_NATPMP_BACKEND.to_string()],
                lease_duration_secs: 3_600,
                ..NatConfig::default()
            })
            .with_mappings(vec![MappingSpec {
                name: "ed2k_tcp".to_string(),
                local_addr: "192.0.2.10:4662".parse().unwrap(),
                protocol: TransportProtocol::Tcp,
                exposure: MappingExposure::Required,
                preferred_external_port: None,
            }])
            .with_provider(provider.clone())
            .build(),
        );
        let reachability_authority = ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();
        let candidate = Ed2kStartupCandidate::new(nat, &reachability_authority);
        let reachability_writer = candidate.reachability_writer();
        candidate.nat().start().await.unwrap();
        reachability_writer.set_fallback_public_ip(Ipv4Addr::new(203, 0, 113, 10));
        reachability_writer.set_nat_mapped_ports(Some(46_620), Some(46_630));
        reachability_writer.set_peer_confirmed_udp_port(46_640);

        let error = candidate
            .rollback(anyhow::anyhow!("forced post-NAT startup failure"))
            .await;

        assert_eq!(error.to_string(), "forced post-NAT startup failure");
        assert_eq!(provider.release_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            reachability.snapshot(),
            emulebb_ed2k::reachability::ReachabilitySnapshot::default()
        );
        assert_eq!(
            reachability_writer.set_fallback_public_ip(Ipv4Addr::LOCALHOST),
            emulebb_ed2k::reachability::ReachabilityUpdate::RejectedStale
        );
    }

    #[tokio::test]
    async fn reconnect_candidate_rejects_delayed_old_generation_write() {
        let reachability_authority = ReachabilityRuntimeAuthority::new();
        let reachability = reachability_authority.reader();

        let first =
            Ed2kStartupCandidate::new(Arc::new(NatManager::default()), &reachability_authority);
        let first_writer = first.reachability_writer();
        first_writer.set_fallback_public_ip(Ipv4Addr::new(192, 0, 2, 10));
        let (_first_nat, first_lease) = first.install();

        let (release_old_writer, release_old_writer_rx) = tokio::sync::oneshot::channel();
        let delayed_write = tokio::spawn(async move {
            release_old_writer_rx.await.unwrap();
            first_writer.set_fallback_public_ip(Ipv4Addr::new(192, 0, 2, 11))
        });

        let second =
            Ed2kStartupCandidate::new(Arc::new(NatManager::default()), &reachability_authority);
        let second_writer = second.reachability_writer();
        second_writer.set_fallback_public_ip(Ipv4Addr::new(198, 51, 100, 20));
        let (_second_nat, _second_lease) = second.install();

        release_old_writer.send(()).unwrap();
        assert_eq!(
            delayed_write.await.unwrap(),
            emulebb_ed2k::reachability::ReachabilityUpdate::RejectedStale
        );
        drop(first_lease);
        assert_eq!(reachability.get(), Some(Ipv4Addr::new(198, 51, 100, 20)));
    }

    #[tokio::test(start_paused = true)]
    async fn server_retirement_timeout_aborts_and_joins_supervisor() {
        let task_dropped = Arc::new(AtomicBool::new(false));
        let task_dropped_for_task = Arc::clone(&task_dropped);
        let server_task = tokio::spawn(async move {
            let _drop_probe = TaskDropProbe(task_dropped_for_task);
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        let retirement = tokio::spawn(retire_ed2k_server_task(server_task));
        tokio::task::yield_now().await;

        tokio::time::advance(ED2K_SERVER_RETIRE_TIMEOUT + Duration::from_millis(1)).await;
        retirement.await.unwrap();

        assert!(task_dropped.load(Ordering::SeqCst));
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

#[cfg(test)]
mod client_state_prune_tests {
    use super::*;
    use emulebb_ed2k::ban_store::{BanStore, BanStoreRetainedCounts, CLIENT_BAN_TIME};
    use emulebb_ed2k::tracked_client_identity::{
        TrackedClientIdentityObservation, TrackedClientIdentityStore,
    };

    #[tokio::test]
    async fn client_state_prune_loop_reclaims_expired_entries_and_honors_shutdown() {
        const EXPIRED_HASH: [u8; 16] = [1; 16];
        const FRESH_HASH: [u8; 16] = [2; 16];

        let ban_store = Arc::new(BanStore::new());
        let tracked_client_identities = Arc::new(TrackedClientIdentityStore::new());
        let start = std::time::Instant::now();
        let expired_ip = Ipv4Addr::new(192, 0, 2, 10);
        let fresh_ip = Ipv4Addr::new(192, 0, 2, 11);
        ban_store.ban_at(Some(expired_ip), Some(EXPIRED_HASH), start);
        ban_store.ban_at(
            Some(fresh_ip),
            Some(FRESH_HASH),
            start + CLIENT_BAN_TIME - Duration::from_secs(10),
        );
        assert_eq!(
            tracked_client_identities.observe_at(expired_ip, 4_662, EXPIRED_HASH, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            tracked_client_identities.observe_at(
                fresh_ip,
                4_662,
                FRESH_HASH,
                start + CLIENT_BAN_TIME - Duration::from_secs(10),
            ),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            ban_store.retained_entry_counts(),
            BanStoreRetainedCounts {
                ip: 2,
                user_hash: 2,
            }
        );
        assert_eq!(tracked_client_identities.retained_entry_count(), 2);

        let prune_at = start + CLIENT_BAN_TIME + Duration::from_secs(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = tokio::spawn(run_ed2k_client_state_prune_loop_with_clock(
            Arc::clone(&ban_store),
            Arc::clone(&tracked_client_identities),
            Arc::clone(&shutdown),
            Duration::from_millis(5),
            move || prune_at,
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if ban_store.retained_entry_counts()
                    == (BanStoreRetainedCounts {
                        ip: 1,
                        user_hash: 1,
                    })
                    && tracked_client_identities.retained_entry_count() == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("client-state prune loop did not reclaim expired entries");

        assert!(!ban_store.is_banned_at(Some(expired_ip), Some(&EXPIRED_HASH), prune_at));
        assert!(ban_store.is_banned_at(Some(fresh_ip), Some(&FRESH_HASH), prune_at));
        assert_eq!(
            tracked_client_identities.observe_at(fresh_ip, 4_662, EXPIRED_HASH, prune_at),
            TrackedClientIdentityObservation::Changed
        );
        assert_eq!(
            tracked_client_identities.observe_at(expired_ip, 4_662, FRESH_HASH, prune_at),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert!(!handle.is_finished());
        shutdown.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("client-state prune loop did not stop on shutdown")
            .expect("client-state prune loop panicked");
    }
}
