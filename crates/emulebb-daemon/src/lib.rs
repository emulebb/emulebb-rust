use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, VpnGuardConfig};
use emulebb_ed2k::{
    NatConfig,
    config::{Ed2kRuntimeConfig, Ed2kUploadQueueRuntimeConfig},
    detect_interfaces,
    ed2k_tcp::Ed2kSecureIdent,
    ipfilter::IpFilter,
};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};
use emulebb_metadata::{MetadataLocalIdentity, MetadataStore};
use emulebb_rest::{RestConfig, router_with_shutdown};
use emulebb_settings::{
    DaemonRuntimeSettings, Ed2kSettings, Ed2kUploadQueueSettings, IpFilterSettings, KadSettings,
    NatSettings, SECTION_DAEMON_RUNTIME, SECTION_ED2K, SECTION_IP_FILTER, SECTION_KAD, SECTION_NAT,
    SECTION_VPN_GUARD, VpnGuardSettings,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use tokio::sync::watch;
use tracing::info;

mod bind_config;
pub mod log_layer;
pub use log_layer::LogBufferLayer;
mod vpn_guard_monitor;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DaemonConfig {
    pub runtime_dir: PathBuf,
    /// Global finished-file delivery directory (eMule Incoming folder). When a
    /// completed transfer has no category path, its payload is materialized here
    /// by its canonical name. Defaults to `<runtimeDir>/incoming` when unset.
    pub incoming_dir: Option<PathBuf>,
    pub p2p_bind_ip: Option<Ipv4Addr>,
    pub p2p_bind_interface: Option<String>,
    pub ed2k_user_hash: Option<String>,
    pub kad: KadSettings,
    pub kad_bootstrap_endpoints: Vec<String>,
    pub ed2k: Ed2kRuntimeConfig,
    pub nat: NatConfig,
    pub rest: RestListenerConfig,
    pub vpn_guard: VpnGuardSettings,
    pub ip_filter: IpFilterSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct DaemonBootstrapConfig {
    pub runtime_dir: PathBuf,
    pub rest: RestListenerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RestListenerConfig {
    pub bind_addr: Option<SocketAddr>,
    pub api_key: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let runtime = DaemonRuntimeSettings::default();
        Self {
            runtime_dir: PathBuf::from("runtime"),
            incoming_dir: runtime.incoming_dir,
            p2p_bind_ip: runtime.p2p_bind_ip,
            p2p_bind_interface: runtime.p2p_bind_interface,
            ed2k_user_hash: runtime.ed2k_user_hash,
            kad: KadSettings::default(),
            kad_bootstrap_endpoints: Vec::new(),
            ed2k: Ed2kRuntimeConfig::default(),
            nat: NatConfig::default(),
            rest: RestListenerConfig::default(),
            vpn_guard: VpnGuardSettings::default(),
            ip_filter: IpFilterSettings::default(),
        }
    }
}

impl Default for DaemonBootstrapConfig {
    fn default() -> Self {
        Self {
            runtime_dir: PathBuf::from("runtime"),
            rest: RestListenerConfig::default(),
        }
    }
}

impl Default for RestListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            api_key: "change-me".to_string(),
        }
    }
}

impl DaemonConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let path = path.context("--config is required; network bindings must come from config")?;
        if !path.exists() {
            bail!("config file does not exist: {}", path.display());
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let bootstrap: DaemonBootstrapConfig = toml::from_str(&text)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        let metadata = MetadataStore::open(bootstrap.runtime_dir.join("metadata.sqlite"))
            .with_context(|| {
                format!(
                    "failed to open metadata store under {}",
                    bootstrap.runtime_dir.display()
                )
            })?;
        let runtime = load_runtime_settings(&metadata)?;
        let config = Self {
            runtime_dir: bootstrap.runtime_dir,
            incoming_dir: runtime.daemon.incoming_dir,
            p2p_bind_ip: runtime.daemon.p2p_bind_ip,
            p2p_bind_interface: runtime.daemon.p2p_bind_interface,
            ed2k_user_hash: runtime.daemon.ed2k_user_hash,
            kad: runtime.kad,
            kad_bootstrap_endpoints: runtime.kad_bootstrap_endpoints,
            ed2k: runtime.ed2k,
            nat: runtime.nat,
            rest: bootstrap.rest,
            vpn_guard: runtime.vpn_guard,
            ip_filter: runtime.ip_filter,
        };
        config
            .nat
            .validate()
            .context("invalid NAT config in metadata store")?;
        Ok(config)
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.runtime_dir.join("metadata.sqlite")
    }

    pub fn transfer_root(&self) -> PathBuf {
        self.runtime_dir.join("transfers")
    }

    /// Resolve the finished-file delivery directory: the configured
    /// `incomingDir`, or `<runtimeDir>/incoming` by default.
    pub fn incoming_dir(&self) -> PathBuf {
        self.incoming_dir
            .clone()
            .unwrap_or_else(|| self.runtime_dir.join("incoming"))
    }

    pub fn ed2k_network_config(
        &self,
        metadata: &MetadataStore,
    ) -> Result<Option<Ed2kNetworkConfig>> {
        let detected_interfaces =
            detect_interfaces().context("failed to enumerate local interfaces")?;
        self.ed2k_network_config_from_interfaces(metadata, &detected_interfaces)
    }

    pub(crate) fn ed2k_network_config_from_interfaces(
        &self,
        metadata: &MetadataStore,
        detected_interfaces: &[emulebb_ed2k::NetworkInterface],
    ) -> Result<Option<Ed2kNetworkConfig>> {
        if !self.has_network_bootstrap(metadata)? {
            return Ok(None);
        }
        let bind_ip = self.resolve_p2p_bind_ip_from_interfaces(detected_interfaces)?;
        let listen_port = self.resolve_ed2k_listen_port()?;
        let user_hash = match self.ed2k_user_hash.as_deref() {
            Some(value) => {
                let user_hash = parse_user_hash(value)?;
                store_user_hash(metadata, user_hash)?;
                user_hash
            }
            None => load_or_create_user_hash(metadata)?,
        };
        let secure_ident = Arc::new(load_or_create_secure_ident(metadata)?);
        let ip_filter = self.load_ip_filter()?;
        let vpn_interface_bound = self.vpn_binding_confirmed(bind_ip, detected_interfaces);
        Ok(Some(Ed2kNetworkConfig {
            bind_ip,
            kad_bind_addr: self.kad_bind_addr(bind_ip)?,
            listen_port,
            user_hash,
            secure_ident,
            kad_local_store: kad_local_store_config(&self.kad),
            kad_snoop_queue: kad_snoop_queue_config(&self.kad),
            kad_bootstrap_endpoints: self.kad_bootstrap_endpoints.clone(),
            kad_bootstrap_min_routing_contacts: self.kad.bootstrap_min_routing_contacts.max(1),
            kad_publish_shared_files: self.kad.publish_shared_files_enabled,
            kad_republish_interval_secs: self.kad.republish_interval_secs.max(1),
            kad_publish_contact_fanout: self.kad.publish_contact_fanout.max(1),
            kad_udp_firewall_check_enabled: self.kad.udp_firewall_check_enabled,
            kad_udp_firewall_check_interval_secs: self.kad.udp_firewall_check_interval_secs.max(60),
            kad_tcp_firewall_check_enabled: self.kad.tcp_firewall_check_enabled,
            kad_tcp_firewall_check_interval_secs: self.kad.tcp_firewall_check_interval_secs.max(60),
            kad_buddy_enabled: self.kad.buddy_enabled,
            kad_routing_maintenance_enabled: self.kad.routing_maintenance_enabled,
            nat_config: self.nat_config(bind_ip),
            config: self.ed2k.clone(),
            p2p_bind_ip: Some(bind_ip),
            p2p_bind_interface: self.p2p_bind_interface.clone(),
            vpn_guard: VpnGuardConfig {
                enabled: self.vpn_guard.enabled,
                mode: self.vpn_guard.mode.clone(),
                allowed_public_ip_cidrs: self.vpn_guard.allowed_public_ip_cidrs.clone(),
            },
            vpn_interface_bound,
            vpn_interface_bound_runtime: Some(Arc::new(AtomicBool::new(vpn_interface_bound))),
            ip_filter,
            ip_filter_path: self
                .ip_filter
                .enabled
                .then(|| self.ip_filter.path.clone())
                .flatten(),
            ip_filter_level: self.ip_filter.level,
        }))
    }

    fn has_network_bootstrap(&self, metadata: &MetadataStore) -> Result<bool> {
        if !self.kad_bootstrap_endpoints.is_empty() {
            return Ok(true);
        }
        Ok(metadata
            .load_servers()?
            .into_iter()
            .any(|server| server.enabled && server.port != 0 && !server.address.is_empty()))
    }

    /// Loads the configured `ipfilter.dat` into an `IpFilter`. Returns an empty
    /// filter (no filtering) when disabled or no path is configured.
    fn load_ip_filter(&self) -> Result<IpFilter> {
        if !self.ip_filter.enabled {
            return Ok(IpFilter::default());
        }
        let Some(path) = self.ip_filter.path.as_ref() else {
            return Ok(IpFilter::default());
        };
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read ipfilter.dat at {}", path.display()))?;
        let filter = IpFilter::parse(&body, self.ip_filter.level);
        info!(ranges = filter.len(), path = %path.display(), "loaded ip filter");
        Ok(filter)
    }

    pub fn kad_local_store_config(&self) -> KadLocalStoreConfig {
        kad_local_store_config(&self.kad)
    }

    pub fn kad_snoop_queue_config(&self) -> SnoopQueueConfig {
        kad_snoop_queue_config(&self.kad)
    }

    fn kad_bind_addr(&self, bind_ip: Ipv4Addr) -> Result<SocketAddr> {
        let Some(listen_port) = self.kad.listen_port else {
            bail!("kad.listenPort is required when ED2K servers are configured");
        };
        Ok(SocketAddr::new(IpAddr::V4(bind_ip), listen_port))
    }

    fn resolve_ed2k_listen_port(&self) -> Result<u16> {
        let Some(listen_port) = self.ed2k.listen_port else {
            bail!("ed2k.listenPort is required when ED2K servers are configured");
        };
        Ok(listen_port)
    }

    fn nat_config(&self, bind_ip: Ipv4Addr) -> NatConfig {
        let mut nat = self.nat.clone();
        nat.bind_ip.get_or_insert_with(|| bind_ip.to_string());
        nat
    }

    pub fn rest_bind_addr(&self) -> Result<SocketAddr> {
        let Some(candidate) = self.rest.bind_addr else {
            bail!("rest.bindAddr is required");
        };
        Ok(candidate)
    }
}

struct LoadedRuntimeSettings {
    daemon: DaemonRuntimeSettings,
    kad: KadSettings,
    kad_bootstrap_endpoints: Vec<String>,
    ed2k: Ed2kRuntimeConfig,
    nat: NatConfig,
    vpn_guard: VpnGuardSettings,
    ip_filter: IpFilterSettings,
}

fn load_runtime_settings(metadata: &MetadataStore) -> Result<LoadedRuntimeSettings> {
    let daemon = load_section_settings(metadata, SECTION_DAEMON_RUNTIME)
        .context("failed to load daemon.runtime settings")?;
    let kad =
        load_section_settings(metadata, SECTION_KAD).context("failed to load kad settings")?;
    let kad_bootstrap_endpoints = metadata
        .load_kad_bootstrap_endpoints()
        .context("failed to load Kad bootstrap endpoints")?;
    let ed2k_settings: Ed2kSettings =
        load_section_settings(metadata, SECTION_ED2K).context("failed to load ed2k settings")?;
    let nat_settings: NatSettings =
        load_section_settings(metadata, SECTION_NAT).context("failed to load nat settings")?;
    Ok(LoadedRuntimeSettings {
        daemon,
        kad,
        kad_bootstrap_endpoints,
        ed2k: ed2k_runtime_config_from_settings(ed2k_settings),
        nat: nat_config_from_settings(nat_settings),
        vpn_guard: load_section_settings(metadata, SECTION_VPN_GUARD)
            .context("failed to load vpn.guard settings")?,
        ip_filter: load_section_settings(metadata, SECTION_IP_FILTER)
            .context("failed to load ip.filter settings")?,
    })
}

fn load_section_settings<T>(metadata: &MetadataStore, section: &str) -> Result<T>
where
    T: Default + DeserializeOwned,
{
    let mut object = Map::new();
    for (key, value_json) in metadata.load_settings_section(section)? {
        let value = serde_json::from_str::<Value>(&value_json)
            .with_context(|| format!("{section}.{key} contains invalid JSON"))?;
        if object.insert(key.clone(), value).is_some() {
            bail!("duplicate setting row for {section}.{key}");
        }
    }
    if object.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_value(Value::Object(object))
        .with_context(|| format!("invalid settings section {section}"))
}

fn ed2k_runtime_config_from_settings(settings: Ed2kSettings) -> Ed2kRuntimeConfig {
    Ed2kRuntimeConfig {
        listen_port: settings.listen_port,
        server_entries: Vec::new(),
        server_endpoints: Vec::new(),
        obfuscation_enabled: settings.obfuscation_enabled,
        probe_search_term: settings.probe_search_term,
        connect_timeout_secs: settings.connect_timeout_secs,
        server_connect_timeout_secs: settings.server_connect_timeout_secs,
        callback_timeout_secs: settings.callback_timeout_secs,
        reconnect_interval_secs: settings.reconnect_interval_secs,
        reconnect_enabled: settings.reconnect_enabled,
        safe_server_connect: settings.safe_server_connect,
        keepalive_secs: settings.keepalive_secs,
        session_rotation_secs: settings.session_rotation_secs,
        max_concurrent_downloads: settings.max_concurrent_downloads,
        max_new_connections_per_five_seconds: settings.max_new_connections_per_five_seconds,
        max_half_open_connections: settings.max_half_open_connections,
        max_sources_per_file: settings.max_sources_per_file,
        max_parallel_download_peers: settings.max_parallel_download_peers,
        keyword_server_attempt_budget: settings.keyword_server_attempt_budget,
        exact_hash_keyword_server_attempt_budget: settings.exact_hash_keyword_server_attempt_budget,
        source_server_attempt_budget: settings.source_server_attempt_budget,
        upload_queue: ed2k_upload_queue_runtime_config_from_settings(settings.upload_queue),
        download_limit_bytes_per_sec: settings.download_limit_bytes_per_sec,
        enable_udp_reask: settings.enable_udp_reask,
        publish_emule_rust_identity: settings.publish_emule_rust_identity,
        add_servers_from_server: settings.add_servers_from_server,
        dead_server_retries: settings.dead_server_retries,
    }
}

fn ed2k_upload_queue_runtime_config_from_settings(
    settings: Ed2kUploadQueueSettings,
) -> Ed2kUploadQueueRuntimeConfig {
    Ed2kUploadQueueRuntimeConfig {
        active_slots: settings.active_slots,
        elastic_percent: settings.elastic_percent,
        upload_limit_bytes_per_sec: settings.upload_limit_bytes_per_sec,
        elastic_underfill_bytes_per_sec: settings.elastic_underfill_bytes_per_sec,
        elastic_underfill_secs: settings.elastic_underfill_secs,
        waiting_capacity: settings.waiting_capacity,
        waiting_timeout_secs: settings.waiting_timeout_secs,
        granted_timeout_secs: settings.granted_timeout_secs,
        upload_timeout_secs: settings.upload_timeout_secs,
        session_transfer_percent: settings.session_transfer_percent,
        session_time_limit_secs: settings.session_time_limit_secs,
    }
}

fn nat_config_from_settings(settings: NatSettings) -> NatConfig {
    NatConfig {
        enabled: settings.enabled,
        require_initial_mapping: settings.require_initial_mapping,
        backend_order: settings.backend_order,
        bind_ip: settings.bind_ip,
        igd_ip: settings.igd_ip,
        minissdpd_socket: settings.minissdpd_socket,
        ssdp_local_port: settings.ssdp_local_port,
        discovery_timeout_secs: settings.discovery_timeout_secs,
        lease_duration_secs: settings.lease_duration_secs,
        renew_margin_secs: settings.renew_margin_secs,
        external_ip_override: settings.external_ip_override,
    }
}

fn kad_local_store_config(settings: &KadSettings) -> KadLocalStoreConfig {
    KadLocalStoreConfig {
        enabled: settings.local_store_enabled,
        keyword_ttl: std::time::Duration::from_secs(settings.local_store_keyword_ttl_secs.max(1)),
        source_ttl: std::time::Duration::from_secs(settings.local_store_source_ttl_secs.max(1)),
        notes_ttl: std::time::Duration::from_secs(settings.local_store_notes_ttl_secs.max(1)),
        keyword_capacity: settings.local_store_keyword_capacity.max(1),
        source_capacity: settings.local_store_source_capacity.max(1),
        notes_capacity: settings.local_store_notes_capacity.max(1),
        source_per_file_capacity: settings.local_store_source_per_file_capacity.max(1),
        notes_per_file_capacity: settings.local_store_notes_per_file_capacity.max(1),
    }
}

fn kad_snoop_queue_config(settings: &KadSettings) -> SnoopQueueConfig {
    SnoopQueueConfig {
        dedup_window_secs: settings.snoop_queue_dedup_window_secs.max(1),
        general_max_queries_per_600s: settings.snoop_queue_general_max_queries_per_600s.max(1),
        general_drain_cooldown_secs: settings.snoop_queue_general_drain_cooldown_secs.max(1),
        source_max_queries_per_600s: settings.snoop_queue_source_max_queries_per_600s.max(1),
        source_drain_cooldown_secs: settings.snoop_queue_source_drain_cooldown_secs.max(1),
        source_stop_after_results: settings.snoop_queue_source_stop_after_results.max(1),
    }
}

/// Upper bound on the graceful network teardown so a wedged provider can never
/// hang daemon shutdown indefinitely. `disconnect_ed2k` already times the NAT
/// `stop()` out at ~2s; this is a belt-and-braces cap over the whole teardown
/// (lease reset + task aborts + NAT release) in case a future step blocks.
const SHUTDOWN_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait for any shutdown trigger: a REST `POST /app/shutdown` (`shutdown_rx`),
/// Ctrl-C (SIGINT on unix, console close on Windows), or — on unix — SIGTERM
/// (systemd / container stop). Returns once the first trigger fires.
async fn wait_for_shutdown_signal(mut shutdown_rx: watch::Receiver<bool>) {
    let rest_shutdown = async {
        while shutdown_rx.changed().await.is_ok() {
            if *shutdown_rx.borrow() {
                break;
            }
        }
    };

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                // Without a SIGTERM handler we still honour SIGINT and REST; log
                // and continue rather than aborting startup.
                tracing::warn!(%error, "failed to install SIGTERM handler");
                tokio::select! {
                    _ = rest_shutdown => info!("shutdown requested via REST"),
                    result = tokio::signal::ctrl_c() => match result {
                        Ok(()) => info!("shutdown requested via Ctrl-C"),
                        Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
                    },
                }
                return;
            }
        };
        tokio::select! {
            _ = rest_shutdown => info!("shutdown requested via REST"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => info!("shutdown requested via Ctrl-C"),
                Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
            },
            _ = sigterm.recv() => info!("shutdown requested via SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = rest_shutdown => info!("shutdown requested via REST"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => info!("shutdown requested via Ctrl-C"),
                Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
            },
        }
    }
}

/// Ordered, bounded, idempotent network teardown run after the REST server has
/// stopped accepting requests. Releases UPnP/NAT port mappings, aborts the
/// session + detached download tasks, and resets download-source leases via
/// `core.disconnect_ed2k()`. Wrapped in a hard timeout so a wedged provider can
/// never block process exit; `disconnect_ed2k` is itself idempotent (a second
/// call simply finds no runtime), so this is safe to call more than once.
///
/// SQLite is finalised by dropping the last `Arc<EmulebbCore>` once the caller
/// returns: the metadata store commits per write transaction (synchronous=FULL,
/// WAL), so closing the connection on drop is a clean flush with no in-memory
/// state to lose.
async fn graceful_teardown(core: &Arc<EmulebbCore>) {
    info!("running graceful network teardown");
    // Surface the shutdown on GET /api/v1/app for any controller still polling.
    core.begin_shutdown();
    // The shared-directory watcher is process-scoped, not P2P-session-scoped:
    // keep it alive across ED2K/Kad disconnects, but stop it for daemon exit.
    core.stop_shared_directory_monitor();
    match tokio::time::timeout(SHUTDOWN_TEARDOWN_TIMEOUT, core.disconnect_ed2k()).await {
        Ok(_status) => info!("graceful network teardown complete (NAT mappings released)"),
        Err(_) => tracing::warn!(
            timeout_secs = SHUTDOWN_TEARDOWN_TIMEOUT.as_secs(),
            "graceful network teardown timed out; forcing shutdown"
        ),
    }
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    fs::create_dir_all(&config.runtime_dir)
        .with_context(|| format!("failed to create {}", config.runtime_dir.display()))?;
    let index = FileIndex::open(config.metadata_path())?;
    let metadata_store = index.metadata_store();
    let ed2k_network = config.ed2k_network_config(&metadata_store)?;
    let ed2k_network_configured = ed2k_network.is_some();
    let vpn_guard_monitor = ed2k_network
        .as_ref()
        .and_then(vpn_guard_monitor::monitor_config);
    let incoming_dir = config.incoming_dir();
    fs::create_dir_all(&incoming_dir)
        .with_context(|| format!("failed to create incoming dir {}", incoming_dir.display()))?;
    let core = Arc::new(
        EmulebbCore::new_with_network(
            env!("CARGO_PKG_VERSION"),
            index,
            config.transfer_root(),
            ed2k_network,
        )?
        .with_incoming_dir(incoming_dir),
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Keep an owned handle for the post-serve teardown; the router gets a clone.
    let app = router_with_shutdown(
        Arc::clone(&core),
        RestConfig {
            api_key: config.rest.api_key.clone(),
        },
        Some(shutdown_tx.clone()),
    );
    let rest_bind_addr = config.rest_bind_addr()?;
    let listener = tokio::net::TcpListener::bind(rest_bind_addr).await?;
    info!("emulebb-rust REST listening on {}", rest_bind_addr);

    // Start the live auto-pickup monitor first, then run the initial
    // scan-on-demand pickup of files that are already present. Keeping both
    // steps in one detached task avoids the startup race where a file created
    // after a scan pass but before watcher registration could be missed until a
    // later reload. REST is already bound, and hashing remains detached in
    // `reload_shared_directories_detached`, so readiness never waits on a large
    // library hash.
    let sharing_core = Arc::clone(&core);
    tokio::spawn(async move {
        sharing_core.start_shared_directory_monitor().await;
        if let Err(error) = sharing_core.reload_shared_directories_detached().await {
            tracing::warn!(%error, "initial shared-directory scan failed; continuing");
        }
    });
    // Deliver any completed-but-undelivered transfers from a previous run in
    // the background. A persisted sharing profile can carry tens of thousands
    // of manifests, so this sweep starts only after REST is bound and after the
    // sharing workers have been scheduled.
    let delivery_core = Arc::clone(&core);
    tokio::spawn(async move {
        delivery_core.deliver_pending_completed_transfers().await;
    });
    if let Some(monitor) = vpn_guard_monitor {
        tokio::spawn(vpn_guard_monitor::run(Arc::clone(&core), monitor));
    }
    if ed2k_network_configured {
        let connect_core = Arc::clone(&core);
        tokio::spawn(async move {
            if !connect_core.preferences().await.auto_connect {
                return;
            }
            match connect_core.connect_ed2k().await {
                Ok(status) => info!(
                    connected = status.connected,
                    firewalled = status.firewalled.unwrap_or(false),
                    "automatic ED2K/Kad startup complete"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    "automatic ED2K/Kad startup failed; REST connect remains available"
                ),
            }
            // Resume persisted incomplete downloads now that ED2K/Kad are up so
            // source acquisition can succeed. In-progress downloads from a prior
            // run are otherwise abandoned (state.transfers starts empty).
            let resumed = connect_core.resume_persisted_downloads().await;
            if resumed > 0 {
                info!(resumed, "resumed persisted incomplete downloads on startup");
            }
        });
    }
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown_signal(shutdown_rx))
        .await;
    // Whatever stopped the server (REST shutdown, Ctrl-C, or SIGTERM), tear the
    // network stack down cleanly before exiting so port mappings are released
    // and SQLite finalises. Done unconditionally, even on a serve error.
    graceful_teardown(&core).await;
    serve_result?;
    Ok(())
}

fn parse_user_hash(value: &str) -> Result<[u8; 16]> {
    let decoded = hex::decode(value.trim()).context("failed to decode ed2kUserHash")?;
    let bytes: [u8; 16] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed2kUserHash must be 16 bytes / 32 hex characters"))?;
    let bytes = normalize_user_hash_markers(bytes);
    if user_hash_is_bad(&bytes) {
        bail!("ed2kUserHash must not be an eMule bad hash");
    }
    Ok(bytes)
}

const ED2K_USER_HASH_IDENTITY_KIND: &str = "ed2k-user-hash";
const ED2K_SECURE_IDENT_IDENTITY_KIND: &str = "ed2k-secure-ident";

fn load_or_create_user_hash(metadata: &MetadataStore) -> Result<[u8; 16]> {
    if let Some(identity) = metadata.load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)? {
        let Some(bytes) = identity.public_identity else {
            anyhow::bail!("stored ED2K user hash identity has no public identity");
        };
        let normalized = parse_user_hash_bytes(&bytes)?;
        if bytes.as_slice() != normalized {
            store_user_hash(metadata, normalized)?;
        }
        return Ok(normalized);
    }
    let bytes = create_user_hash();
    store_user_hash(metadata, bytes)?;
    Ok(bytes)
}

fn store_user_hash(metadata: &MetadataStore, user_hash: [u8; 16]) -> Result<()> {
    metadata.upsert_local_identity(&MetadataLocalIdentity {
        identity_kind: ED2K_USER_HASH_IDENTITY_KIND.to_string(),
        public_identity: Some(user_hash.to_vec()),
        private_secret: None,
    })
}

fn load_or_create_secure_ident(metadata: &MetadataStore) -> Result<Ed2kSecureIdent> {
    if let Some(identity) = metadata.load_local_identity(ED2K_SECURE_IDENT_IDENTITY_KIND)? {
        let Some(secret) = identity.private_secret else {
            anyhow::bail!("stored ED2K secure-ident identity has no private secret");
        };
        return Ed2kSecureIdent::from_pkcs8_der(&secret);
    }
    let secure_ident = Ed2kSecureIdent::generate()?;
    metadata.upsert_local_identity(&MetadataLocalIdentity {
        identity_kind: ED2K_SECURE_IDENT_IDENTITY_KIND.to_string(),
        public_identity: None,
        private_secret: Some(secure_ident.to_pkcs8_der()?),
    })?;
    Ok(secure_ident)
}

fn parse_user_hash_bytes(value: &[u8]) -> Result<[u8; 16]> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored ED2K user hash must be 16 bytes"))?;
    let bytes = normalize_user_hash_markers(bytes);
    if user_hash_is_bad(&bytes) {
        anyhow::bail!("stored ED2K user hash must not be an eMule bad hash");
    }
    Ok(bytes)
}

fn normalize_user_hash_markers(mut bytes: [u8; 16]) -> [u8; 16] {
    bytes[5] = 0x0E;
    bytes[14] = 0x6F;
    bytes
}

fn user_hash_is_bad(bytes: &[u8; 16]) -> bool {
    let lo = u64::from_le_bytes(bytes[..8].try_into().expect("slice has 8 bytes"));
    let hi = u64::from_le_bytes(bytes[8..].try_into().expect("slice has 8 bytes"));
    (lo & 0xffff_00ff_ffff_ffff) == 0 && (hi & 0xff00_ffff_ffff_ffff) == 0
}

fn create_user_hash() -> [u8; 16] {
    loop {
        let bytes = normalize_user_hash_markers(*uuid::Uuid::new_v4().as_bytes());
        if !user_hash_is_bad(&bytes) {
            return bytes;
        }
    }
}

#[cfg(test)]
mod tests;
