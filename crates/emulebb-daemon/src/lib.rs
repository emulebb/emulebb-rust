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
    NatConfig, config::Ed2kConfig, detect_interfaces, ed2k_tcp::Ed2kSecureIdent, ipfilter,
    ipfilter::IpFilter,
};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};
use emulebb_metadata::{MetadataLocalIdentity, MetadataStore};
use emulebb_rest::{RestConfig, router_with_shutdown};
use serde::{Deserialize, Serialize};
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
    pub kad: KadListenerConfig,
    pub ed2k: Ed2kConfig,
    pub nat: NatConfig,
    pub rest: RestListenerConfig,
    pub vpn_guard: VpnGuardSettings,
    pub ip_filter: IpFilterSettings,
}

/// Optional VPN-binding guard configuration (`[vpnGuard]`). Default disabled, so
/// it never affects startup unless explicitly enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct VpnGuardSettings {
    pub enabled: bool,
    pub mode: String,
    pub allowed_public_ip_cidrs: String,
}

/// Optional IPv4 range filter configuration (`[ipFilter]`). Default disabled, so
/// no addresses are filtered unless explicitly enabled with a loadable file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct IpFilterSettings {
    pub enabled: bool,
    pub path: Option<PathBuf>,
    pub level: u32,
}

impl Default for IpFilterSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            level: ipfilter::DEFAULT_FILTER_LEVEL,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct KadListenerConfig {
    pub listen_port: Option<u16>,
    pub bootstrap_nodes: Vec<String>,
    pub bootstrap_min_routing_contacts: usize,
    pub local_store_enabled: bool,
    pub local_store_keyword_ttl_secs: u64,
    pub local_store_source_ttl_secs: u64,
    pub local_store_notes_ttl_secs: u64,
    pub local_store_keyword_capacity: usize,
    pub local_store_source_capacity: usize,
    pub local_store_notes_capacity: usize,
    /// Per-file source cap (stock KADEMLIAMAXSOURCEPERFILE). Distinct from the
    /// global `local_store_source_capacity` so per-file and overall limits do
    /// not conflate.
    pub local_store_source_per_file_capacity: usize,
    /// Per-file note cap (stock KADEMLIAMAXNOTESPERFILE), distinct from the
    /// global `local_store_notes_capacity`.
    pub local_store_notes_per_file_capacity: usize,
    pub publish_shared_files_enabled: bool,
    pub republish_interval_secs: u64,
    pub publish_contact_fanout: usize,
    pub hello_intro_interval_secs: u64,
    pub hello_intro_fanout: usize,
    pub udp_firewall_check_enabled: bool,
    pub udp_firewall_check_interval_secs: u64,
    /// Requester-side Kad TCP firewall recheck (FIREWALLED2_REQ) driver.
    pub tcp_firewall_check_enabled: bool,
    pub tcp_firewall_check_interval_secs: u64,
    /// Kad LowID buddy/firewalled-callback subsystem (default on).
    pub buddy_enabled: bool,
    /// Periodic routing-table maintenance loop (bucket refresh + dead-contact
    /// expiry + stale-contact re-probe). Default on.
    pub routing_maintenance_enabled: bool,
    pub snoop_queue_dedup_window_secs: u64,
    pub snoop_queue_general_max_queries_per_600s: u32,
    pub snoop_queue_general_drain_cooldown_secs: u64,
    pub snoop_queue_source_max_queries_per_600s: u32,
    pub snoop_queue_source_drain_cooldown_secs: u64,
    pub snoop_queue_source_stop_after_results: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RestListenerConfig {
    pub bind_addr: Option<SocketAddr>,
    pub api_key: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            runtime_dir: PathBuf::from("runtime"),
            incoming_dir: None,
            p2p_bind_ip: None,
            p2p_bind_interface: None,
            ed2k_user_hash: None,
            kad: KadListenerConfig::default(),
            ed2k: Ed2kConfig::default(),
            nat: NatConfig::default(),
            rest: RestListenerConfig::default(),
            vpn_guard: VpnGuardSettings::default(),
            ip_filter: IpFilterSettings::default(),
        }
    }
}

impl Default for KadListenerConfig {
    fn default() -> Self {
        Self {
            listen_port: None,
            bootstrap_nodes: Vec::new(),
            bootstrap_min_routing_contacts: 10,
            local_store_enabled: true,
            local_store_keyword_ttl_secs: 86_400,
            // Master inbound source entry lifetime = KADEMLIAREPUBLISHTIMES (5h),
            // KademliaUDPListener.cpp:1349. Keyword/notes keep 24h.
            local_store_source_ttl_secs: 18_000,
            local_store_notes_ttl_secs: 86_400,
            local_store_keyword_capacity: 20_000,
            local_store_source_capacity: 20_000,
            local_store_notes_capacity: 5_000,
            // Stock per-file caps (Opcodes.h KADEMLIAMAXSOURCEPERFILE /
            // KADEMLIAMAXNOTESPERFILE), well below the global caps above.
            local_store_source_per_file_capacity: 1_000,
            local_store_notes_per_file_capacity: 150,
            publish_shared_files_enabled: true,
            republish_interval_secs: 1_800,
            publish_contact_fanout: 4,
            hello_intro_interval_secs: 300,
            hello_intro_fanout: 2,
            udp_firewall_check_enabled: true,
            udp_firewall_check_interval_secs: 600,
            tcp_firewall_check_enabled: true,
            tcp_firewall_check_interval_secs: 600,
            buddy_enabled: true,
            routing_maintenance_enabled: true,
            snoop_queue_dedup_window_secs: 28_800,
            snoop_queue_general_max_queries_per_600s: 24,
            snoop_queue_general_drain_cooldown_secs: 900,
            snoop_queue_source_max_queries_per_600s: 60,
            snoop_queue_source_drain_cooldown_secs: 300,
            snoop_queue_source_stop_after_results: 2,
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
        toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
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
        if self.ed2k.server_entries.is_empty() && self.ed2k.server_endpoints.is_empty() {
            return Ok(None);
        }
        let bind_ip = self.resolve_p2p_bind_ip()?;
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
        let detected_interfaces = detect_interfaces().unwrap_or_default();
        let vpn_interface_bound = self.vpn_binding_confirmed(bind_ip, &detected_interfaces);
        Ok(Some(Ed2kNetworkConfig {
            bind_ip,
            kad_bind_addr: self.kad_bind_addr(bind_ip)?,
            listen_port,
            user_hash,
            secure_ident,
            kad_local_store: self.kad.local_store_config(),
            kad_snoop_queue: self.kad.snoop_queue_config(),
            kad_bootstrap_nodes: self.kad.bootstrap_nodes.clone(),
            kad_bootstrap_min_routing_contacts: self.kad.bootstrap_min_routing_contacts.max(1),
            kad_publish_shared_files: self.kad.publish_shared_files_enabled,
            kad_republish_interval_secs: self.kad.republish_interval_secs.max(1),
            kad_publish_contact_fanout: self.kad.publish_contact_fanout.max(1),
            kad_hello_intro_interval_secs: self.kad.hello_intro_interval_secs.max(1),
            kad_hello_intro_fanout: self.kad.hello_intro_fanout,
            kad_udp_firewall_check_enabled: self.kad.udp_firewall_check_enabled,
            kad_udp_firewall_check_interval_secs: self.kad.udp_firewall_check_interval_secs.max(60),
            kad_tcp_firewall_check_enabled: self.kad.tcp_firewall_check_enabled,
            kad_tcp_firewall_check_interval_secs: self.kad.tcp_firewall_check_interval_secs.max(60),
            kad_buddy_enabled: self.kad.buddy_enabled,
            kad_routing_maintenance_enabled: self.kad.routing_maintenance_enabled,
            nat_config: self.nat_config(bind_ip),
            config: self.ed2k.clone(),
            p2p_bind_ip: self.p2p_bind_ip,
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
        self.kad.local_store_config()
    }

    pub fn kad_snoop_queue_config(&self) -> SnoopQueueConfig {
        self.kad.snoop_queue_config()
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

impl KadListenerConfig {
    pub fn local_store_config(&self) -> KadLocalStoreConfig {
        KadLocalStoreConfig {
            enabled: self.local_store_enabled,
            keyword_ttl: std::time::Duration::from_secs(self.local_store_keyword_ttl_secs.max(1)),
            source_ttl: std::time::Duration::from_secs(self.local_store_source_ttl_secs.max(1)),
            notes_ttl: std::time::Duration::from_secs(self.local_store_notes_ttl_secs.max(1)),
            keyword_capacity: self.local_store_keyword_capacity.max(1),
            source_capacity: self.local_store_source_capacity.max(1),
            notes_capacity: self.local_store_notes_capacity.max(1),
            source_per_file_capacity: self.local_store_source_per_file_capacity.max(1),
            notes_per_file_capacity: self.local_store_notes_per_file_capacity.max(1),
        }
    }

    pub fn snoop_queue_config(&self) -> SnoopQueueConfig {
        SnoopQueueConfig {
            dedup_window_secs: self.snoop_queue_dedup_window_secs.max(1),
            general_max_queries_per_600s: self.snoop_queue_general_max_queries_per_600s.max(1),
            general_drain_cooldown_secs: self.snoop_queue_general_drain_cooldown_secs.max(1),
            source_max_queries_per_600s: self.snoop_queue_source_max_queries_per_600s.max(1),
            source_drain_cooldown_secs: self.snoop_queue_source_drain_cooldown_secs.max(1),
            source_stop_after_results: self.snoop_queue_source_stop_after_results.max(1),
        }
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

    // Deliver any completed-but-undelivered transfers from a previous run in
    // the background. A persisted sharing profile can carry tens of thousands
    // of manifests, so this sweep starts only after REST is bound.
    let delivery_core = Arc::clone(&core);
    tokio::spawn(async move {
        delivery_core.deliver_pending_completed_transfers().await;
    });
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
        });
    }
    // Initial scan-on-demand pickup of the already-present shared files, then
    // start the live auto-pickup monitor (eMule directory auto-monitor parity).
    // Both startup tasks are detached so REST readiness is never blocked on
    // scanning, watch registration, or hashing the shared library (a large
    // library hashes far longer than any client timeout). They are started
    // after REST is bound; the reload worker updates `hashingCount`; shares are
    // seeded in place, not copied. The monitor is torn down by the graceful
    // teardown's disconnect_ed2k.
    let reload_core = Arc::clone(&core);
    tokio::spawn(async move {
        if let Err(error) = reload_core.reload_shared_directories_detached().await {
            tracing::warn!(%error, "initial shared-directory scan failed; continuing");
        }
    });
    let monitor_core = Arc::clone(&core);
    tokio::spawn(async move {
        monitor_core.start_shared_directory_monitor().await;
    });
    if let Some(monitor) = vpn_guard_monitor {
        tokio::spawn(vpn_guard_monitor::run(
            Arc::clone(&core),
            shutdown_tx.clone(),
            monitor,
        ));
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
        kind: ED2K_USER_HASH_IDENTITY_KIND.to_string(),
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
        kind: ED2K_SECURE_IDENT_IDENTITY_KIND.to_string(),
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
