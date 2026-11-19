use std::{
    env, fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, ServerInfo, VpnGuardConfig};
use emulebb_ed2k::{
    NatConfig, config::Ed2kRuntimeConfig, detect_interfaces, ed2k_tcp::Ed2kSecureIdent,
    ipfilter::IpFilter,
};
use emulebb_index::{FileIndex, KadLocalStoreConfig, SnoopQueueConfig};
pub use emulebb_metadata::InitialProfileStorage;
use emulebb_metadata::{MetadataLocalIdentity, MetadataStore, SCHEMA_VERSION};
use emulebb_rest::{RestServerSettings, router_with_shutdown};
use emulebb_settings::product::{SecurityIpFilterValues, SettingsValues};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

mod bind_config;
mod offline_settings;
mod runtime_settings;
pub use bind_config::NetworkStartupError;
pub use offline_settings::{OfflineSettingsOperation, run_offline_settings};
use runtime_settings::{KadRuntimePolicy, load_settings};
mod discovery_bootstrap;
pub mod host_bootstrap;
mod listener_receipt;
pub mod logging;
mod profile_import;
mod profile_ownership;
mod rest_listener;
mod shutdown;
pub mod support_diagnostics;
mod vpn_guard_monitor;

pub use profile_import::{ProfileImportApplySummary, apply_profile_import};
pub use profile_ownership::ProfileLease;
pub use shutdown::{ShutdownRequest, ShutdownSignal};

pub const PROFILE_SETTINGS_FILE: &str = "emulebb-rust-settings.toml";
pub const PROFILE_METADATA_FILE: &str = "emulebb-rust-metadata.db";
pub use emulebb_core::{
    BUILD_CHANNEL, BUILD_SOURCE_REVISION, BUILD_VERSION, build_version_description,
    validate_ed2k_file_link,
};

const REGULAR_DIAGNOSTIC_SUMMARY_INTERVAL: Duration = Duration::from_secs(10);
const AUTO_CONNECT_POPULARITY_WAIT: Duration = Duration::from_secs(60);
const AUTO_CONNECT_POPULARITY_POLL: Duration = Duration::from_millis(500);
const AUTO_CONNECT_TARGET_VERIFY: Duration = Duration::from_secs(12);
const AUTO_CONNECT_TARGET_STABLE: Duration = Duration::from_secs(2);
const MIN_REST_API_KEY_BYTES: usize = 32;
const DEFAULT_BOOTSTRAP_SETTINGS: &str =
    include_str!("../../../emulebb-rust-settings.example.toml");
const UNSAFE_REST_API_KEYS: &[&str] = &[
    "change-me",
    "changeme",
    "replace-me",
    "replace_with_32_or_more_random_characters",
];

#[derive(Debug, Clone)]
pub struct DaemonProfile {
    pub profile_dir: PathBuf,
    pub temp_dir: PathBuf,
    /// Global finished-file delivery directory (eMule Incoming folder). When a
    /// completed transfer has no category path, its payload is materialized here
    /// by its canonical name. Relative values resolve against the profile.
    pub incoming_dir: PathBuf,
    pub p2p_bind_ip: Option<Ipv4Addr>,
    pub p2p_bind_interface: Option<String>,
    pub initial_shared_directory_reload: bool,
    pub kad: KadRuntimePolicy,
    pub kad_bootstrap_endpoints: Vec<String>,
    pub ed2k: Ed2kRuntimeConfig,
    pub nat: NatConfig,
    pub rest: RestBootstrapSettings,
    pub vpn_guard: VpnGuardConfig,
    pub ip_filter: SecurityIpFilterValues,
    /// Runtime ownership shared with metadata handles; never a configuration key.
    #[doc(hidden)]
    pub profile_lease: Option<ProfileLease>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DaemonBootstrapSettings {
    pub rest: RestBootstrapSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RestBootstrapSettings {
    pub bind_addr: Option<SocketAddr>,
    pub api_key: String,
    pub web_root_dir: Option<PathBuf>,
}

impl Default for DaemonProfile {
    fn default() -> Self {
        let settings = runtime_settings::from_values(SettingsValues::default(), Vec::new());
        Self {
            profile_dir: PathBuf::from("profile"),
            temp_dir: settings.temp_dir,
            incoming_dir: settings.incoming_dir,
            p2p_bind_ip: settings.p2p_bind_ip,
            p2p_bind_interface: settings.p2p_bind_interface,
            initial_shared_directory_reload: settings.initial_shared_directory_reload,
            kad: settings.kad,
            kad_bootstrap_endpoints: settings.kad_bootstrap_endpoints,
            ed2k: settings.ed2k,
            nat: settings.nat,
            rest: RestBootstrapSettings::default(),
            vpn_guard: settings.vpn_guard,
            ip_filter: settings.ip_filter,
            profile_lease: None,
        }
    }
}

impl DaemonProfile {
    /// Load or create a profile, defaulting to the executable directory.
    /// Explicit relative paths retain ordinary caller-working-directory semantics.
    pub fn load(profile_dir: Option<PathBuf>) -> Result<Self> {
        let profile_dir = match profile_dir {
            Some(profile_dir) => profile_dir,
            None => default_profile_dir()?,
        };
        Self::load_from_dir(profile_dir)
    }

    pub fn load_for_import(profile_dir: PathBuf) -> Result<Self> {
        Self::load_from_dir(profile_dir)
    }

    /// Load an application profile, applying folder defaults only to a new database.
    /// Existing canonical settings and removed sharing roots are never reseeded.
    pub fn load_hosted(profile_dir: PathBuf, storage: InitialProfileStorage) -> Result<Self> {
        let lease = ProfileLease::acquire(&profile_dir, true)?;
        Self::load_owned(profile_dir, lease, Some(storage))
    }

    fn load_from_dir(profile_dir: PathBuf) -> Result<Self> {
        // WHY: bootstrap creation, schema initialization and reads of mutable
        // state must all belong to the same exclusive writable-profile session.
        let profile_lease = ProfileLease::acquire(&profile_dir, true)?;
        Self::load_owned(profile_dir, profile_lease, None)
    }

    fn load_owned(
        profile_dir: PathBuf,
        profile_lease: ProfileLease,
        host_folders: Option<InitialProfileStorage>,
    ) -> Result<Self> {
        let settings_path = profile_lease.directory().join(PROFILE_SETTINGS_FILE);
        if !settings_path.exists() {
            create_default_profile_bootstrap(&profile_dir, &settings_path)?;
        }
        validate_profile_settings_permissions(&settings_path)?;
        let text = fs::read_to_string(&settings_path)
            .with_context(|| format!("failed to read settings {}", settings_path.display()))?;
        // WHY: TOML error displays include the offending source line, which
        // can contain an operator API key. Keep the diagnostic without values.
        let bootstrap: DaemonBootstrapSettings =
            toml::from_str(&text).map_err(|error: toml::de::Error| {
                anyhow::anyhow!(
                    "failed to parse settings {}: {}",
                    settings_path.display(),
                    error.message()
                )
            })?;
        let metadata_path = profile_lease.directory().join(PROFILE_METADATA_FILE);
        let opened = match host_folders {
            Some(storage) => MetadataStore::open_with_profile_lease_and_storage(
                metadata_path,
                profile_lease.guard(),
                move || {
                    for path in [
                        &storage.incoming_dir,
                        &storage.temp_dir,
                        &storage.shared_dir,
                    ] {
                        anyhow::ensure!(path.is_absolute(), "host folders must be absolute");
                        fs::create_dir_all(path)?;
                    }
                    let canonical = |path: &Path| -> Result<PathBuf> {
                        Ok(PathBuf::from(emulebb_core::normal_path_display(
                            path.canonicalize()?,
                        )))
                    };
                    Ok(InitialProfileStorage {
                        incoming_dir: canonical(&storage.incoming_dir)?,
                        temp_dir: canonical(&storage.temp_dir)?,
                        shared_dir: canonical(&storage.shared_dir)?,
                    })
                },
            ),
            None => MetadataStore::open_with_profile_lease(metadata_path, profile_lease.guard()),
        };
        let metadata = opened.with_context(|| {
            format!(
                "failed to open metadata store under {}",
                profile_dir.display()
            )
        })?;
        let settings = load_settings(&metadata)?;
        let profile = Self {
            profile_dir,
            temp_dir: settings.temp_dir,
            incoming_dir: settings.incoming_dir,
            p2p_bind_ip: settings.p2p_bind_ip,
            p2p_bind_interface: settings.p2p_bind_interface,
            initial_shared_directory_reload: settings.initial_shared_directory_reload,
            kad: settings.kad,
            kad_bootstrap_endpoints: settings.kad_bootstrap_endpoints,
            ed2k: settings.ed2k,
            nat: settings.nat,
            rest: bootstrap.rest,
            vpn_guard: settings.vpn_guard,
            ip_filter: settings.ip_filter,
            profile_lease: Some(profile_lease),
        };
        profile
            .nat
            .validate()
            .context("invalid NAT config in metadata store")?;
        Ok(profile)
    }

    pub fn metadata_path(&self) -> PathBuf {
        self.profile_io_dir().join(PROFILE_METADATA_FILE)
    }

    /// Use the acquired directory for profile I/O after loading or starting.
    pub fn profile_io_dir(&self) -> &Path {
        self.profile_lease
            .as_ref()
            .map_or(self.profile_dir.as_path(), ProfileLease::directory)
    }

    /// Open an independent metadata connection retaining this profile's lease.
    ///
    /// Load the profile first so all connections share the same OS lock rather
    /// than independently contending against their own process.
    pub fn open_metadata_store(&self) -> Result<MetadataStore> {
        let lease = self
            .profile_lease
            .as_ref()
            .context("load the profile before opening writable metadata")?;
        MetadataStore::open_with_profile_lease(
            lease.directory().join(PROFILE_METADATA_FILE),
            lease.guard(),
        )
    }

    fn product_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.profile_io_dir().join(path)
        }
    }
    pub fn transfer_root(&self) -> PathBuf {
        self.product_path(&self.temp_dir)
    }
    pub fn incoming_dir(&self) -> PathBuf {
        self.product_path(&self.incoming_dir)
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
        // A profile with neither listener configured is intentionally REST-only.
        // Discovery data is not a configuration gate: an empty first-run profile
        // must still be able to import servers and start Kad without a restart.
        if self.ed2k.listen_port.is_none() && self.kad.listen_port.is_none() {
            return Ok(None);
        }
        let bind_ip = self.resolve_p2p_bind_ip_from_interfaces(detected_interfaces)?;
        let listen_port = self.resolve_ed2k_listen_port()?;
        let user_hash = load_or_create_user_hash(metadata)?;
        let secure_ident = Arc::new(load_or_create_secure_ident(metadata)?);
        let ip_filter = self.load_ip_filter()?;
        let vpn_interface_bound = self.vpn_binding_confirmed(bind_ip, detected_interfaces);
        // WHY: a default-route address is resolved for source binding, but it
        // must not be mistaken for an operator-selected interface pin.
        let egress_route = self.egress_route();
        Ok(Some(Ed2kNetworkConfig {
            egress_route,
            bind_ip,
            kad_bind_addr: self.kad_bind_addr(bind_ip)?,
            listen_port,
            user_hash,
            secure_ident,
            kad_local_store: kad_local_store_config(&self.kad),
            kad_snoop_queue: SnoopQueueConfig::default(),
            kad_passive_replay_enabled: self.kad.passive_replay_enabled,
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
            ed2k: self.ed2k.clone(),
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
                .then(|| {
                    self.ip_filter
                        .file_path
                        .as_ref()
                        .map(|path| self.product_path(path))
                })
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
        let Some(path) = self.ip_filter.file_path.as_ref() else {
            return Ok(IpFilter::default());
        };
        let path = self.product_path(path);
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read ipfilter.dat at {}", path.display()))?;
        let filter = IpFilter::parse(&body, self.ip_filter.level);
        info!(ranges = filter.len(), path = %path.display(), "loaded ip filter");
        Ok(filter)
    }

    pub fn kad_local_store_config(&self) -> KadLocalStoreConfig {
        kad_local_store_config(&self.kad)
    }

    fn kad_bind_addr(&self, bind_ip: Ipv4Addr) -> Result<SocketAddr> {
        let Some(listen_port) = self.kad.listen_port else {
            bail!("network.p2p.udpPort is required when P2P is enabled");
        };
        Ok(SocketAddr::new(IpAddr::V4(bind_ip), listen_port))
    }

    fn resolve_ed2k_listen_port(&self) -> Result<u16> {
        let Some(listen_port) = self.ed2k.listen_port else {
            bail!("network.p2p.tcpPort is required when P2P is enabled");
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
            bail!("rest.bind_addr is required");
        };
        Ok(candidate)
    }

    pub fn validate_rest_api_key(&self) -> Result<()> {
        let api_key = self.rest.api_key.as_str();
        if api_key.is_empty() {
            bail!("rest.api_key is required and must not be empty");
        }
        if api_key.trim() != api_key {
            bail!("rest.api_key must not have leading or trailing whitespace");
        }
        if !api_key.bytes().all(|byte| byte.is_ascii_graphic()) {
            bail!("rest.api_key must contain only printable ASCII characters without spaces");
        }
        if UNSAFE_REST_API_KEYS
            .iter()
            .any(|placeholder| api_key.eq_ignore_ascii_case(placeholder))
        {
            bail!("rest.api_key is a placeholder and must be replaced");
        }
        if api_key.len() < MIN_REST_API_KEY_BYTES {
            bail!(
                "rest.api_key must contain at least {MIN_REST_API_KEY_BYTES} bytes of secret material"
            );
        }
        Ok(())
    }

    pub fn web_root_dir(&self) -> Result<Option<PathBuf>> {
        if let Some(configured) = &self.rest.web_root_dir {
            let resolved = if configured.is_absolute() {
                configured.clone()
            } else {
                self.profile_io_dir().join(configured)
            };
            validate_web_root_dir(&resolved, "rest.web_root_dir")?;
            return Ok(Some(resolved));
        }

        let exe = env::current_exe().context("failed to resolve current executable path")?;
        let Some(exe_dir) = exe.parent() else {
            bail!(
                "failed to resolve executable directory from {}",
                exe.display()
            );
        };
        let default_root = exe_dir.join("webui");
        if !default_root.exists() {
            return Ok(None);
        }
        if let Err(error) = validate_web_root_dir(&default_root, "default webui directory") {
            warn!(%error, "ignoring invalid default WebUI directory");
            return Ok(None);
        }
        Ok(Some(default_root))
    }
}

fn default_profile_dir() -> Result<PathBuf> {
    let executable =
        env::current_exe().context("cannot locate the executable for its default profile")?;
    executable
        .parent()
        .map(Path::to_path_buf)
        .context("executable has no parent directory; choose an explicit --profile directory")
}

fn create_default_profile_bootstrap(
    profile_dir: &std::path::Path,
    settings_path: &std::path::Path,
) -> Result<()> {
    let text = DEFAULT_BOOTSTRAP_SETTINGS;
    let bootstrap: DaemonBootstrapSettings =
        toml::from_str(text).context("invalid canonical bootstrap template")?;
    let listener = bootstrap
        .rest
        .bind_addr
        .context("canonical REST bind_addr is missing")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(settings_path)
        .with_context(|| format!("failed to create {}", settings_path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {}", settings_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", settings_path.display()))?;
    eprintln!("Created eMuleBB profile at {}", profile_dir.display());
    eprintln!("WebUI: http://{listener}/  API key: see emulebb-rust-settings.toml");
    Ok(())
}

fn create_private_profile_dir(profile_dir: &std::path::Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(profile_dir)
        .with_context(|| format!("failed to create default profile {}", profile_dir.display()))
}

#[cfg(unix)]
fn validate_profile_settings_permissions(settings_path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(settings_path)
        .with_context(|| format!("failed to inspect settings {}", settings_path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "profile settings {} have mode {mode:03o}; rest.api_key requires owner-only permissions (chmod 600)",
            settings_path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_profile_settings_permissions(_settings_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn validate_web_root_dir(path: &std::path::Path, label: &str) -> Result<()> {
    if !path.is_dir() {
        bail!("{label} must be an existing directory: {}", path.display());
    }
    let index = path.join("index.html");
    if !index.is_file() {
        bail!("{label} must contain index.html: {}", index.display());
    }
    Ok(())
}

fn kad_local_store_config(settings: &KadRuntimePolicy) -> KadLocalStoreConfig {
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

/// Upper bound on the graceful network teardown so a wedged provider can never
/// hang daemon shutdown indefinitely. `disconnect_ed2k` already times the NAT
/// `stop()` out at ~2s; this is a belt-and-braces cap over the whole teardown
/// (lease reset + task aborts + NAT release) in case a future step blocks.
const SHUTDOWN_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Finish persistence before bounded network cleanup, including on failure.
async fn graceful_teardown(core: &Arc<EmulebbCore>) -> Result<()> {
    info!("running graceful network teardown");
    core.begin_shutdown();
    let admission = core.stop_persistence_admission();
    let monitor = core.stop_shared_directory_monitor().await;
    let result = teardown_sequence(
        async { core.finish_kad_persistence().await },
        async { core.disconnect_ed2k_after_persistence().await.map(|_| ()) },
        SHUTDOWN_TEARDOWN_TIMEOUT,
    )
    .await;
    admission.and(monitor).and(result)
}

async fn teardown_sequence(
    snapshot: impl std::future::Future<Output = Result<()>>,
    cleanup: impl std::future::Future<Output = Result<()>>,
    deadline: Duration,
) -> Result<()> {
    let snapshot = snapshot.await.context("failed to persist final Kad state");
    let cleanup = match tokio::time::timeout(deadline, cleanup).await {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!("graceful network teardown timed out; forcing shutdown");
            Ok(())
        }
    };
    snapshot.and(cleanup)
}

/// Drain even after a failed final snapshot or network cleanup.
async fn finalize_daemon(core: &Arc<EmulebbCore>) -> Result<()> {
    let teardown = graceful_teardown(core).await;
    let drain = core
        .drain_persistence()
        .await
        .context("failed to drain persistence");
    teardown.and(drain)
}

pub async fn run(profile: DaemonProfile) -> Result<()> {
    run_inner(profile, None).await
}

/// Run inside an application-owned runtime without installing process signal handlers.
///
/// Readiness reports the bound address, including an OS-assigned port. Stop is
/// retained before startup and host loss fails closed. The host must drain its
/// Tokio runtime after this returns before releasing process network ownership.
pub async fn run_hosted(
    profile: DaemonProfile,
    shutdown: ShutdownSignal,
    ready: oneshot::Sender<SocketAddr>,
) -> Result<()> {
    run_inner(profile, Some(HostedLifecycle { shutdown, ready })).await
}

struct HostedLifecycle {
    shutdown: ShutdownSignal,
    ready: oneshot::Sender<SocketAddr>,
}

async fn run_inner(mut profile: DaemonProfile, host: Option<HostedLifecycle>) -> Result<()> {
    if let Some(host) = &host {
        if host.shutdown.is_requested() {
            return Ok(());
        }
        if host.ready.is_closed() {
            bail!("embedded host readiness receiver closed before startup");
        }
    }
    let rest_bind_addr = profile.rest_bind_addr()?;
    profile.validate_rest_api_key()?;
    info!(
        version = BUILD_VERSION,
        release_channel = BUILD_CHANNEL,
        source_revision = BUILD_SOURCE_REVISION,
        metadata_schema_version = SCHEMA_VERSION,
        "starting emulebb-rust"
    );
    // Embedded callers can construct a profile without loading it from disk.
    // They acquire the same lease before any discovery, DB or runtime mutation.
    if profile.profile_lease.is_none() {
        profile.profile_lease = Some(ProfileLease::acquire(&profile.profile_dir, true)?);
    }
    let index = FileIndex::from_metadata_store(profile.open_metadata_store()?);
    let metadata_store = index.metadata_store();
    discovery_bootstrap::seed_empty_discovery(&metadata_store).await?;
    let ed2k_network = profile.ed2k_network_config(&metadata_store)?;
    let ed2k_network_configured = ed2k_network.is_some();
    let vpn_guard_monitor = ed2k_network
        .as_ref()
        .and_then(vpn_guard_monitor::monitor_config);
    let incoming_dir = profile.incoming_dir();
    fs::create_dir_all(&incoming_dir)
        .with_context(|| format!("failed to create incoming dir {}", incoming_dir.display()))?;
    let core = Arc::new(
        EmulebbCore::new_with_network_progressive_catalog(
            BUILD_VERSION,
            index,
            profile.transfer_root(),
            ed2k_network,
        )?
        .with_profile_dir(profile.profile_io_dir().to_path_buf())
        .with_incoming_dir(incoming_dir),
    );
    let shutdown_error = Arc::new(std::sync::Mutex::new(None));
    let run_result: Result<()> = async {
    if let Err(error) = discovery_bootstrap::seed_pending_kad(&core).await {
        warn!(%error, "Kad discovery initialization unavailable; retrying next launch");
    }
    // Download storage is reconciled only when selected. Durable cleanup runs
    // in bounded pages after listener startup; history is never hydrated here.
    let initial_shared_catalog_entries = core.hydrate_initial_shared_catalog().await?;
    info!(
        initial_shared_catalog_entries,
        "hydrated validated initial shared catalog before REST startup"
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Keep an owned handle for the post-serve teardown; the router gets a clone.
    let app = router_with_shutdown(
        Arc::clone(&core),
        RestServerSettings {
            api_key: profile.rest.api_key.clone(),
            web_root_dir: profile.web_root_dir()?,
        },
        Some(shutdown_tx.clone()),
    );
    let listener = rest_listener::bind(rest_bind_addr).await?;
    let bound_addr = listener.local_addr()?;
    let _listener_receipt = listener_receipt::ListenerReceipt::publish(
        profile.profile_io_dir(),
        bound_addr,
        core.instance_id(),
    )?;
    let host_shutdown = if let Some(host) = host {
        if host.shutdown.is_requested() {
            return Ok(());
        }
        if host.ready.send(bound_addr).is_err() {
            bail!("embedded host readiness receiver closed during startup");
        }
        Some(host.shutdown)
    } else {
        None
    };
    info!("emulebb-rust REST listening on {}", bound_addr);
    spawn_regular_diagnostic_summary(Arc::clone(&core));

    // Start the live auto-pickup monitor first, then hydrate the persisted
    // catalog remainder in bounded pages before reconciling the directory tree.
    // One validated cohort is already publishable, so network startup need not
    // wait for a 100k-file catalog load or exhaustive filesystem scan.
    let sharing_core = Arc::clone(&core);
    let initial_shared_directory_reload = profile.initial_shared_directory_reload;
    tokio::spawn(async move {
        sharing_core.start_shared_directory_monitor().await;
        match sharing_core.hydrate_shared_catalog().await {
            Ok(hydrated) if hydrated > 0 => {
                tracing::info!(hydrated, "background shared catalog hydration complete");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "background shared catalog hydration failed; continuing");
            }
        }
        if !initial_shared_directory_reload {
            tracing::info!("initial shared-directory reload disabled by daemon settings");
            return;
        }
        if let Err(error) = sharing_core.reload_shared_directories_detached().await {
            tracing::warn!(%error, "initial shared-directory scan failed; continuing");
        }
    });
    // Resume hidden destructive-deletion cleanup and deliver
    // completed-but-undelivered transfers in the background. A persisted
    // sharing profile can carry tens of thousands of manifests, so the first
    // sweep starts only after REST is bound and sharing workers have been
    // scheduled. Later sweeps recover transient sharing/AV and destination
    // failures without a restart.
    let delivery_core = Arc::clone(&core);
    tokio::spawn(async move {
        loop {
            if let Err(error)=delivery_core.maintain_download_cleanup().await {
                tracing::warn!(%error,"download cleanup maintenance deferred");
            }
            if let Err(error) = delivery_core.maintain_download_delivery().await {
                tracing::warn!(%error, "download delivery maintenance deferred");
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    if let Some(monitor) = vpn_guard_monitor {
        tokio::spawn(vpn_guard_monitor::run(Arc::clone(&core), monitor));
    }
    if ed2k_network_configured {
        let connect_core = Arc::clone(&core);
        tokio::spawn(async move {
            let settings = match connect_core.effective_settings().await {
                Ok(settings) => settings,
                Err(error) => {
                    tracing::warn!(%error, "automatic connection requires coherent settings");
                    return;
                }
            };
            if !settings.network.auto_connect { return; }
            // Record Kad as desired before constructing the shared eD2K/Kad
            // runtime. The connect path applies this flag to the new DHT, so a
            // fresh profile starts both networks without a WebUI Start click.
            if let Err(error) = connect_core.start_kad().await {
                tracing::warn!(%error, "automatic Kad startup failed; REST start remains available");
            }
            match connect_core.auto_connect_ed2k().await {
                Ok(status) => {
                    info!(
                        connected = status.connected,
                        firewalled = status.firewalled.unwrap_or(false),
                        "automatic ED2K/Kad startup complete"
                    );
                    connect_to_most_popular_server(&connect_core).await;
                }
                Err(error) => tracing::warn!(
                    %error,
                    "automatic ED2K/Kad startup failed; REST connect remains available"
                ),
            }
        });
    }
    let shutdown_core = Arc::clone(&core);
    let callback_error = Arc::clone(&shutdown_error);
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown::wait_for_shutdown(shutdown_rx, host_shutdown).await;
            // WHY: event streams must close for every shutdown source, and P2P
            // teardown must not wait behind HTTP response draining.
            shutdown_tx.send_replace(true);
            if let Err(error) = graceful_teardown(&shutdown_core).await {
                tracing::error!(%error, "graceful network teardown failed");
                *callback_error.lock().unwrap() = Some(error);
            }
        })
        .await;
    serve_result?;
    Ok(())
    }.await;
    // WHY: every exit after the owner can start must stop tasks and drain it,
    // including startup errors and hosted shutdown before readiness.
    let final_result = finalize_daemon(&core).await;
    let callback_result = shutdown_error.lock().unwrap().take().map_or(Ok(()), Err);
    run_result.and(callback_result).and(final_result)
}

async fn connect_to_most_popular_server(core: &EmulebbCore) {
    let deadline = tokio::time::Instant::now() + AUTO_CONNECT_POPULARITY_WAIT;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            let servers = core.servers().await;
            let candidates = ranked_popular_enabled_servers(servers);
            if candidates.is_empty() {
                warn!(
                    wait_seconds = AUTO_CONNECT_POPULARITY_WAIT.as_secs(),
                    "automatic server selection received no live population data; keeping the current server"
                );
                return;
            }
            for server in candidates {
                let is_live_current = core
                    .server(&server.endpoint)
                    .await
                    .is_some_and(|current| current.current && current.connected);
                if !is_live_current {
                    match core.connect_ed2k_server(&server.endpoint).await {
                        Ok(Some(_)) => info!(
                            endpoint = %server.endpoint,
                            users = server.users,
                            files = server.files,
                            "automatic connection trying the most popular responding server"
                        ),
                        Ok(None) => continue,
                        Err(error) => {
                            warn!(endpoint = %server.endpoint, %error, "automatic popular-server connect request failed");
                            continue;
                        }
                    }
                }
                if server_connection_is_stable(core, &server.endpoint).await {
                    info!(
                        endpoint = %server.endpoint,
                        users = server.users,
                        files = server.files,
                        "automatic connection selected the most popular reachable server"
                    );
                    return;
                }
                warn!(
                    endpoint = %server.endpoint,
                    users = server.users,
                    "popular server did not stay connected; trying the next candidate"
                );
            }
            if let Err(error) = core.connect_ed2k().await {
                warn!(%error, "automatic server fallback failed; REST connect remains available");
            }
            return;
        }
        tokio::time::sleep(AUTO_CONNECT_POPULARITY_POLL).await;
    }
}

async fn server_connection_is_stable(core: &EmulebbCore, endpoint: &str) -> bool {
    let deadline = tokio::time::Instant::now() + AUTO_CONNECT_TARGET_VERIFY;
    let mut connected_since = None;
    loop {
        let now = tokio::time::Instant::now();
        let Some(server) = core.server(endpoint).await else {
            return false;
        };
        if !server.enabled {
            return false;
        }
        if server.current && server.connected {
            let since = connected_since.get_or_insert(now);
            if now.duration_since(*since) >= AUTO_CONNECT_TARGET_STABLE {
                return true;
            }
        } else {
            connected_since = None;
        }
        if now >= deadline {
            return false;
        }
        tokio::time::sleep(AUTO_CONNECT_POPULARITY_POLL).await;
    }
}

fn ranked_popular_enabled_servers(servers: Vec<ServerInfo>) -> Vec<ServerInfo> {
    let mut servers = servers
        .into_iter()
        .filter(|server| server.enabled && server.users > 0)
        .collect::<Vec<_>>();
    servers.sort_by(|left, right| {
        right
            .users
            .cmp(&left.users)
            .then_with(|| right.files.cmp(&left.files))
            .then_with(|| right.name.cmp(&left.name))
    });
    servers
}

fn spawn_regular_diagnostic_summary(core: Arc<EmulebbCore>) {
    tokio::spawn(async move {
        if tracing::enabled!(tracing::Level::DEBUG) {
            log_regular_diagnostic_summary(&core).await;
        }
        let mut interval = tokio::time::interval(REGULAR_DIAGNOSTIC_SUMMARY_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            if tracing::enabled!(tracing::Level::DEBUG) {
                log_regular_diagnostic_summary(&core).await;
            }
        }
    });
}

async fn log_regular_diagnostic_summary(core: &EmulebbCore) {
    let status = core.status().await;
    let transfers = match core.transfer_stats().await {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "regular diagnostic summary could not read persisted download counts");
            return;
        }
    };
    let upload_policy = core.upload_policy_metrics().await;
    let throughput = core.transfer_throughput_stats();
    let shared_hashing_count = core.shared_directories().await.hashing_count;
    let vpn_guard = core.vpn_guard_status();
    tracing::debug!(
        uptime_secs = status.uptime_secs,
        vpn_guard_enabled = vpn_guard.enabled,
        vpn_guard_startup_blocked = vpn_guard.startup_blocked,
        vpn_guard_egress_verified = vpn_guard.egress_verified,
        vpn_guard_http_attempted = vpn_guard.http_probe.attempted,
        vpn_guard_http_succeeded = vpn_guard.http_probe.succeeded,
        vpn_guard_stun_attempted = vpn_guard.stun_probe.attempted,
        vpn_guard_stun_succeeded = vpn_guard.stun_probe.succeeded,
        ed2k_connected = status.ed2k.connected,
        ed2k_high_id = status.ed2k.connected && !status.ed2k.firewalled.unwrap_or(false),
        kad_connected = status.kad.connected,
        active_uploads = upload_policy.active_sessions,
        waiting_uploads = upload_policy.waiting_sessions,
        upload_speed_kibps = upload_policy.upload_rate_bytes_per_sec as f64 / 1024.0,
        session_uploaded_bytes = throughput.session_uploaded_bytes,
        active_downloads = transfers.active,
        completed_downloads = transfers.completed,
        total_downloads = transfers.total,
        download_speed_kibps = throughput.download_rate_bytes_per_sec as f64 / 1024.0,
        session_downloaded_bytes = throughput.session_downloaded_bytes,
        shared_hashing_count,
        "regular startup HTTP public IPv4 STUN ED2K Kad publish upload download diagnostic summary"
    );
}

const ED2K_USER_HASH_IDENTITY_KIND: &str = "ed2k-user-hash";
const ED2K_SECURE_IDENT_IDENTITY_KIND: &str = "ed2k-secure-ident";

fn load_or_create_user_hash(metadata: &MetadataStore) -> Result<[u8; 16]> {
    if let Some(identity) = metadata.load_local_identity(ED2K_USER_HASH_IDENTITY_KIND)? {
        let Some(bytes) = identity.public_identity else {
            anyhow::bail!("stored ED2K user hash identity has no public identity");
        };
        return parse_user_hash_bytes(&bytes);
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
    if user_hash_is_bad(&bytes) {
        anyhow::bail!("stored ED2K user hash must not be an eMule bad hash");
    }
    Ok(bytes)
}

fn user_hash_is_bad(bytes: &[u8; 16]) -> bool {
    let lo = u64::from_le_bytes(bytes[..8].try_into().expect("slice has 8 bytes"));
    let hi = u64::from_le_bytes(bytes[8..].try_into().expect("slice has 8 bytes"));
    (lo & 0xffff_00ff_ffff_ffff) == 0 && (hi & 0xff00_ffff_ffff_ffff) == 0
}

fn create_user_hash() -> [u8; 16] {
    loop {
        let mut bytes = *uuid::Uuid::new_v4().as_bytes();
        bytes[5] = 0x0E;
        bytes[14] = 0x6F;
        if !user_hash_is_bad(&bytes) {
            return bytes;
        }
    }
}

#[cfg(test)]
mod tests;
