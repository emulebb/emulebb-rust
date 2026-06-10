//! NAT reachability and port-mapping model for the eMuleBB Rust client.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tracing::{info, warn};

mod types {
    use std::net::SocketAddr;

    use serde::{Deserialize, Serialize};

    /// Transport protocol for one NAT port mapping.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum TransportProtocol {
        Tcp,
        Udp,
    }

    impl TransportProtocol {
        /// Returns the protocol token expected by UPnP IGD APIs.
        #[must_use]
        pub fn as_upnp_token(self) -> &'static str {
            match self {
                Self::Tcp => "TCP",
                Self::Udp => "UDP",
            }
        }
    }

    /// Whether a port mapping is mandatory for reachability or only a best-effort preference.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
    #[serde(rename_all = "snake_case")]
    pub enum MappingExposure {
        #[default]
        Required,
        Preferred,
    }

    /// Desired local listener to expose through NAT traversal.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MappingSpec {
        pub name: String,
        pub local_addr: SocketAddr,
        pub protocol: TransportProtocol,
        #[serde(default)]
        pub exposure: MappingExposure,
        pub preferred_external_port: Option<u16>,
    }

    /// Gateway selected by a NAT backend during discovery.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SelectedGateway {
        pub backend: String,
        pub control_url: String,
        pub local_ip: Option<String>,
        pub gateway_ip: Option<String>,
        pub external_ip: Option<String>,
    }

    /// Active external endpoint created by a NAT backend.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct MappedEndpoint {
        pub name: String,
        pub protocol: TransportProtocol,
        pub local_addr: SocketAddr,
        pub external_addr: SocketAddr,
        pub lease_expires_in_secs: u32,
        pub backend: String,
    }

    /// Serializable NAT status view for diagnostics and REST surfaces.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct NatStatusSnapshot {
        pub enabled: bool,
        pub gateway_discovered: bool,
        pub backend: Option<String>,
        pub bind_ip: Option<String>,
        pub igd_ip: Option<String>,
        pub minissdpd_socket: Option<String>,
        pub ssdp_local_port: Option<u16>,
        pub external_ip_override: Option<String>,
        pub gateway: Option<SelectedGateway>,
        #[serde(default)]
        pub mappings: Vec<MappedEndpoint>,
        #[serde(default)]
        pub observed_external_addresses: Vec<String>,
        pub last_refresh_unix_secs: Option<u64>,
        pub last_error: Option<String>,
    }

    /// Mutable NAT status maintained by the runtime manager.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
    pub struct NatStatus {
        pub enabled: bool,
        pub gateway_discovered: bool,
        pub backend: Option<String>,
        pub bind_ip: Option<String>,
        pub igd_ip: Option<String>,
        pub minissdpd_socket: Option<String>,
        pub ssdp_local_port: Option<u16>,
        pub external_ip_override: Option<String>,
        pub gateway: Option<SelectedGateway>,
        pub mappings: Vec<MappedEndpoint>,
        pub observed_external_addresses: Vec<String>,
        pub last_refresh_unix_secs: Option<u64>,
        pub last_error: Option<String>,
    }

    impl NatStatus {
        /// Returns a detached serializable snapshot of the current NAT state.
        #[must_use]
        pub fn snapshot(&self) -> NatStatusSnapshot {
            NatStatusSnapshot {
                enabled: self.enabled,
                gateway_discovered: self.gateway_discovered,
                backend: self.backend.clone(),
                bind_ip: self.bind_ip.clone(),
                igd_ip: self.igd_ip.clone(),
                minissdpd_socket: self.minissdpd_socket.clone(),
                ssdp_local_port: self.ssdp_local_port,
                external_ip_override: self.external_ip_override.clone(),
                gateway: self.gateway.clone(),
                mappings: self.mappings.clone(),
                observed_external_addresses: self.observed_external_addresses.clone(),
                last_refresh_unix_secs: self.last_refresh_unix_secs,
                last_error: self.last_error.clone(),
            }
        }
    }
}

pub use types::{
    MappedEndpoint, MappingExposure, MappingSpec, NatStatus, NatStatusSnapshot, SelectedGateway,
    TransportProtocol,
};

/// MiniUPnPc backend identifier inherited from the original Rust agent.
pub const UPNP_MINIUPNPC_BACKEND: &str = "upnp_miniupnpc";
/// Deprecated `rupnp` backend identifier kept for explicit fallback compatibility.
pub const UPNP_RUPNP_BACKEND: &str = "upnp_rupnp";
/// Reserved backend identifier for a future pure Rust IGD implementation.
pub const UPNP_IGD_BACKEND: &str = "upnp_igd";

/// NAT traversal configuration loaded from the daemon config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NatConfig {
    pub enabled: bool,
    pub backend_order: Vec<String>,
    pub bind_ip: Option<String>,
    pub igd_ip: Option<String>,
    pub minissdpd_socket: Option<String>,
    pub ssdp_local_port: Option<u16>,
    pub discovery_timeout_secs: u64,
    pub lease_duration_secs: u32,
    pub renew_margin_secs: u64,
    pub external_ip_override: Option<String>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_order: default_upnp_backend_order(),
            bind_ip: None,
            igd_ip: None,
            minissdpd_socket: None,
            ssdp_local_port: None,
            discovery_timeout_secs: 5,
            lease_duration_secs: 3_600,
            renew_margin_secs: 300,
            external_ip_override: None,
        }
    }
}

/// Agent capability contract for runtimes that can describe NAT mappings.
#[async_trait]
pub trait NatCapableAgent: Send + Sync + 'static {
    fn nat_config(&self) -> NatConfig;
    fn nat_mappings(&self) -> Vec<MappingSpec>;
}

/// Backend interface for UPnP/NAT-PMP-style port mapping providers.
#[async_trait]
pub trait PortMappingProvider: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn reconcile(
        &self,
        config: &NatConfig,
        mappings: &[MappingSpec],
        status: Arc<RwLock<NatStatus>>,
    ) -> Result<()>;

    async fn release(
        &self,
        config: &NatConfig,
        mappings: &[MappedEndpoint],
        status: Arc<RwLock<NatStatus>>,
    ) -> Result<()>;
}

/// Callback surface for components that react to changed NAT reachability.
#[async_trait]
pub trait ReachabilityStrategy: Send + Sync + 'static {
    async fn on_nat_status_changed(&self, _status: NatStatus) {}
}

/// Reachability strategy used when no observer is configured.
#[derive(Debug, Default)]
pub struct NoopReachabilityStrategy;

#[async_trait]
impl ReachabilityStrategy for NoopReachabilityStrategy {}

/// Returns the default UPnP backend order used by the old Rust agent.
#[must_use]
pub fn default_upnp_backend_order() -> Vec<String> {
    vec![UPNP_MINIUPNPC_BACKEND.to_string()]
}

/// Returns compiled-in port mapping providers.
///
/// The eMuleBB Rust repository now owns the NAT contract and manager state. The
/// provider implementations are intentionally imported in later slices because
/// they carry separate MiniUPnPc and patched `rupnp` dependencies.
#[must_use]
pub fn built_in_upnp_port_mapping_providers() -> Vec<Arc<dyn PortMappingProvider>> {
    Vec::new()
}

/// Builder for one NAT manager instance.
pub struct NatManagerBuilder {
    config: NatConfig,
    mappings: Vec<MappingSpec>,
    providers: Vec<Arc<dyn PortMappingProvider>>,
    reachability: Arc<dyn ReachabilityStrategy>,
}

impl NatManagerBuilder {
    /// Creates a NAT manager builder from config.
    #[must_use]
    pub fn new(config: NatConfig) -> Self {
        Self {
            config,
            mappings: Vec::new(),
            providers: Vec::new(),
            reachability: Arc::new(NoopReachabilityStrategy),
        }
    }

    /// Sets desired local mappings.
    #[must_use]
    pub fn with_mappings(mut self, mappings: Vec<MappingSpec>) -> Self {
        self.mappings = mappings;
        self
    }

    /// Adds one provider implementation.
    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn PortMappingProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Adds provider implementations.
    #[must_use]
    pub fn with_providers(mut self, providers: Vec<Arc<dyn PortMappingProvider>>) -> Self {
        self.providers.extend(providers);
        self
    }

    /// Sets an observer for changed reachability status.
    #[must_use]
    pub fn with_reachability(mut self, reachability: Arc<dyn ReachabilityStrategy>) -> Self {
        self.reachability = reachability;
        self
    }

    /// Builds the NAT manager.
    #[must_use]
    pub fn build(self) -> NatManager {
        NatManager {
            config: self.config,
            mappings: self.mappings,
            providers: self.providers,
            reachability: self.reachability,
            status: Arc::new(RwLock::new(NatStatus::default())),
            task: Arc::new(Mutex::new(None)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Runtime NAT manager shared by the ED2K server session loop.
pub struct NatManager {
    config: NatConfig,
    mappings: Vec<MappingSpec>,
    providers: Vec<Arc<dyn PortMappingProvider>>,
    reachability: Arc<dyn ReachabilityStrategy>,
    status: Arc<RwLock<NatStatus>>,
    task: Arc<Mutex<Option<JoinHandle<()>>>>,
    shutdown: Arc<AtomicBool>,
}

impl Default for NatManager {
    fn default() -> Self {
        NatManagerBuilder::new(NatConfig::default()).build()
    }
}

impl NatManager {
    /// Starts NAT reconciliation when enabled by config.
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled || self.mappings.is_empty() {
            self.write_config_status(None).await;
            return Ok(());
        }

        let mut slot = self.task.lock().await;
        if slot.is_some() {
            return Ok(());
        }
        self.write_config_status(None).await;
        self.shutdown.store(false, Ordering::SeqCst);

        let config = self.config.clone();
        let mappings = self.mappings.clone();
        let providers = self.providers.clone();
        let status = Arc::clone(&self.status);
        let shutdown = Arc::clone(&self.shutdown);
        let reachability = Arc::clone(&self.reachability);
        *slot = Some(tokio::spawn(async move {
            run_manager_loop(config, mappings, providers, status, reachability, shutdown).await;
        }));
        Ok(())
    }

    /// Stops NAT reconciliation and asks providers to release active mappings.
    pub async fn stop(&self) -> Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.lock().await.take() {
            task.abort();
        }

        let status = self.status.read().await.clone();
        let mappings = if status.mappings.is_empty() {
            release_targets_from_specs(&self.mappings, self.config.lease_duration_secs)
        } else {
            status.mappings
        };
        if mappings.is_empty() {
            return Ok(());
        }

        for backend_name in release_backend_order(&status.backend, &self.config.backend_order) {
            if let Some(provider) = self
                .providers
                .iter()
                .find(|provider| provider.name() == backend_name.as_str())
            {
                let _ = provider
                    .release(&self.config, &mappings, Arc::clone(&self.status))
                    .await;
            }
        }
        Ok(())
    }

    /// Returns a cloned NAT status.
    pub async fn status(&self) -> NatStatus {
        self.status.read().await.clone()
    }

    async fn write_config_status(&self, last_error: Option<String>) {
        let mut status = self.status.write().await;
        status.enabled = self.config.enabled;
        status.bind_ip = self.config.bind_ip.clone();
        status.igd_ip = self.config.igd_ip.clone();
        status.minissdpd_socket = self.config.minissdpd_socket.clone();
        status.ssdp_local_port = self.config.ssdp_local_port;
        status.external_ip_override = self.config.external_ip_override.clone();
        status.last_error = last_error;
    }
}

async fn run_manager_loop(
    config: NatConfig,
    mappings: Vec<MappingSpec>,
    providers: Vec<Arc<dyn PortMappingProvider>>,
    status: Arc<RwLock<NatStatus>>,
    reachability: Arc<dyn ReachabilityStrategy>,
    shutdown: Arc<AtomicBool>,
) {
    let refresh_period = Duration::from_secs(
        config
            .lease_duration_secs
            .saturating_sub(config.renew_margin_secs as u32)
            .max(30)
            .into(),
    );

    while !shutdown.load(Ordering::Relaxed) {
        info!(
            "UPnP reconcile starting: bind_ip={} igd_ip={} backends={} mappings={}",
            option_display(config.bind_ip.as_deref(), "auto"),
            option_display(config.igd_ip.as_deref(), "auto"),
            backend_order_display(&config.backend_order),
            requested_mappings_display(&mappings)
        );
        match reconcile_once(&config, &mappings, &providers, Arc::clone(&status)).await {
            Ok(()) => {
                let snapshot = status.read().await.clone();
                info!(
                    "UPnP reconcile succeeded via backend {}: external_ip={} mappings={}",
                    option_display(snapshot.backend.as_deref(), "unknown"),
                    observed_external_ip_display(&snapshot.observed_external_addresses),
                    mapped_endpoints_display(&snapshot.mappings)
                );
                reachability.on_nat_status_changed(snapshot).await;
                tokio::time::sleep(refresh_period).await;
            }
            Err(error) => {
                warn!("nat mapping reconcile failed: {error}");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut guard = status.write().await;
                guard.enabled = config.enabled;
                guard.bind_ip = config.bind_ip.clone();
                guard.igd_ip = config.igd_ip.clone();
                guard.minissdpd_socket = config.minissdpd_socket.clone();
                guard.ssdp_local_port = config.ssdp_local_port;
                guard.external_ip_override = config.external_ip_override.clone();
                guard.last_error = Some(error.to_string());
                guard.last_refresh_unix_secs = Some(now);
                drop(guard);
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

async fn reconcile_once(
    config: &NatConfig,
    mappings: &[MappingSpec],
    providers: &[Arc<dyn PortMappingProvider>],
    status: Arc<RwLock<NatStatus>>,
) -> Result<()> {
    let mut backend_errors = Vec::new();
    for backend_name in &config.backend_order {
        let Some(provider) = providers
            .iter()
            .find(|provider| provider.name() == backend_name.as_str())
        else {
            backend_errors.push(format!(
                "{backend_name}: backend not available in this build"
            ));
            continue;
        };

        match provider
            .reconcile(config, mappings, Arc::clone(&status))
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) => backend_errors.push(format!("{backend_name}: {error}")),
        }
    }

    let count = config.backend_order.len();
    let noun = if count == 1 { "backend" } else { "backends" };
    Err(anyhow!(
        "UPnP reconcile failed after {count} {noun}: {}",
        backend_errors.join("; ")
    ))
}

fn release_targets_from_specs(
    mappings: &[MappingSpec],
    lease_duration_secs: u32,
) -> Vec<MappedEndpoint> {
    mappings
        .iter()
        .map(|spec| MappedEndpoint {
            name: spec.name.clone(),
            protocol: spec.protocol,
            local_addr: spec.local_addr,
            external_addr: spec.local_addr,
            lease_expires_in_secs: lease_duration_secs,
            backend: String::new(),
        })
        .collect()
}

fn release_backend_order(
    selected_backend: &Option<String>,
    configured_order: &[String],
) -> Vec<String> {
    let mut order = Vec::new();
    if let Some(selected_backend) = selected_backend {
        order.push(selected_backend.clone());
    }
    for backend in configured_order {
        if !order.iter().any(|existing| existing == backend) {
            order.push(backend.clone());
        }
    }
    order
}

fn option_display(value: Option<&str>, fallback: &str) -> String {
    value.unwrap_or(fallback).to_string()
}

fn backend_order_display(backends: &[String]) -> String {
    if backends.is_empty() {
        return "none".to_string();
    }
    backends.join(",")
}

fn requested_mappings_display(mappings: &[MappingSpec]) -> String {
    if mappings.is_empty() {
        return "none".to_string();
    }
    mappings
        .iter()
        .map(|mapping| {
            format!(
                "{}:{}:{}",
                mapping.name,
                mapping.protocol.as_upnp_token(),
                mapping.local_addr
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn observed_external_ip_display(addresses: &[String]) -> String {
    if addresses.is_empty() {
        return "unknown".to_string();
    }
    addresses.join(",")
}

fn mapped_endpoints_display(mappings: &[MappedEndpoint]) -> String {
    if mappings.is_empty() {
        return "none".to_string();
    }
    mappings
        .iter()
        .map(|mapping| {
            format!(
                "{}:{}:{}->{}",
                mapping.name,
                mapping.protocol.as_upnp_token(),
                mapping.local_addr,
                mapping.external_addr
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FakeProvider {
        name: &'static str,
        failures_before_success: AtomicUsize,
        reconcile_calls: AtomicUsize,
        release_calls: AtomicUsize,
    }

    #[async_trait]
    impl PortMappingProvider for FakeProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn reconcile(
            &self,
            config: &NatConfig,
            mappings: &[MappingSpec],
            status: Arc<RwLock<NatStatus>>,
        ) -> Result<()> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            if self.failures_before_success.load(Ordering::SeqCst) > 0 {
                self.failures_before_success.fetch_sub(1, Ordering::SeqCst);
                return Err(anyhow!("boom"));
            }
            let mut guard = status.write().await;
            guard.enabled = config.enabled;
            guard.bind_ip = config.bind_ip.clone();
            guard.igd_ip = config.igd_ip.clone();
            guard.minissdpd_socket = config.minissdpd_socket.clone();
            guard.ssdp_local_port = config.ssdp_local_port;
            guard.external_ip_override = config.external_ip_override.clone();
            guard.gateway_discovered = config.igd_ip.is_some();
            guard.backend = Some(self.name.to_string());
            guard.mappings = mappings
                .iter()
                .map(|spec| MappedEndpoint {
                    name: spec.name.clone(),
                    protocol: spec.protocol,
                    local_addr: spec.local_addr,
                    external_addr: spec.local_addr,
                    lease_expires_in_secs: config.lease_duration_secs,
                    backend: self.name.to_string(),
                })
                .collect();
            guard.observed_external_addresses = config
                .external_ip_override
                .clone()
                .into_iter()
                .collect::<Vec<_>>();
            Ok(())
        }

        async fn release(
            &self,
            _config: &NatConfig,
            _mappings: &[MappedEndpoint],
            _status: Arc<RwLock<NatStatus>>,
        ) -> Result<()> {
            self.release_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn sample_mapping() -> MappingSpec {
        MappingSpec {
            name: "kad".to_string(),
            local_addr: "192.0.2.10:41000".parse().unwrap(),
            protocol: TransportProtocol::Udp,
            exposure: MappingExposure::Required,
            preferred_external_port: None,
        }
    }

    #[test]
    fn default_nat_config_prefers_miniupnpc_only() {
        assert_eq!(
            NatConfig::default().backend_order,
            vec![UPNP_MINIUPNPC_BACKEND.to_string()]
        );
    }

    #[test]
    fn built_in_providers_are_pending_external_dependency_import() {
        assert!(built_in_upnp_port_mapping_providers().is_empty());
    }

    #[tokio::test]
    async fn disabled_start_records_config_status_without_task() {
        let manager = NatManagerBuilder::new(NatConfig {
            bind_ip: Some("192.0.2.10".to_string()),
            external_ip_override: Some("203.0.113.10".to_string()),
            ..NatConfig::default()
        })
        .with_mappings(vec![sample_mapping()])
        .build();

        manager.start().await.unwrap();
        let status = manager.status().await;

        assert!(!status.enabled);
        assert_eq!(status.bind_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(status.external_ip_override.as_deref(), Some("203.0.113.10"));
        assert!(status.last_error.is_none());
    }

    #[tokio::test]
    async fn reconcile_once_uses_matching_backend() {
        let provider = Arc::new(FakeProvider {
            name: UPNP_RUPNP_BACKEND,
            failures_before_success: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            release_calls: AtomicUsize::new(0),
        });
        let status = Arc::new(RwLock::new(NatStatus::default()));
        let config = NatConfig {
            enabled: true,
            backend_order: vec![UPNP_RUPNP_BACKEND.to_string()],
            bind_ip: Some("192.0.2.10".to_string()),
            igd_ip: Some("192.0.2.1".to_string()),
            external_ip_override: Some("203.0.113.10".to_string()),
            ..NatConfig::default()
        };

        reconcile_once(
            &config,
            &[sample_mapping()],
            &[provider],
            Arc::clone(&status),
        )
        .await
        .unwrap();

        let status = status.read().await.clone();
        assert_eq!(status.backend.as_deref(), Some(UPNP_RUPNP_BACKEND));
        assert_eq!(status.bind_ip.as_deref(), Some("192.0.2.10"));
        assert_eq!(status.igd_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(status.observed_external_addresses, ["203.0.113.10"]);
        assert_eq!(status.mappings.len(), 1);
    }

    #[tokio::test]
    async fn reconcile_once_reports_unavailable_backend() {
        let status = Arc::new(RwLock::new(NatStatus::default()));
        let config = NatConfig {
            enabled: true,
            backend_order: vec!["unknown_backend".to_string()],
            ..NatConfig::default()
        };

        let error = reconcile_once(&config, &[sample_mapping()], &[], Arc::clone(&status))
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "UPnP reconcile failed after 1 backend: unknown_backend: backend not available in this build"
        );
    }

    #[tokio::test]
    async fn stop_releases_selected_backend_before_fallback_backends() {
        let selected_provider = Arc::new(FakeProvider {
            name: UPNP_RUPNP_BACKEND,
            failures_before_success: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            release_calls: AtomicUsize::new(0),
        });
        let fallback_provider = Arc::new(FakeProvider {
            name: UPNP_MINIUPNPC_BACKEND,
            failures_before_success: AtomicUsize::new(0),
            reconcile_calls: AtomicUsize::new(0),
            release_calls: AtomicUsize::new(0),
        });
        let manager = NatManagerBuilder::new(NatConfig {
            enabled: true,
            backend_order: vec![
                UPNP_MINIUPNPC_BACKEND.to_string(),
                UPNP_RUPNP_BACKEND.to_string(),
            ],
            ..NatConfig::default()
        })
        .with_mappings(vec![sample_mapping()])
        .with_provider(selected_provider.clone())
        .with_provider(fallback_provider.clone())
        .build();

        {
            let mut status = manager.status.write().await;
            status.backend = Some(UPNP_RUPNP_BACKEND.to_string());
            status.mappings = vec![MappedEndpoint {
                name: "kad".to_string(),
                protocol: TransportProtocol::Udp,
                local_addr: "192.0.2.10:41000".parse().unwrap(),
                external_addr: "203.0.113.10:41000".parse().unwrap(),
                lease_expires_in_secs: 300,
                backend: UPNP_RUPNP_BACKEND.to_string(),
            }];
        }

        manager.stop().await.unwrap();

        assert_eq!(selected_provider.release_calls.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_provider.release_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn status_snapshot_detaches_current_state() {
        let mut status = NatStatus {
            enabled: true,
            backend: Some(UPNP_MINIUPNPC_BACKEND.to_string()),
            observed_external_addresses: vec!["203.0.113.10".to_string()],
            ..NatStatus::default()
        };

        let snapshot = status.snapshot();
        status.observed_external_addresses.clear();

        assert!(snapshot.enabled);
        assert_eq!(snapshot.backend.as_deref(), Some(UPNP_MINIUPNPC_BACKEND));
        assert_eq!(snapshot.observed_external_addresses, ["203.0.113.10"]);
    }
}
