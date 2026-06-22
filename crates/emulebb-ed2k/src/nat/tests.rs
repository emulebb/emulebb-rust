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
fn built_in_providers_use_explicit_backend_ids() {
    let provider_names = built_in_upnp_port_mapping_providers()
        .into_iter()
        .map(|provider| provider.name().to_string())
        .collect::<Vec<_>>();

    assert_eq!(
        provider_names,
        [
            UPNP_MINIUPNPC_BACKEND.to_string(),
            UPNP_RUPNP_BACKEND.to_string(),
            UPNP_IGD_BACKEND.to_string(),
        ]
    );
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
async fn reconcile_now_awaits_mapping_before_returning() {
    // Connection ordering: reconcile_now must run the reconcile synchronously so a
    // caller can await the forwarded port BEFORE sending the eD2k login (HighID on
    // first connect). On return the mapped external port is already in status.
    let provider = Arc::new(FakeProvider {
        name: UPNP_MINIUPNPC_BACKEND,
        failures_before_success: AtomicUsize::new(0),
        reconcile_calls: AtomicUsize::new(0),
        release_calls: AtomicUsize::new(0),
    });
    let manager = NatManagerBuilder::new(NatConfig {
        enabled: true,
        backend_order: vec![UPNP_MINIUPNPC_BACKEND.to_string()],
        bind_ip: Some("192.0.2.10".to_string()),
        ..NatConfig::default()
    })
    .with_mappings(vec![sample_mapping()])
    .with_provider(provider.clone())
    .build();

    manager.reconcile_now().await.unwrap();

    assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
    let status = manager.status().await;
    assert_eq!(status.mappings.len(), 1);
    assert_eq!(status.backend.as_deref(), Some(UPNP_MINIUPNPC_BACKEND));
}

#[tokio::test]
async fn reconcile_now_is_noop_when_disabled() {
    // NAT disabled / no mappings is "definitively unavailable": reconcile_now
    // returns Ok immediately so connect proceeds without waiting and never calls a
    // backend.
    let provider = Arc::new(FakeProvider {
        name: UPNP_MINIUPNPC_BACKEND,
        failures_before_success: AtomicUsize::new(0),
        reconcile_calls: AtomicUsize::new(0),
        release_calls: AtomicUsize::new(0),
    });
    let manager = NatManagerBuilder::new(NatConfig {
        enabled: false,
        ..NatConfig::default()
    })
    .with_mappings(vec![sample_mapping()])
    .with_provider(provider.clone())
    .build();

    manager.reconcile_now().await.unwrap();

    assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn reconcile_now_propagates_backend_failure() {
    // Every backend failing surfaces as Err so the caller can log it and connect
    // best-effort with internal ports instead of blocking startup.
    let provider = Arc::new(FakeProvider {
        name: UPNP_MINIUPNPC_BACKEND,
        failures_before_success: AtomicUsize::new(1),
        reconcile_calls: AtomicUsize::new(0),
        release_calls: AtomicUsize::new(0),
    });
    let manager = NatManagerBuilder::new(NatConfig {
        enabled: true,
        backend_order: vec![UPNP_MINIUPNPC_BACKEND.to_string()],
        ..NatConfig::default()
    })
    .with_mappings(vec![sample_mapping()])
    .with_provider(provider.clone())
    .build();

    assert!(manager.reconcile_now().await.is_err());
    assert_eq!(provider.reconcile_calls.load(Ordering::SeqCst), 1);
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
