use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use emulebb_miniupnpc::{DiscoveryOptions, Gateway, PortMappingEntry, gateway_from_url};
use tokio::{sync::RwLock, task};
use tracing::{info, warn};

use super::{
    MappedEndpoint, MappingSpec, NatConfig, NatStatus, PortMappingProvider, SelectedGateway,
    UPNP_MINIUPNPC_BACKEND,
};

#[derive(Debug, Default)]
pub struct MiniupnpcPortMappingProvider;

#[derive(Debug)]
struct ReconcileOutcome {
    gateway: SelectedGateway,
    observed_external_addresses: Vec<String>,
    mappings: Vec<MappedEndpoint>,
}

#[async_trait]
impl PortMappingProvider for MiniupnpcPortMappingProvider {
    fn name(&self) -> &'static str {
        UPNP_MINIUPNPC_BACKEND
    }

    async fn reconcile(
        &self,
        config: &NatConfig,
        mappings: &[MappingSpec],
        status: Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        if mappings.is_empty() {
            return Ok(());
        }

        info!(
            "UPnP backend {} starting discovery: bind_ip={} igd_ip={} mappings={}",
            self.name(),
            option_display(config.bind_ip.as_deref(), "auto"),
            option_display(config.igd_ip.as_deref(), "auto"),
            mapping_specs_display(mappings)
        );

        let backend_name = self.name().to_string();
        let config = config.clone();
        let status_config = config.clone();
        let mappings = mappings.to_vec();
        let outcome =
            task::spawn_blocking(move || reconcile_blocking(&backend_name, &config, &mappings))
                .await
                .context("miniupnpc reconcile task failed")??;

        info!(
            "UPnP backend {} selected gateway {} local_ip={} external_ip={}",
            self.name(),
            outcome.gateway.control_url,
            option_display(outcome.gateway.local_ip.as_deref(), "unknown"),
            option_display(outcome.gateway.external_ip.as_deref(), "unknown")
        );
        info!(
            "UPnP backend {} reconcile complete: mappings={}",
            self.name(),
            mapped_endpoints_display(&outcome.mappings)
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut guard = status.write().await;
        guard.enabled = true;
        guard.gateway_discovered = true;
        guard.backend = Some(self.name().to_string());
        guard.bind_ip = status_config.bind_ip.clone();
        guard.igd_ip = status_config.igd_ip.clone();
        guard.minissdpd_socket = status_config.minissdpd_socket.clone();
        guard.ssdp_local_port = status_config.ssdp_local_port;
        guard.external_ip_override = status_config.external_ip_override.clone();
        guard.gateway = Some(outcome.gateway);
        guard.observed_external_addresses = outcome.observed_external_addresses;
        guard.mappings = outcome.mappings;
        guard.last_refresh_unix_secs = Some(now);
        guard.last_error = None;
        Ok(())
    }

    async fn release(
        &self,
        config: &NatConfig,
        mappings: &[MappedEndpoint],
        status: Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        if mappings.is_empty() {
            return Ok(());
        }

        info!(
            "UPnP backend {} releasing mappings: {}",
            self.name(),
            mapped_endpoints_display(mappings)
        );

        let config = config.clone();
        let mappings = mappings.to_vec();
        task::spawn_blocking(move || release_blocking(&config, &mappings))
            .await
            .context("miniupnpc release task failed")??;

        info!("UPnP backend {} release complete", self.name());

        let mut guard = status.write().await;
        guard.mappings.clear();
        Ok(())
    }
}

#[allow(clippy::cognitive_complexity)]
fn reconcile_blocking(
    backend_name: &str,
    config: &NatConfig,
    mappings: &[MappingSpec],
) -> Result<ReconcileOutcome> {
    let gateway = discover_gateway(config).context("gateway discovery failed")?;
    let local_ip = gateway_local_ip(config, &gateway).with_context(|| {
        format!(
            "gateway {} did not provide a usable LAN IPv4",
            gateway.control_url()
        )
    })?;
    let external_ip_text = config
        .external_ip_override
        .clone()
        .or_else(|| gateway.fetch_external_ip().ok().flatten())
        .or_else(|| gateway.external_ip().map(ToString::to_string));

    info!(
        "UPnP backend {} using gateway {} gateway_ip={} local_ip={}",
        backend_name,
        gateway.control_url(),
        option_display(gateway.gateway_ip(), "unknown"),
        local_ip
    );

    let mut applied = Vec::new();
    let mut mapped = Vec::with_capacity(mappings.len());
    for spec in mappings {
        let external_port = spec
            .preferred_external_port
            .unwrap_or_else(|| spec.local_addr.port());
        let internal_ip = mapping_internal_ip(config, spec, &local_ip).to_string();
        if let Err(error) = gateway
            .add_port_mapping(
                external_port,
                spec.local_addr.port(),
                &internal_ip,
                &spec.name,
                spec.protocol.as_upnp_token(),
                config.lease_duration_secs,
            )
            .with_context(|| {
                format!(
                    "gateway {} failed to add {} mapping",
                    gateway.control_url(),
                    spec.name
                )
            })
        {
            if !mapping_matches_existing_entry(
                &gateway,
                external_port,
                spec.protocol.as_upnp_token(),
                &internal_ip,
                spec.local_addr.port(),
            )
            .with_context(|| {
                format!(
                    "gateway {} failed to inspect existing {} mapping",
                    gateway.control_url(),
                    spec.name
                )
            })? {
                for (protocol, port) in applied.into_iter().rev() {
                    let _ = gateway.delete_port_mapping(port, protocol);
                }
                return Err(error);
            }
            info!(
                "UPnP backend {} reused existing {} mapping {} external_port={} internal={}{}{}",
                backend_name,
                spec.name,
                spec.protocol.as_upnp_token(),
                external_port,
                internal_ip,
                ":",
                spec.local_addr.port()
            );
        } else {
            applied.push((spec.protocol.as_upnp_token(), external_port));
            info!(
                "UPnP backend {} added {} mapping {} external_port={} internal={}{}{}",
                backend_name,
                spec.name,
                spec.protocol.as_upnp_token(),
                external_port,
                internal_ip,
                ":",
                spec.local_addr.port()
            );
        }

        let external_ip = external_ip_text
            .clone()
            .unwrap_or_else(|| local_ip.to_string())
            .parse::<IpAddr>()
            .with_context(|| format!("invalid external ip for {}", spec.name))?;
        mapped.push(MappedEndpoint {
            name: spec.name.clone(),
            protocol: spec.protocol,
            local_addr: spec.local_addr,
            external_addr: SocketAddr::new(external_ip, external_port),
            lease_expires_in_secs: config.lease_duration_secs,
            backend: backend_name.to_string(),
        });
    }

    info!(
        "UPnP backend {} reconcile succeeded for gateway {}: external_ip={} mappings={}",
        backend_name,
        gateway.control_url(),
        option_display(external_ip_text.as_deref(), "unknown"),
        mapped_endpoints_display(&mapped)
    );

    Ok(ReconcileOutcome {
        gateway: SelectedGateway {
            backend: backend_name.to_string(),
            control_url: gateway.control_url().to_string(),
            local_ip: gateway.local_ip().map(ToString::to_string),
            gateway_ip: gateway.gateway_ip().map(ToString::to_string),
            external_ip: external_ip_text.clone(),
        },
        observed_external_addresses: external_ip_text.into_iter().collect(),
        mappings: mapped,
    })
}

fn release_blocking(config: &NatConfig, mappings: &[MappedEndpoint]) -> Result<()> {
    let gateway = discover_gateway(config).context("gateway discovery failed during release")?;
    info!(
        "UPnP backend {} releasing mappings via gateway {}",
        UPNP_MINIUPNPC_BACKEND,
        gateway.control_url()
    );
    for mapping in mappings {
        info!(
            "UPnP backend {} releasing {} mapping {} external_port={}",
            UPNP_MINIUPNPC_BACKEND,
            mapping.name,
            mapping.protocol.as_upnp_token(),
            mapping.external_addr.port()
        );
        if let Err(error) = gateway.delete_port_mapping(
            mapping.external_addr.port(),
            mapping.protocol.as_upnp_token(),
        ) {
            warn!(
                "UPnP backend {} failed to release {} mapping {} external_port={}: {}",
                UPNP_MINIUPNPC_BACKEND,
                mapping.name,
                mapping.protocol.as_upnp_token(),
                mapping.external_addr.port(),
                error
            );
        }
    }
    Ok(())
}

fn discover_gateway(config: &NatConfig) -> Result<Gateway> {
    info!(
        "UPnP backend {} discovery starting: bind_ip={} igd_ip={}",
        UPNP_MINIUPNPC_BACKEND,
        option_display(config.bind_ip.as_deref(), "auto"),
        option_display(config.igd_ip.as_deref(), "auto")
    );
    if let Some(igd_ip) = config.igd_ip.as_deref() {
        for root_description_url in candidate_root_description_urls(igd_ip) {
            if let Some(gateway) = gateway_from_url(&root_description_url)? {
                info!(
                    "UPnP backend {} direct IGD probe succeeded for configured gateway {} via {}",
                    UPNP_MINIUPNPC_BACKEND, igd_ip, root_description_url
                );
                return Ok(gateway);
            }
        }
        return Err(anyhow!("no matching IGD found for configured nat.igd_ip"));
    }

    let (discovery, gateway) = emulebb_miniupnpc::discover(&DiscoveryOptions {
        timeout: Duration::from_secs(config.discovery_timeout_secs.max(1)),
        multicast_interface: config.bind_ip.clone(),
        minissdpd_socket: config.minissdpd_socket.as_ref().map(PathBuf::from),
        local_port: config.ssdp_local_port,
        ..DiscoveryOptions::default()
    })?;

    info!(
        "UPnP backend {} discovery found {} device(s); gateway discovered={}",
        UPNP_MINIUPNPC_BACKEND,
        discovery.devices.len(),
        discovery.gateway.is_some()
    );

    if let Some(gateway) = gateway {
        return Ok(gateway);
    }

    if let Some(bind_ip) = config.bind_ip.as_deref() {
        Err(anyhow!(
            "no UPnP IGD service discovered for nat.bind_ip {bind_ip}; on point-to-point VPNs you may need to set nat.igd_ip explicitly"
        ))
    } else {
        Err(anyhow!("no UPnP IGD service discovered"))
    }
}

fn candidate_root_description_urls(igd_ip: &str) -> [String; 4] {
    [
        format!("http://{igd_ip}:1900/gateDesc.xml"),
        format!("http://{igd_ip}:1900/rootDesc.xml"),
        format!("http://{igd_ip}:5000/rootDesc.xml"),
        format!("http://{igd_ip}:49152/rootDesc.xml"),
    ]
}

fn gateway_local_ip(config: &NatConfig, gateway: &Gateway) -> Result<Ipv4Addr> {
    if let Some(bind_ip) = config.bind_ip.as_deref()
        && let Ok(IpAddr::V4(ip)) = bind_ip.parse::<IpAddr>()
    {
        return Ok(ip);
    }
    if let Some(local_ip) = gateway.local_ip()
        && let Ok(IpAddr::V4(ip)) = local_ip.parse::<IpAddr>()
    {
        return Ok(ip);
    }
    Err(anyhow!(
        "miniupnpc did not provide a usable IPv4 LAN address"
    ))
}

fn mapping_internal_ip(
    config: &NatConfig,
    spec: &MappingSpec,
    gateway_local_ip: &Ipv4Addr,
) -> Ipv4Addr {
    if !spec.local_addr.ip().is_unspecified() {
        return match spec.local_addr.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
        };
    }
    if let Some(bind_ip) = config.bind_ip.as_deref()
        && let Ok(IpAddr::V4(ip)) = bind_ip.parse::<IpAddr>()
    {
        return ip;
    }
    *gateway_local_ip
}

fn mapping_matches_existing_entry(
    gateway: &Gateway,
    external_port: u16,
    protocol: &str,
    expected_internal_ip: &str,
    expected_internal_port: u16,
) -> Result<bool> {
    let Some(entry) = gateway.get_specific_port_mapping(external_port, protocol)? else {
        return Ok(false);
    };
    Ok(existing_mapping_matches(
        &entry,
        expected_internal_ip,
        expected_internal_port,
    ))
}

fn existing_mapping_matches(
    entry: &PortMappingEntry,
    expected_internal_ip: &str,
    expected_internal_port: u16,
) -> bool {
    entry.internal_client == expected_internal_ip && entry.internal_port == expected_internal_port
}

fn mapping_specs_display(mappings: &[MappingSpec]) -> String {
    if mappings.is_empty() {
        return "none".to_string();
    }

    mappings
        .iter()
        .map(|mapping| {
            let external_port = mapping
                .preferred_external_port
                .unwrap_or_else(|| mapping.local_addr.port());
            format!(
                "{} {}/{} -> {}",
                mapping.name,
                mapping.protocol.as_upnp_token(),
                external_port,
                mapping.local_addr
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn mapped_endpoints_display(mappings: &[MappedEndpoint]) -> String {
    if mappings.is_empty() {
        return "none".to_string();
    }

    mappings
        .iter()
        .map(|mapping| {
            format!(
                "{} {}/{} -> {}",
                mapping.name,
                mapping.protocol.as_upnp_token(),
                mapping.external_addr.port(),
                mapping.local_addr
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn option_display<'a>(value: Option<&'a str>, fallback: &'a str) -> &'a str {
    value.unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use emulebb_miniupnpc::PortMappingEntry;

    use super::existing_mapping_matches;

    #[test]
    fn existing_mapping_match_requires_same_ip_and_port() {
        let entry = PortMappingEntry {
            internal_client: "10.54.220.34".to_string(),
            internal_port: 41000,
            description: Some("kad".to_string()),
            enabled: Some(true),
            lease_duration_secs: Some(3600),
        };

        assert!(existing_mapping_matches(&entry, "10.54.220.34", 41000));
        assert!(!existing_mapping_matches(&entry, "10.54.220.35", 41000));
        assert!(!existing_mapping_matches(&entry, "10.54.220.34", 41001));
    }
}
