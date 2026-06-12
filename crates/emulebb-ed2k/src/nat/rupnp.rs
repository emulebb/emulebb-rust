//! Deprecated and frozen UPnP backend based on `rupnp`.
//!
//! Keep this backend only for explicit opt-in fallback support.
//! Do not add new features, behavior changes, or new tests in this module.

use std::{
    cmp::Reverse,
    collections::HashSet,
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use futures_util::TryStreamExt;
use rupnp::{
    Device, Service,
    ssdp::{SearchTarget, URN},
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{sync::RwLock, task};
use tracing::{debug, info, warn};

use super::{
    MappedEndpoint, MappingSpec, NatConfig, NatStatus, PortMappingProvider, SelectedGateway,
    UPNP_RUPNP_BACKEND,
};

const INTERNET_GATEWAY_DEVICE_1: URN = URN::device("schemas-upnp-org", "InternetGatewayDevice", 1);
const INTERNET_GATEWAY_DEVICE_2: URN = URN::device("schemas-upnp-org", "InternetGatewayDevice", 2);
const WAN_IP_CONNECTION_1: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
const WAN_IP_CONNECTION_2: URN = URN::service("schemas-upnp-org", "WANIPConnection", 2);
const WAN_PPP_CONNECTION_1: URN = URN::service("schemas-upnp-org", "WANPPPConnection", 1);

/// Deprecated frozen backend retained only for explicit opt-in compatibility.
///
/// No further development or new tests should be added for this backend.
#[deprecated(
    note = "upnp_rupnp is deprecated and frozen; keep it only for explicit opt-in fallback support"
)]
#[derive(Debug, Default)]
pub struct RupnpPortMappingProvider;

#[derive(Clone)]
struct GatewayHandle {
    device: Device,
    service: Service,
}

#[async_trait]
#[allow(deprecated)]
impl PortMappingProvider for RupnpPortMappingProvider {
    fn name(&self) -> &'static str {
        UPNP_RUPNP_BACKEND
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

        let gateways = discover_gateways(config).await?;
        let mut last_error = None;
        for gateway in gateways {
            info!(
                "UPnP backend {} evaluating gateway {}",
                self.name(),
                gateway.device.url()
            );
            match reconcile_gateway(self.name(), &gateway, config, mappings, Arc::clone(&status))
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    info!(
                        "UPnP backend {} gateway {} failed during reconcile: {}",
                        self.name(),
                        gateway.device.url(),
                        error
                    );
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("no usable UPnP IGD service discovered")))
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
        for gateway in discover_gateways(config).await? {
            info!(
                "UPnP backend {} releasing mappings via gateway {}",
                self.name(),
                gateway.device.url()
            );
            for mapping in mappings {
                let spec = MappingSpec {
                    name: mapping.name.clone(),
                    local_addr: mapping.local_addr,
                    protocol: mapping.protocol,
                    exposure: Default::default(),
                    preferred_external_port: Some(mapping.external_addr.port()),
                };
                info!(
                    "UPnP backend {} releasing {} mapping {} external_port={}",
                    self.name(),
                    mapping.name,
                    mapping.protocol.as_upnp_token(),
                    mapping.external_addr.port()
                );
                if let Err(error) = gateway
                    .delete_mapping(&spec, mapping.external_addr.port())
                    .await
                {
                    warn!(
                        "UPnP backend {} failed to release {} mapping {} external_port={}: {}",
                        self.name(),
                        mapping.name,
                        mapping.protocol.as_upnp_token(),
                        mapping.external_addr.port(),
                        error
                    );
                }
            }
        }
        info!("UPnP backend {} release complete", self.name());
        let mut guard = status.write().await;
        guard.mappings.clear();
        Ok(())
    }
}

#[allow(clippy::cognitive_complexity)]
async fn reconcile_gateway(
    backend_name: &str,
    gateway: &GatewayHandle,
    config: &NatConfig,
    mappings: &[MappingSpec],
    status: Arc<RwLock<NatStatus>>,
) -> Result<()> {
    let external_ip_text = if let Some(override_ip) = config.external_ip_override.clone() {
        Some(override_ip)
    } else {
        gateway.external_ip().await.ok()
    };

    info!(
        "UPnP backend {} using gateway {} gateway_ip={} external_ip={}",
        backend_name,
        gateway.device.url(),
        gateway.device.url().host().unwrap_or("unknown"),
        option_display(external_ip_text.as_deref(), "unknown")
    );

    let mut mapped = Vec::with_capacity(mappings.len());
    let mut applied = Vec::with_capacity(mappings.len());
    for spec in mappings {
        let external_port = spec
            .preferred_external_port
            .unwrap_or_else(|| spec.local_addr.port());
        if let Err(error) = gateway
            .add_mapping(config, config.lease_duration_secs, spec, external_port)
            .await
            .with_context(|| {
                format!(
                    "gateway {} failed to add {} mapping",
                    gateway.device.url(),
                    spec.name
                )
            })
        {
            for (applied_spec, applied_port) in applied.into_iter().rev() {
                let _ = gateway.delete_mapping(applied_spec, applied_port).await;
            }
            return Err(error);
        }
        applied.push((spec, external_port));
        info!(
            "UPnP backend {} added {} mapping {} external_port={} internal={}:{}",
            backend_name,
            spec.name,
            spec.protocol.as_upnp_token(),
            external_port,
            gateway.mapping_internal_ip(config, spec),
            spec.local_addr.port()
        );

        let external_ip = external_ip_text
            .clone()
            .unwrap_or_else(|| gateway.mapping_internal_ip(config, spec).to_string())
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
        gateway.device.url(),
        option_display(external_ip_text.as_deref(), "unknown"),
        mapped_endpoints_display(&mapped)
    );

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut guard = status.write().await;
    guard.enabled = true;
    guard.gateway_discovered = true;
    guard.backend = Some(backend_name.to_string());
    guard.bind_ip = config.bind_ip.clone();
    guard.igd_ip = config.igd_ip.clone();
    guard.minissdpd_socket = config.minissdpd_socket.clone();
    guard.ssdp_local_port = config.ssdp_local_port;
    guard.external_ip_override = config.external_ip_override.clone();
    guard.gateway = Some(gateway.selected_gateway(external_ip_text.clone()));
    guard.observed_external_addresses = external_ip_text.into_iter().collect();
    guard.mappings = mapped;
    guard.last_refresh_unix_secs = Some(now);
    guard.last_error = None;
    Ok(())
}

impl GatewayHandle {
    async fn add_mapping(
        &self,
        config: &NatConfig,
        lease_secs: u32,
        spec: &MappingSpec,
        external_port: u16,
    ) -> Result<()> {
        let local_ip = self.mapping_internal_ip(config, spec);
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{}</NewProtocol>\
             <NewInternalPort>{}</NewInternalPort>\
             <NewInternalClient>{}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{}</NewPortMappingDescription>\
             <NewLeaseDuration>{lease_secs}</NewLeaseDuration>",
            spec.protocol.as_upnp_token(),
            spec.local_addr.port(),
            local_ip,
            xml_escape(&spec.name),
        );
        self.service
            .action(self.device.url(), "AddPortMapping", &args)
            .await
            .map(|_| ())
            .context("AddPortMapping failed")
    }

    async fn delete_mapping(&self, spec: &MappingSpec, external_port: u16) -> Result<()> {
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>{}</NewProtocol>",
            spec.protocol.as_upnp_token(),
        );
        self.service
            .action(self.device.url(), "DeletePortMapping", &args)
            .await
            .map(|_| ())
            .context("DeletePortMapping failed")
    }

    async fn external_ip(&self) -> Result<String> {
        let response = self
            .service
            .action(self.device.url(), "GetExternalIPAddress", "")
            .await
            .context("GetExternalIPAddress failed")?;
        response
            .get("NewExternalIPAddress")
            .cloned()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("UPnP gateway did not return an external IP"))
    }

    fn mapping_internal_ip(&self, config: &NatConfig, spec: &MappingSpec) -> Ipv4Addr {
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
        Ipv4Addr::LOCALHOST
    }

    fn selected_gateway(&self, external_ip: Option<String>) -> SelectedGateway {
        SelectedGateway {
            backend: UPNP_RUPNP_BACKEND.to_string(),
            control_url: self.device.url().to_string(),
            local_ip: None,
            gateway_ip: self.device.url().host().map(ToString::to_string),
            external_ip,
        }
    }
}

#[allow(clippy::cognitive_complexity)]
async fn discover_gateways(config: &NatConfig) -> Result<Vec<GatewayHandle>> {
    let bind_ip = config
        .bind_ip
        .as_deref()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .with_context(|| format!("invalid nat.bind_ip {ip}"))
        })
        .transpose()?;
    let timeout = Duration::from_secs(config.discovery_timeout_secs.max(1));

    info!(
        "UPnP backend {} discovery starting: bind_ip={} igd_ip={} timeout_secs={}",
        UPNP_RUPNP_BACKEND,
        option_display(config.bind_ip.as_deref(), "auto"),
        option_display(config.igd_ip.as_deref(), "auto"),
        timeout.as_secs()
    );

    if let Some(igd_ip) = config.igd_ip.as_deref()
        && let Some(gateway) = discover_gateway_from_configured_ip(igd_ip).await?
    {
        info!(
            "UPnP backend {} direct IGD probe succeeded for configured gateway {}",
            UPNP_RUPNP_BACKEND, igd_ip
        );
        return Ok(vec![gateway]);
    }

    let mut gateways = Vec::new();
    let mut seen_gateways = HashSet::new();
    let mut fallback_gateway_ips = Vec::new();

    if let Some(bind_ip) = bind_ip {
        match discover_root_devices_via_bind_ip(bind_ip, timeout).await {
            Ok(devices) => {
                info!(
                    "UPnP backend {} bind-ip discovery on {} returned {} root devices",
                    UPNP_RUPNP_BACKEND,
                    bind_ip,
                    devices.len()
                );
                record_devices(
                    devices,
                    config.igd_ip.as_deref(),
                    &mut fallback_gateway_ips,
                    &mut gateways,
                    &mut seen_gateways,
                );
            }
            Err(error) => {
                debug!("UPnP bind-ip SSDP discovery on {bind_ip} failed: {error}");
            }
        }

        if gateways.is_empty() {
            match discover_root_devices(timeout).await {
                Ok(devices) => {
                    info!(
                        "UPnP backend {} generic discovery returned {} root devices after bind-ip discovery",
                        UPNP_RUPNP_BACKEND,
                        devices.len()
                    );
                    record_devices(
                        devices,
                        config.igd_ip.as_deref(),
                        &mut fallback_gateway_ips,
                        &mut gateways,
                        &mut seen_gateways,
                    );
                }
                Err(error) => {
                    debug!("UPnP generic SSDP discovery failed: {error}");
                }
            }
        }
    } else {
        record_devices(
            discover_root_devices(timeout).await?,
            config.igd_ip.as_deref(),
            &mut fallback_gateway_ips,
            &mut gateways,
            &mut seen_gateways,
        );
    }

    if let Some(bind_ip) = bind_ip {
        fallback_gateway_ips.extend(gateway_ips_for_bind_ip(bind_ip));
    }
    let preferred_gateway_ips = dedupe_ipv4_candidates(fallback_gateway_ips);
    for gateway_ip in &preferred_gateway_ips {
        if let Some(gateway) = discover_gateway_from_configured_ip(&gateway_ip.to_string()).await? {
            info!(
                "UPnP backend {} direct IGD probe succeeded for fallback gateway {}",
                UPNP_RUPNP_BACKEND, gateway_ip
            );
            push_gateway_candidate(&mut gateways, &mut seen_gateways, gateway);
        }
    }

    if let Some(bind_ip) = bind_ip {
        gateways.sort_by_key(|gateway| {
            Reverse(gateway_preference_score(
                gateway,
                bind_ip,
                &config.igd_ip,
                &preferred_gateway_ips,
            ))
        });
    }

    if !gateways.is_empty() {
        info!(
            "UPnP backend {} discovery produced {} gateway candidate(s): {}",
            UPNP_RUPNP_BACKEND,
            gateways.len(),
            gateways
                .iter()
                .filter_map(|gateway| gateway.device.url().host())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(gateways);
    }

    if config.igd_ip.is_some() {
        Err(anyhow!("no matching IGD found for configured nat.igd_ip"))
    } else if let Some(bind_ip) = bind_ip {
        Err(anyhow!(
            "no UPnP IGD service discovered for nat.bind_ip {bind_ip}; on point-to-point VPNs you may need to set nat.igd_ip explicitly"
        ))
    } else {
        Err(anyhow!("no UPnP IGD service discovered"))
    }
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

fn record_devices(
    devices: Vec<Device>,
    requested_igd_ip: Option<&str>,
    fallback_gateway_ips: &mut Vec<Ipv4Addr>,
    gateways: &mut Vec<GatewayHandle>,
    seen_gateways: &mut HashSet<String>,
) {
    for device in devices {
        if let Some(host) = device.url().host() {
            append_unique_ipv4_candidate(fallback_gateway_ips, host);
        }

        if let Some(requested_igd_ip) = requested_igd_ip {
            let matches = device
                .url()
                .host()
                .map(|host| host == requested_igd_ip)
                .unwrap_or(false);
            if !matches {
                continue;
            }
        }

        if let Some(gateway) = gateway_from_device(device) {
            push_gateway_candidate(gateways, seen_gateways, gateway);
        }
    }
}

async fn discover_root_devices(timeout: Duration) -> Result<Vec<Device>> {
    let devices = rupnp::discover(&SearchTarget::RootDevice, timeout, None).await?;
    let mut devices = Box::pin(devices);
    let mut discovered = Vec::new();
    while let Some(device) = devices.try_next().await? {
        discovered.push(device);
    }
    Ok(discovered)
}

fn gateway_from_device(device: Device) -> Option<GatewayHandle> {
    for urn in [
        WAN_IP_CONNECTION_2,
        WAN_IP_CONNECTION_1,
        WAN_PPP_CONNECTION_1,
    ] {
        let service = device.find_service(&urn).cloned();
        if let Some(service) = service {
            return Some(GatewayHandle { device, service });
        }
    }
    None
}

fn push_gateway_candidate(
    gateways: &mut Vec<GatewayHandle>,
    seen_gateways: &mut HashSet<String>,
    gateway: GatewayHandle,
) {
    let key = gateway.device.url().to_string();
    if seen_gateways.insert(key) {
        gateways.push(gateway);
    }
}

fn gateway_preference_score(
    gateway: &GatewayHandle,
    bind_ip: IpAddr,
    requested_igd_ip: &Option<String>,
    preferred_gateway_ips: &[Ipv4Addr],
) -> u8 {
    let Some(host) = gateway.device.url().host() else {
        return 0;
    };
    let Ok(IpAddr::V4(host_ip)) = host.parse::<IpAddr>() else {
        return 0;
    };
    if requested_igd_ip
        .as_deref()
        .is_some_and(|candidate| candidate == host)
    {
        return 100;
    }
    if preferred_gateway_ips.contains(&host_ip) {
        return 90;
    }
    match bind_ip {
        IpAddr::V4(bind_ip) if host_ip.octets()[0] == bind_ip.octets()[0] => 50,
        _ => 0,
    }
}

async fn discover_gateway_from_configured_ip(igd_ip: &str) -> Result<Option<GatewayHandle>> {
    let candidate_urls = [
        format!("http://{igd_ip}:1900/gateDesc.xml"),
        format!("http://{igd_ip}:1900/rootDesc.xml"),
        format!("http://{igd_ip}:5000/rootDesc.xml"),
        format!("http://{igd_ip}:49152/rootDesc.xml"),
    ];

    for candidate in candidate_urls {
        let uri = match candidate.parse() {
            Ok(uri) => uri,
            Err(_) => continue,
        };
        let device = match Device::from_url(uri).await {
            Ok(device) => device,
            Err(_) => continue,
        };
        for urn in [
            WAN_IP_CONNECTION_2,
            WAN_IP_CONNECTION_1,
            WAN_PPP_CONNECTION_1,
        ] {
            if let Some(service) = device.find_service(&urn).cloned() {
                return Ok(Some(GatewayHandle { device, service }));
            }
        }
    }

    Ok(None)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

#[allow(clippy::cognitive_complexity)]
async fn discover_root_devices_via_bind_ip(
    bind_ip: IpAddr,
    timeout: Duration,
) -> Result<Vec<Device>> {
    let bind_addr = SocketAddr::new(bind_ip, 0);
    let local_v4 = match bind_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => anyhow::bail!("IPv6 bind_ip is not supported for UPnP v1"),
    };
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create SSDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to set SSDP reuse-address")?;
    socket
        .set_multicast_ttl_v4(2)
        .context("failed to set SSDP multicast TTL")?;
    socket
        .set_multicast_if_v4(&local_v4)
        .context("failed to set SSDP multicast interface")?;
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("failed to bind SSDP socket to {bind_addr}"))?;
    let socket: std::net::UdpSocket = socket.into();
    debug!(
        "UPnP bind-ip discovery socket bound local_addr={} bind_ip={bind_ip} timeout_secs={}",
        socket
            .local_addr()
            .context("failed to read SSDP socket local_addr")?,
        timeout.as_secs_f32()
    );

    let multicast_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();
    let locations = task::spawn_blocking(move || {
        discover_location_headers_via_socket(socket, multicast_addr, timeout)
    })
    .await
    .context("UPnP bind-ip discovery task failed")??;

    let mut devices = Vec::new();
    for location in locations {
        let uri = location
            .parse()
            .with_context(|| format!("invalid SSDP location URI {location}"))?;
        match Device::from_url(uri).await {
            Ok(device) => {
                debug!(
                    "UPnP bind-ip discovery fetched device description {}",
                    device.url()
                );
                devices.push(device);
            }
            Err(error) => {
                debug!(
                    "UPnP bind-ip discovery failed to fetch device description at {location}: {error}"
                );
            }
        }
    }
    Ok(devices)
}

#[allow(clippy::cognitive_complexity)]
fn discover_location_headers_via_socket(
    socket: std::net::UdpSocket,
    multicast_addr: SocketAddr,
    timeout: Duration,
) -> Result<Vec<String>> {
    for target in ssdp_search_targets() {
        let search = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: {}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n\r\n",
            target
        );
        debug!(
            "UPnP bind-ip discovery sending M-SEARCH st={} bytes={} from {} to {}",
            target,
            search.len(),
            socket
                .local_addr()
                .context("failed to read SSDP socket local_addr before send")?,
            multicast_addr
        );
        socket
            .send_to(search.as_bytes(), multicast_addr)
            .with_context(|| format!("failed to send SSDP discovery packet for {target}"))?;
    }

    let started = std::time::Instant::now();
    let mut locations = HashSet::new();
    while started.elapsed() < timeout {
        let remaining = timeout.saturating_sub(started.elapsed());
        socket
            .set_read_timeout(Some(remaining))
            .context("failed to set SSDP read timeout")?;
        let mut buffer = [0u8; 4096];
        match socket.recv_from(&mut buffer) {
            Ok((read, from)) => collect_location_header(&mut locations, &buffer[..read], from)?,
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                debug!(
                    "UPnP bind-ip discovery timed out after {}s with no more packets",
                    timeout.as_secs_f32()
                );
                break;
            }
            Err(error) => return Err(error).context("failed to receive SSDP response"),
        }
    }

    Ok(locations.into_iter().collect())
}

#[allow(clippy::cognitive_complexity)]
fn collect_location_header(
    locations: &mut HashSet<String>,
    payload: &[u8],
    from: SocketAddr,
) -> Result<()> {
    debug!(
        "UPnP bind-ip discovery received {} bytes from {from}",
        payload.len()
    );
    let text = std::str::from_utf8(payload).context("invalid SSDP response payload")?;
    debug!("UPnP bind-ip discovery raw response from {from}: {text}");
    if let Some(location) = extract_location_header(text) {
        debug!("UPnP bind-ip discovery extracted location {location}");
        if !locations.insert(location.clone()) {
            debug!("UPnP bind-ip discovery ignored duplicate location {location}");
        }
    } else {
        debug!("UPnP bind-ip discovery response from {from} had no LOCATION header");
    }
    Ok(())
}

fn ssdp_search_targets() -> Vec<SearchTarget> {
    vec![
        SearchTarget::URN(INTERNET_GATEWAY_DEVICE_2),
        SearchTarget::URN(INTERNET_GATEWAY_DEVICE_1),
        SearchTarget::URN(WAN_IP_CONNECTION_2),
        SearchTarget::URN(WAN_IP_CONNECTION_1),
        SearchTarget::URN(WAN_PPP_CONNECTION_1),
        SearchTarget::RootDevice,
    ]
}

fn append_unique_ipv4_candidate(candidates: &mut Vec<Ipv4Addr>, value: &str) {
    let Ok(IpAddr::V4(ip)) = value.parse::<IpAddr>() else {
        return;
    };
    if ip != Ipv4Addr::UNSPECIFIED && !candidates.contains(&ip) {
        candidates.push(ip);
    }
}

fn dedupe_ipv4_candidates(candidates: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut unique = Vec::new();
    for candidate in candidates {
        if candidate != Ipv4Addr::UNSPECIFIED && !unique.contains(&candidate) {
            unique.push(candidate);
        }
    }
    unique
}

#[cfg(windows)]
fn gateway_ips_for_bind_ip(bind_ip: IpAddr) -> Vec<Ipv4Addr> {
    ipconfig::get_adapters()
        .ok()
        .into_iter()
        .flatten()
        .filter(|adapter| adapter.ip_addresses().contains(&bind_ip))
        .flat_map(|adapter| adapter.gateways().to_vec())
        .filter_map(|gateway| match gateway {
            IpAddr::V4(ip) if ip != Ipv4Addr::UNSPECIFIED => Some(ip),
            _ => None,
        })
        .collect()
}

#[cfg(not(windows))]
fn gateway_ips_for_bind_ip(_bind_ip: IpAddr) -> Vec<Ipv4Addr> {
    Vec::new()
}

fn extract_location_header(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("location")
            .then(|| value.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        append_unique_ipv4_candidate, dedupe_ipv4_candidates, extract_location_header,
        ssdp_search_targets, xml_escape,
    };
    use rupnp::ssdp::SearchTarget;

    #[test]
    fn xml_escape_covers_port_mapping_description_chars() {
        assert_eq!(
            xml_escape("udp & tcp <nat> 'map' \"desc\""),
            "udp &amp; tcp &lt;nat&gt; &apos;map&apos; &quot;desc&quot;"
        );
    }

    #[test]
    fn extract_location_header_is_case_insensitive() {
        let response =
            "HTTP/1.1 200 OK\r\nLOCATION: http://10.0.0.1/root.xml\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            extract_location_header(response).as_deref(),
            Some("http://10.0.0.1/root.xml")
        );
    }

    #[test]
    fn ssdp_search_targets_include_igd_and_root_queries() {
        let targets = ssdp_search_targets()
            .into_iter()
            .map(|target| target.to_string())
            .collect::<Vec<_>>();

        assert!(targets.contains(&SearchTarget::RootDevice.to_string()));
        assert!(
            targets.contains(&"urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string())
        );
        assert!(targets.contains(&"urn:schemas-upnp-org:service:WANIPConnection:1".to_string()));
    }

    #[test]
    fn ipv4_candidate_helpers_filter_and_dedupe() {
        let mut candidates = Vec::new();
        append_unique_ipv4_candidate(&mut candidates, "10.255.255.250");
        append_unique_ipv4_candidate(&mut candidates, "10.255.255.250");
        append_unique_ipv4_candidate(&mut candidates, "not-an-ip");
        append_unique_ipv4_candidate(&mut candidates, "::1");

        assert_eq!(
            dedupe_ipv4_candidates(candidates),
            vec!["10.255.255.250".parse::<Ipv4Addr>().unwrap()]
        );
    }
}
