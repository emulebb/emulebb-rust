//! Independent UPnP Internet Gateway Device backend.
//!
//! This provider deliberately does not share discovery or SOAP code with the
//! MiniUPnPc FFI backend. It is the second provider in the default order, so a
//! native-library failure can fall through to a separately implemented path.

use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use reqwest::{
    Client, Response, Url,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use roxmltree::{Document, Node};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, sync::RwLock, time::Instant};
use tracing::{debug, info, warn};

use super::{
    MappedEndpoint, MappingSpec, NatConfig, NatStatus, PortMappingProvider, SelectedGateway,
    UPNP_IGD_BACKEND,
};

const SSDP_MULTICAST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
const MAX_SOAP_BYTES: usize = 64 * 1024;
const SOAP_ACTION: HeaderName = HeaderName::from_static("soapaction");
const SEARCH_TARGETS: &[&str] = &[
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "upnp:rootdevice",
];

/// Pure-Rust SSDP and SOAP fallback for UPnP IGD v1/v2 routers.
#[derive(Debug, Default)]
pub struct IgdPortMappingProvider;

#[derive(Clone)]
struct Gateway {
    client: Client,
    control_url: Url,
    service_type: String,
    local_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
}

#[derive(Debug)]
struct IgdFault {
    code: u32,
    description: String,
}

impl fmt::Display for IgdFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "UPnP error {} ({})", self.code, self.description)
    }
}

impl Error for IgdFault {}

#[async_trait]
impl PortMappingProvider for IgdPortMappingProvider {
    fn name(&self) -> &'static str {
        UPNP_IGD_BACKEND
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
            "UPnP backend {} starting independent discovery: bind_ip={} igd_ip={} mappings={}",
            self.name(),
            option_display(config.bind_ip.as_deref(), "auto"),
            option_display(config.igd_ip.as_deref(), "auto"),
            mapping_specs_display(mappings)
        );

        let gateways = discover_gateways(config).await?;
        let mut last_error = None;
        for gateway in gateways {
            match reconcile_gateway(&gateway, config, mappings, Arc::clone(&status)).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    warn!(
                        "UPnP backend {} gateway {} failed: {error:#}",
                        self.name(),
                        gateway.control_url
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

        let gateways = discover_gateways(config)
            .await
            .context("independent IGD discovery failed during release")?;
        for gateway in gateways {
            for mapping in mappings {
                if let Err(error) = gateway
                    .delete_mapping(
                        mapping.external_addr.port(),
                        mapping.protocol.as_upnp_token(),
                    )
                    .await
                {
                    warn!(
                        "UPnP backend {} failed to release {} {}/{} via {}: {error:#}",
                        self.name(),
                        mapping.name,
                        mapping.protocol.as_upnp_token(),
                        mapping.external_addr.port(),
                        gateway.control_url
                    );
                }
            }
        }
        status.write().await.mappings.clear();
        Ok(())
    }
}

async fn reconcile_gateway(
    gateway: &Gateway,
    config: &NatConfig,
    mappings: &[MappingSpec],
    status: Arc<RwLock<NatStatus>>,
) -> Result<()> {
    let external_ip = match config.external_ip_override.as_deref() {
        Some(value) => parse_ipv4(value, "nat.externalIpOverride")?,
        None => gateway.external_ip().await.unwrap_or(gateway.local_ip),
    };

    let mut applied = Vec::new();
    let mut mapped = Vec::with_capacity(mappings.len());
    for spec in mappings {
        let external_port = spec
            .preferred_external_port
            .unwrap_or_else(|| spec.local_addr.port());
        let internal_ip = mapping_internal_ip(config, spec, gateway.local_ip)?;

        if let Err(add_error) = gateway.add_mapping(spec, external_port, internal_ip).await {
            let existing_matches = gateway
                .specific_mapping(external_port, spec.protocol.as_upnp_token())
                .await
                .with_context(|| {
                    format!(
                        "gateway {} failed to inspect existing {} mapping after {add_error}",
                        gateway.control_url, spec.name
                    )
                })?
                .is_some_and(|entry| {
                    entry.internal_ip == internal_ip
                        && entry.internal_port == spec.local_addr.port()
                });
            if !existing_matches {
                for (protocol, port) in applied.into_iter().rev() {
                    let _ = gateway.delete_mapping(port, protocol).await;
                }
                return Err(add_error).with_context(|| {
                    format!(
                        "gateway {} failed to add {} mapping",
                        gateway.control_url, spec.name
                    )
                });
            }
            info!(
                "UPnP backend {} reused existing {} {}/{} -> {}:{}",
                UPNP_IGD_BACKEND,
                spec.name,
                spec.protocol.as_upnp_token(),
                external_port,
                internal_ip,
                spec.local_addr.port()
            );
        } else {
            applied.push((spec.protocol.as_upnp_token(), external_port));
        }

        mapped.push(MappedEndpoint {
            name: spec.name.clone(),
            protocol: spec.protocol,
            local_addr: spec.local_addr,
            external_addr: SocketAddr::new(IpAddr::V4(external_ip), external_port),
            lease_expires_in_secs: config.lease_duration_secs,
            backend: UPNP_IGD_BACKEND.to_string(),
        });
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut guard = status.write().await;
    guard.enabled = true;
    guard.gateway_discovered = true;
    guard.backend = Some(UPNP_IGD_BACKEND.to_string());
    guard.bind_ip = config.bind_ip.clone();
    guard.igd_ip = config.igd_ip.clone();
    guard.minissdpd_socket = config.minissdpd_socket.clone();
    guard.ssdp_local_port = config.ssdp_local_port;
    guard.external_ip_override = config.external_ip_override.clone();
    guard.gateway = Some(SelectedGateway {
        backend: UPNP_IGD_BACKEND.to_string(),
        control_url: gateway.control_url.to_string(),
        local_ip: Some(gateway.local_ip.to_string()),
        gateway_ip: Some(gateway.gateway_ip.to_string()),
        external_ip: Some(external_ip.to_string()),
    });
    guard.observed_external_addresses = vec![external_ip.to_string()];
    guard.mappings = mapped;
    guard.last_refresh_unix_secs = Some(now);
    guard.last_error = None;
    Ok(())
}

impl Gateway {
    async fn external_ip(&self) -> Result<Ipv4Addr> {
        let body = self.soap("GetExternalIPAddress", &[]).await?;
        let value = xml_text(&body, "NewExternalIPAddress")
            .context("GetExternalIPAddress response omitted NewExternalIPAddress")?;
        parse_ipv4(&value, "IGD external address")
    }

    async fn add_mapping(
        &self,
        spec: &MappingSpec,
        external_port: u16,
        internal_ip: Ipv4Addr,
    ) -> Result<()> {
        let external_port = external_port.to_string();
        let internal_port = spec.local_addr.port().to_string();
        let internal_ip = internal_ip.to_string();
        // Zero is the IGD SOAP representation of an indefinite lease. It matches
        // the MFC/MiniUPnPc path and works with routers that reject finite leases.
        self.soap(
            "AddPortMapping",
            &[
                ("NewRemoteHost", ""),
                ("NewExternalPort", &external_port),
                ("NewProtocol", spec.protocol.as_upnp_token()),
                ("NewInternalPort", &internal_port),
                ("NewInternalClient", &internal_ip),
                ("NewEnabled", "1"),
                ("NewPortMappingDescription", &spec.name),
                ("NewLeaseDuration", "0"),
            ],
        )
        .await?;
        Ok(())
    }

    async fn delete_mapping(&self, external_port: u16, protocol: &str) -> Result<()> {
        let external_port = external_port.to_string();
        self.soap(
            "DeletePortMapping",
            &[
                ("NewRemoteHost", ""),
                ("NewExternalPort", &external_port),
                ("NewProtocol", protocol),
            ],
        )
        .await?;
        Ok(())
    }

    async fn specific_mapping(
        &self,
        external_port: u16,
        protocol: &str,
    ) -> Result<Option<ExistingMapping>> {
        let external_port = external_port.to_string();
        let body = match self
            .soap(
                "GetSpecificPortMappingEntry",
                &[
                    ("NewRemoteHost", ""),
                    ("NewExternalPort", &external_port),
                    ("NewProtocol", protocol),
                ],
            )
            .await
        {
            Ok(body) => body,
            Err(error)
                if error
                    .downcast_ref::<IgdFault>()
                    .is_some_and(|fault| fault.code == 714) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let internal_ip = xml_text(&body, "NewInternalClient")
            .context("mapping response omitted NewInternalClient")?;
        let internal_port = xml_text(&body, "NewInternalPort")
            .context("mapping response omitted NewInternalPort")?
            .parse::<u16>()
            .context("mapping response contained invalid NewInternalPort")?;
        Ok(Some(ExistingMapping {
            internal_ip: parse_ipv4(&internal_ip, "mapping internal address")?,
            internal_port,
        }))
    }

    async fn soap(&self, action: &str, arguments: &[(&str, &str)]) -> Result<String> {
        let body = soap_envelope(&self.service_type, action, arguments);
        let soap_action = HeaderValue::from_str(&format!("\"{}#{action}\"", self.service_type))
            .context("invalid SOAP action header")?;
        let response = self
            .client
            .post(self.control_url.clone())
            .header(CONTENT_TYPE, "text/xml; charset=\"utf-8\"")
            .header(SOAP_ACTION, soap_action)
            .body(body)
            .send()
            .await
            .with_context(|| format!("IGD SOAP {action} request failed"))?;
        let status = response.status();
        let body = bounded_response_text(response, MAX_SOAP_BYTES).await?;
        if let Some(fault) = parse_igd_fault(&body) {
            return Err(fault.into());
        }
        if !status.is_success() {
            bail!("IGD SOAP {action} returned HTTP {status}");
        }
        Ok(body)
    }
}

#[derive(Debug)]
struct ExistingMapping {
    internal_ip: Ipv4Addr,
    internal_port: u16,
}

async fn discover_gateways(config: &NatConfig) -> Result<Vec<Gateway>> {
    let bind_ip = config
        .bind_ip
        .as_deref()
        .map(|value| parse_ipv4(value, "nat.bindIp"))
        .transpose()?;
    let requested_igd_ip = config
        .igd_ip
        .as_deref()
        .map(|value| parse_ipv4(value, "nat.igdIp"))
        .transpose()?;
    let timeout = Duration::from_secs(config.discovery_timeout_secs.max(1));
    let client = http_client(bind_ip, timeout)?;

    let locations = if let Some(igd_ip) = requested_igd_ip {
        candidate_root_description_urls(igd_ip)
            .into_iter()
            .filter_map(|candidate| Url::parse(&candidate).ok())
            .collect()
    } else {
        discover_locations(bind_ip, config.ssdp_local_port, timeout).await?
    };

    let mut gateways = Vec::new();
    let mut seen = HashSet::new();
    let mut last_error = None;
    for location in locations {
        match gateway_from_description(&client, location, bind_ip).await {
            Ok(gateway) => {
                let key = gateway.control_url.to_string();
                if seen.insert(key) {
                    gateways.push(gateway);
                }
            }
            Err(error) => {
                debug!("ignored unusable IGD description: {error:#}");
                last_error = Some(error);
            }
        }
    }
    if !gateways.is_empty() {
        return Ok(gateways);
    }
    if let Some(error) = last_error {
        return Err(error).context("no usable UPnP IGD description found");
    }
    if requested_igd_ip.is_some() {
        bail!("no matching IGD found for configured nat.igd_ip");
    }
    if let Some(bind_ip) = bind_ip {
        bail!(
            "no UPnP IGD service discovered for nat.bind_ip {bind_ip}; on point-to-point VPNs you may need to set nat.igd_ip explicitly"
        );
    }
    bail!("no UPnP IGD service discovered")
}

fn http_client(bind_ip: Option<Ipv4Addr>, timeout: Duration) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        // WHY: SSDP is unauthenticated. Following a router-supplied redirect
        // could escape the discovered IPv4 host and defeat the interface/host
        // checks that keep this fallback on the selected local route.
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some(bind_ip) = bind_ip {
        builder = builder.local_address(IpAddr::V4(bind_ip));
    }
    builder.build().context("failed to build IGD HTTP client")
}

async fn gateway_from_description(
    client: &Client,
    location: Url,
    bind_ip: Option<Ipv4Addr>,
) -> Result<Gateway> {
    validate_http_url(&location, "SSDP LOCATION")?;
    let response = client
        .get(location.clone())
        .send()
        .await
        .with_context(|| format!("failed to fetch IGD description {location}"))?;
    if !response.status().is_success() {
        bail!(
            "IGD description {} returned HTTP {}",
            location,
            response.status()
        );
    }
    let xml = bounded_response_text(response, MAX_DESCRIPTION_BYTES).await?;
    let (control_url, service_type) = parse_device_description(&location, &xml)?;
    validate_http_url(&control_url, "IGD control URL")?;
    if control_url.host_str() != location.host_str() {
        bail!("IGD control URL host differs from its description host");
    }
    let gateway_ip = parse_ipv4(
        control_url
            .host_str()
            .context("IGD control URL omitted host")?,
        "IGD control URL host",
    )?;
    let local_ip = match bind_ip {
        Some(bind_ip) => bind_ip,
        None => route_local_ip(gateway_ip)?,
    };
    Ok(Gateway {
        client: client.clone(),
        control_url,
        service_type,
        local_ip,
        gateway_ip,
    })
}

async fn discover_locations(
    bind_ip: Option<Ipv4Addr>,
    local_port: Option<u16>,
    discovery_timeout: Duration,
) -> Result<Vec<Url>> {
    let interface_ip = bind_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create independent SSDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to configure SSDP reuse-address")?;
    socket
        .set_multicast_ttl_v4(2)
        .context("failed to configure SSDP multicast TTL")?;
    if let Some(bind_ip) = bind_ip {
        socket
            .set_multicast_if_v4(&bind_ip)
            .context("failed to pin SSDP multicast to nat.bindIp")?;
    }
    socket
        .bind(&SocketAddrV4::new(interface_ip, local_port.unwrap_or(0)).into())
        .context("failed to bind independent SSDP socket")?;
    socket
        .set_nonblocking(true)
        .context("failed to make SSDP socket nonblocking")?;
    let std_socket: StdUdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_socket).context("failed to adopt SSDP socket")?;

    for target in SEARCH_TARGETS {
        let request = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n"
        );
        socket
            .send_to(request.as_bytes(), SSDP_MULTICAST)
            .await
            .with_context(|| format!("failed to send SSDP search for {target}"))?;
    }

    let deadline = Instant::now() + discovery_timeout;
    let mut locations = Vec::new();
    let mut seen = HashSet::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let received = match tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(Ok(received)) => received,
            Ok(Err(error)) => return Err(error).context("failed to receive SSDP response"),
            Err(_) => break,
        };
        let text = match std::str::from_utf8(&buffer[..received.0]) {
            Ok(text) => text,
            Err(_) => continue,
        };
        let Some(location) = extract_location_header(text) else {
            continue;
        };
        let Ok(url) = Url::parse(location) else {
            continue;
        };
        if validate_http_url(&url, "SSDP LOCATION").is_err() {
            continue;
        }
        if seen.insert(url.to_string()) {
            locations.push(url);
        }
    }
    Ok(locations)
}

fn parse_device_description(location: &Url, xml: &str) -> Result<(Url, String)> {
    let document = Document::parse(xml).context("invalid IGD device XML")?;
    let base_url = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "URLBase")
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(Url::parse)
        .transpose()
        .context("invalid IGD URLBase")?
        .unwrap_or_else(|| location.clone());

    let mut candidates = document
        .descendants()
        // UPnP descriptions normally put every device element in a default
        // namespace. Match the local name so IGD v1/v2 namespace URNs both work.
        .filter(|node| node.is_element() && node.tag_name().name() == "service")
        .filter_map(|service| {
            let service_type = child_text(service, "serviceType")?;
            let control_url = child_text(service, "controlURL")?;
            let rank = service_rank(&service_type)?;
            Some((rank, service_type, control_url))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.0));
    let (_, service_type, control_path) = candidates
        .into_iter()
        .next()
        .context("device description has no WANIPConnection/WANPPPConnection service")?;
    let control_url = base_url
        .join(&control_path)
        .context("invalid IGD control URL")?;
    Ok((control_url, service_type))
}

fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn service_rank(service_type: &str) -> Option<u32> {
    let version = service_type.rsplit(':').next()?.parse::<u32>().ok()?;
    if service_type.starts_with("urn:schemas-upnp-org:service:WANIPConnection:") {
        Some(200 + version)
    } else if service_type.starts_with("urn:schemas-upnp-org:service:WANPPPConnection:") {
        Some(100 + version)
    } else {
        None
    }
}

async fn bounded_response_text(mut response: Response, limit: usize) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit as u64)
    {
        bail!("IGD HTTP response exceeded {limit} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read IGD response")?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("IGD HTTP response exceeded {limit} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("IGD HTTP response was not UTF-8")
}

fn soap_envelope(service_type: &str, action: &str, arguments: &[(&str, &str)]) -> String {
    let mut body = format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{}\">",
        xml_escape(service_type)
    );
    for (name, value) in arguments {
        body.push('<');
        body.push_str(name);
        body.push('>');
        body.push_str(&xml_escape(value));
        body.push_str("</");
        body.push_str(name);
        body.push('>');
    }
    body.push_str(&format!("</u:{action}></s:Body></s:Envelope>"));
    body
}

fn parse_igd_fault(xml: &str) -> Option<IgdFault> {
    let document = Document::parse(xml).ok()?;
    let code = document
        .descendants()
        .find(|node| node.tag_name().name() == "errorCode")?
        .text()?
        .trim()
        .parse::<u32>()
        .ok()?;
    let description = document
        .descendants()
        .find(|node| node.tag_name().name() == "errorDescription")
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown IGD fault")
        .to_string();
    Some(IgdFault { code, description })
}

fn xml_text(xml: &str, name: &str) -> Option<String> {
    let document = Document::parse(xml).ok()?;
    document
        .descendants()
        .find(|node| node.tag_name().name() == name)
        .and_then(|node| node.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn extract_location_header(response: &str) -> Option<&str> {
    response.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        let value = value.trim();
        (name.eq_ignore_ascii_case("location") && !value.is_empty()).then_some(value)
    })
}

fn validate_http_url(url: &Url, label: &str) -> Result<()> {
    if url.scheme() != "http" {
        bail!("{label} must use http");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{label} must not contain credentials");
    }
    let host = url.host_str().context(format!("{label} omitted host"))?;
    parse_ipv4(host, label)?;
    Ok(())
}

fn route_local_ip(gateway_ip: Ipv4Addr) -> Result<Ipv4Addr> {
    let socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to create route-probe socket")?;
    socket
        .connect(SocketAddrV4::new(gateway_ip, 1900))
        .context("failed to resolve local address for IGD route")?;
    match socket.local_addr()?.ip().to_string().parse::<Ipv4Addr>() {
        Ok(local_ip) if !local_ip.is_unspecified() => Ok(local_ip),
        _ => bail!("IGD route did not select a usable local IPv4 address"),
    }
}

fn mapping_internal_ip(
    config: &NatConfig,
    spec: &MappingSpec,
    gateway_local_ip: Ipv4Addr,
) -> Result<Ipv4Addr> {
    let mapping_ip = spec
        .local_addr
        .ip()
        .to_string()
        .parse::<Ipv4Addr>()
        .context("UPnP IGD supports only IPv4 mapping addresses")?;
    if !mapping_ip.is_unspecified() {
        return Ok(mapping_ip);
    }
    config
        .bind_ip
        .as_deref()
        .map(|value| parse_ipv4(value, "nat.bindIp"))
        .transpose()
        .map(|bind_ip| bind_ip.unwrap_or(gateway_local_ip))
}

fn parse_ipv4(value: &str, label: &str) -> Result<Ipv4Addr> {
    value
        .parse::<Ipv4Addr>()
        .with_context(|| format!("{label} must be an IPv4 address"))
}

fn candidate_root_description_urls(igd_ip: Ipv4Addr) -> [String; 4] {
    [
        format!("http://{igd_ip}:1900/gateDesc.xml"),
        format!("http://{igd_ip}:1900/rootDesc.xml"),
        format!("http://{igd_ip}:5000/rootDesc.xml"),
        format!("http://{igd_ip}:49152/rootDesc.xml"),
    ]
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn mapping_specs_display(mappings: &[MappingSpec]) -> String {
    mappings
        .iter()
        .map(|mapping| {
            format!(
                "{} {}/{} -> {}",
                mapping.name,
                mapping.protocol.as_upnp_token(),
                mapping
                    .preferred_external_port
                    .unwrap_or_else(|| mapping.local_addr.port()),
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
#[path = "igd/tests.rs"]
mod tests;
