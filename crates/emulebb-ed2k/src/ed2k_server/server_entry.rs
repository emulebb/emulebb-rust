use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use tokio::net::lookup_host;

use crate::config::{Ed2kConfig, Ed2kServerEntry};

use super::{SERVER_UDP_FLAG_TCPOBFUSCATION, SERVER_UDP_FLAG_UDPOBFUSCATION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConfiguredServerEntry {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
    pub(super) udp_flags: u32,
    pub(super) udp_key: u32,
    pub(super) udp_key_ip: u32,
    pub(super) obfuscation_port_tcp: u16,
    pub(super) obfuscation_port_udp: u16,
    pub(super) soft_files: u32,
    pub(super) hard_files: u32,
}

/// eMule offer-batch cap from a server's soft file limit: use the soft limit,
/// falling back to 200 when it is unknown (0) or exceeds 200.
pub(super) fn server_offer_file_limit(soft_files: u32) -> usize {
    if soft_files == 0 || soft_files > 200 {
        200
    } else {
        soft_files as usize
    }
}

impl ConfiguredServerEntry {
    /// eMule offer-batch cap for this server: the server's soft file limit,
    /// falling back to 200 when unknown (0) or above 200 (matches MFC's
    /// `CServerConnect`/`CSharedFileList` offer clamp).
    pub(super) fn offer_file_limit(&self) -> usize {
        server_offer_file_limit(self.soft_files)
    }

    pub(super) fn from_endpoint_text(endpoint_text: &str) -> Result<Self> {
        let endpoint = endpoint_text
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid ED2K server endpoint {endpoint_text}"))?;
        Ok(Self {
            host: endpoint.ip().to_string(),
            port: endpoint.port(),
            name: None,
            description: None,
            udp_flags: 0,
            udp_key: 0,
            udp_key_ip: 0,
            obfuscation_port_tcp: 0,
            obfuscation_port_udp: 0,
            soft_files: 0,
            hard_files: 0,
        })
    }

    fn from_metadata(entry: &Ed2kServerEntry) -> Result<Self> {
        if entry.host.trim().is_empty() || entry.port == 0 {
            anyhow::bail!("ED2K server entry requires a non-empty host and non-zero port");
        }
        Ok(Self {
            host: entry.host.clone(),
            port: entry.port,
            name: entry.name.clone(),
            description: entry.description.clone(),
            udp_flags: entry.udp_flags,
            udp_key: entry.udp_key,
            udp_key_ip: entry.udp_key_ip,
            obfuscation_port_tcp: entry.obfuscation_port_tcp,
            obfuscation_port_udp: entry.obfuscation_port_udp,
            soft_files: entry.soft_files,
            hard_files: entry.hard_files,
        })
    }

    pub(super) fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("-")
    }

    pub(super) fn base_endpoint_text(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub(super) fn supports_obfuscation_tcp(&self) -> bool {
        self.obfuscation_port_tcp != 0
            && (self.udp_flags & (SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_TCPOBFUSCATION))
                != 0
    }

    pub(super) fn has_obfuscation_metadata(&self) -> bool {
        self.obfuscation_port_tcp != 0
            || self.obfuscation_port_udp != 0
            || self.udp_key != 0
            || self.udp_key_ip != 0
            || self.udp_flags != 0
    }

    pub(super) fn supports_obfuscation_udp(&self) -> bool {
        self.udp_flags & SERVER_UDP_FLAG_UDPOBFUSCATION != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedServerEntry {
    pub(super) entry: ConfiguredServerEntry,
    pub(super) ip: Ipv4Addr,
}

impl ResolvedServerEntry {
    pub(super) fn base_endpoint(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.ip), self.entry.port)
    }

    pub(super) fn transport_endpoint(&self, use_obfuscation: bool) -> SocketAddr {
        let chosen_port = if use_obfuscation && self.entry.obfuscation_port_tcp != 0 {
            self.entry.obfuscation_port_tcp
        } else {
            self.entry.port
        };
        SocketAddr::new(IpAddr::V4(self.ip), chosen_port)
    }
}

pub(super) fn configured_server_entries(config: &Ed2kConfig) -> Result<Vec<ConfiguredServerEntry>> {
    if !config.server_entries.is_empty() {
        return config
            .server_entries
            .iter()
            .map(ConfiguredServerEntry::from_metadata)
            .collect();
    }

    config
        .server_endpoints
        .iter()
        .map(|endpoint_text| ConfiguredServerEntry::from_endpoint_text(endpoint_text))
        .collect()
}

pub(super) async fn resolve_server_entry(
    entry: &ConfiguredServerEntry,
) -> Result<ResolvedServerEntry> {
    let lookup = format!("{}:{}", entry.host, entry.port);
    let ip = if let Ok(parsed_ip) = entry.host.parse::<Ipv4Addr>() {
        parsed_ip
    } else {
        lookup_host(&lookup)
            .await
            .with_context(|| format!("failed to resolve {lookup}"))?
            .find_map(|endpoint| match endpoint {
                SocketAddr::V4(endpoint) => Some(*endpoint.ip()),
                SocketAddr::V6(_) => None,
            })
            .ok_or_else(|| anyhow::anyhow!("no IPv4 address resolved for {lookup}"))?
    };
    Ok(ResolvedServerEntry {
        entry: entry.clone(),
        ip,
    })
}

pub(super) async fn resolve_callback_server_entry(
    config: &Ed2kConfig,
    server_endpoint: SocketAddr,
) -> Result<ResolvedServerEntry> {
    let endpoint_v4 = match server_endpoint {
        SocketAddr::V4(endpoint) => endpoint,
        SocketAddr::V6(_) => {
            anyhow::bail!("ED2K callback server endpoint must be IPv4, got {server_endpoint}")
        }
    };

    for configured_server in configured_server_entries(config)? {
        let resolved_server = resolve_server_entry(&configured_server).await?;
        if resolved_server.base_endpoint() == SocketAddr::V4(endpoint_v4) {
            return Ok(resolved_server);
        }
    }

    Ok(ResolvedServerEntry {
        entry: ConfiguredServerEntry::from_endpoint_text(&server_endpoint.to_string())?,
        ip: *endpoint_v4.ip(),
    })
}
