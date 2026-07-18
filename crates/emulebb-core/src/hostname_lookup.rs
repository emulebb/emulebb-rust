use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use emulebb_settings::HostnameLookupSettings;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::UdpSocket;

use crate::{EmulebbCore, HostNameResolution, ServerInfo};

static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Clone)]
struct HostNameEntry {
    host_name: Option<String>,
    status: String,
    resolved_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    error: Option<String>,
}

impl HostNameEntry {
    fn queued() -> Self {
        Self {
            host_name: None,
            status: "queued".to_string(),
            resolved_at: None,
            expires_at: None,
            error: None,
        }
    }

    fn blocked(error: String) -> Self {
        Self {
            host_name: None,
            status: "blockedByBindPolicy".to_string(),
            resolved_at: Some(Utc::now()),
            expires_at: None,
            error: Some(error),
        }
    }

    fn from_result(result: Result<Option<String>>, ttl_secs: u64) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_secs.max(1) as i64);
        match result {
            Ok(Some(host_name)) => Self {
                host_name: Some(host_name),
                status: "resolved".to_string(),
                resolved_at: Some(now),
                expires_at: Some(expires_at),
                error: None,
            },
            Ok(None) => Self {
                host_name: None,
                status: "notFound".to_string(),
                resolved_at: Some(now),
                expires_at: Some(expires_at),
                error: None,
            },
            Err(error) => Self {
                host_name: None,
                status: "failed".to_string(),
                resolved_at: Some(now),
                expires_at: Some(expires_at),
                error: Some(error.to_string()),
            },
        }
    }

    fn fresh(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at > Utc::now())
            || self.status == "blockedByBindPolicy"
    }

    fn to_resolution(&self) -> HostNameResolution {
        HostNameResolution {
            host_name: self.host_name.clone(),
            host_name_status: self.status.clone(),
            host_name_resolved_at: self.resolved_at,
            host_name_error: self.error.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct HostNameLookupCache {
    entries: parking_lot::Mutex<BTreeMap<Ipv4Addr, HostNameEntry>>,
}

impl HostNameLookupCache {
    pub(crate) fn snapshot(&self, ip: Ipv4Addr) -> HostNameResolution {
        self.entries
            .lock()
            .get(&ip)
            .map(HostNameEntry::to_resolution)
            .unwrap_or_else(|| HostNameResolution {
                host_name: None,
                host_name_status: "unknown".to_string(),
                host_name_resolved_at: None,
                host_name_error: None,
            })
    }

    fn queue_candidates(&self, ips: Vec<Ipv4Addr>, max_count: usize) -> Vec<Ipv4Addr> {
        let mut entries = self.entries.lock();
        let mut queued = Vec::new();
        for ip in ips {
            if queued.len() >= max_count {
                break;
            }
            if entries.get(&ip).is_some_and(HostNameEntry::fresh) {
                continue;
            }
            entries.insert(ip, HostNameEntry::queued());
            queued.push(ip);
        }
        queued
    }

    fn set_blocked(&self, ips: Vec<Ipv4Addr>, error: String) {
        let mut entries = self.entries.lock();
        for ip in ips {
            entries.insert(ip, HostNameEntry::blocked(error.clone()));
        }
    }

    fn set_result(&self, ip: Ipv4Addr, result: Result<Option<String>>, ttl_secs: u64) {
        self.entries
            .lock()
            .insert(ip, HostNameEntry::from_result(result, ttl_secs));
    }
}

pub(crate) async fn run_hostname_lookup_loop(core: EmulebbCore, shutdown: Arc<AtomicBool>) {
    let mut interval_secs = 30;
    let mut tick = hostname_lookup_interval(interval_secs);
    loop {
        tick.tick().await;
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(settings) = core
            .app_settings()
            .await
            .map(|settings| settings.daemon.hostname_lookup)
        else {
            continue;
        };
        if !settings.enabled {
            if interval_secs != 30 {
                interval_secs = 30;
                tick = hostname_lookup_interval(interval_secs);
                tick.tick().await;
            }
            continue;
        }
        let desired_interval_secs = settings.tick_interval_secs.max(5);
        if interval_secs != desired_interval_secs {
            interval_secs = desired_interval_secs;
            tick = hostname_lookup_interval(interval_secs);
            tick.tick().await;
        }
        run_hostname_lookup_tick(&core, &settings).await;
    }
}

fn hostname_lookup_interval(interval_secs: u64) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

async fn run_hostname_lookup_tick(core: &EmulebbCore, settings: &HostnameLookupSettings) {
    let ips = core.hostname_lookup_candidate_ips().await;
    let queued = core
        .hostname_lookup_cache
        .queue_candidates(ips, settings.max_lookups_per_tick.max(1));
    if queued.is_empty() {
        return;
    }
    let Some(network) = core.ed2k_network.as_ref() else {
        core.hostname_lookup_cache
            .set_blocked(queued, "P2P network binding is not configured".to_string());
        return;
    };
    let dns_servers = parse_dns_servers(&settings.dns_servers);
    if dns_servers.is_empty() {
        core.hostname_lookup_cache
            .set_blocked(queued, "hostnameLookup.dnsServers is empty".to_string());
        return;
    }
    let bind_ip = network.bind_ip;
    let bind_if_index =
        match emulebb_ed2k::networking::require_bind_if_index(bind_ip, "hostname reverse DNS") {
            Ok(index) => Some(index),
            Err(error) if network.p2p_bind_ip.is_some() || network.p2p_bind_interface.is_some() => {
                core.hostname_lookup_cache
                    .set_blocked(queued, error.to_string());
                return;
            }
            Err(_) => None,
        };
    for ip in queued {
        let result = reverse_lookup(ip, bind_ip, bind_if_index, &dns_servers).await;
        core.hostname_lookup_cache
            .set_result(ip, result, settings.cache_ttl_secs);
    }
}

impl EmulebbCore {
    pub(crate) fn host_name_resolution_for_ip(&self, ip: Ipv4Addr) -> HostNameResolution {
        self.hostname_lookup_cache.snapshot(ip)
    }

    pub(crate) fn apply_hostname_to_server(&self, server: &mut ServerInfo) {
        let ip = server
            .ip
            .parse::<Ipv4Addr>()
            .ok()
            .or_else(|| server.address.parse::<Ipv4Addr>().ok())
            .or_else(|| server.dyn_ip.parse::<Ipv4Addr>().ok());
        let Some(ip) = ip else {
            return;
        };
        let resolution = self.host_name_resolution_for_ip(ip);
        server.host_name = resolution.host_name;
        server.host_name_status = Some(resolution.host_name_status);
        server.host_name_resolved_at = resolution.host_name_resolved_at;
        server.host_name_error = resolution.host_name_error;
    }

    pub(crate) async fn hostname_lookup_candidate_ips(&self) -> Vec<Ipv4Addr> {
        let mut ips = candidate_ips_from_servers(&self.servers().await);
        if let Some(dht) = self.ed2k_dht_node().await {
            ips.extend(
                dht.routing_contacts_snapshot()
                    .await
                    .into_iter()
                    .map(|contact| contact.ip),
            );
        }
        ips.extend(
            self.uploads()
                .await
                .into_iter()
                .filter_map(|upload| upload.address.parse::<Ipv4Addr>().ok()),
        );
        ips.extend(
            self.upload_queue()
                .await
                .into_iter()
                .filter_map(|upload| upload.address.parse::<Ipv4Addr>().ok()),
        );
        ips.sort_unstable();
        ips.dedup();
        ips
    }
}

pub(crate) fn candidate_ips_from_servers(servers: &[ServerInfo]) -> Vec<Ipv4Addr> {
    let mut ips = Vec::new();
    for server in servers {
        push_ip(&mut ips, &server.address);
        push_ip(&mut ips, &server.ip);
        push_ip(&mut ips, &server.dyn_ip);
    }
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn push_ip(ips: &mut Vec<Ipv4Addr>, value: &str) {
    if let Ok(ip) = value.parse::<Ipv4Addr>() {
        ips.push(ip);
    }
}

fn parse_dns_servers(values: &[String]) -> Vec<SocketAddrV4> {
    values
        .iter()
        .filter_map(|value| {
            value.parse::<SocketAddrV4>().ok().or_else(|| {
                value
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|ip| SocketAddrV4::new(ip, 53))
            })
        })
        .collect()
}

async fn reverse_lookup(
    ip: Ipv4Addr,
    bind_ip: Ipv4Addr,
    bind_if_index: Option<u32>,
    dns_servers: &[SocketAddrV4],
) -> Result<Option<String>> {
    let query = build_ptr_query(ip);
    let socket = bound_dns_socket(bind_ip, bind_if_index)?;
    for server in dns_servers {
        socket
            .send_to(&query, SocketAddr::V4(*server))
            .await
            .with_context(|| format!("failed to send reverse DNS query to {server}"))?;
        let mut response = [0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut response)).await {
            Ok(Ok((len, _))) => {
                if let Some(name) = parse_ptr_response(&response[..len])? {
                    return Ok(Some(name));
                }
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => continue,
        }
    }
    Ok(None)
}

fn bound_dns_socket(bind_ip: Ipv4Addr, bind_if_index: Option<u32>) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create DNS UDP socket")?;
    socket
        .bind(&SocketAddr::new(IpAddr::V4(bind_ip), 0).into())
        .with_context(|| format!("failed to bind DNS UDP socket on {bind_ip}"))?;
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(SockRef::from(&socket), bind_if_index)
        .with_context(|| format!("failed to pin DNS egress for {bind_ip}"))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into()).context("failed to adopt DNS UDP socket")
}

fn build_ptr_query(ip: Ipv4Addr) -> Vec<u8> {
    let id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let octets = ip.octets();
    let qname = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&0x0100u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    encode_dns_name(&qname, &mut bytes);
    bytes.extend_from_slice(&12u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

fn encode_dns_name(name: &str, bytes: &mut Vec<u8>) {
    for label in name.split('.') {
        bytes.push(u8::try_from(label.len()).unwrap_or(0));
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
}

fn parse_ptr_response(bytes: &[u8]) -> Result<Option<String>> {
    if bytes.len() < 12 {
        return Err(anyhow!("short DNS response"));
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut offset = 12usize;
    for _ in 0..qdcount {
        skip_dns_name(bytes, &mut offset)?;
        offset = offset.saturating_add(4);
        if offset > bytes.len() {
            return Err(anyhow!("truncated DNS question"));
        }
    }
    for _ in 0..ancount {
        skip_dns_name(bytes, &mut offset)?;
        if offset + 10 > bytes.len() {
            return Err(anyhow!("truncated DNS answer"));
        }
        let rr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let rdlen = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > bytes.len() {
            return Err(anyhow!("truncated DNS rdata"));
        }
        if rr_type == 12 {
            let mut rdata_offset = offset;
            return read_dns_name(bytes, &mut rdata_offset).map(Some);
        }
        offset += rdlen;
    }
    Ok(None)
}

fn skip_dns_name(bytes: &[u8], offset: &mut usize) -> Result<()> {
    let _ = read_dns_name(bytes, offset)?;
    Ok(())
}

fn read_dns_name(bytes: &[u8], offset: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;
    loop {
        if cursor >= bytes.len() {
            return Err(anyhow!("truncated DNS name"));
        }
        let len = bytes[cursor];
        if len & 0xC0 == 0xC0 {
            if cursor + 1 >= bytes.len() {
                return Err(anyhow!("truncated DNS compression pointer"));
            }
            let pointer = (((len & 0x3F) as usize) << 8) | bytes[cursor + 1] as usize;
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow!("DNS compression pointer loop"));
            }
            continue;
        }
        cursor += 1;
        if len == 0 {
            if !jumped {
                *offset = cursor;
            }
            break;
        }
        let end = cursor + len as usize;
        if end > bytes.len() {
            return Err(anyhow!("truncated DNS label"));
        }
        labels.push(String::from_utf8_lossy(&bytes[cursor..end]).to_string());
        cursor = end;
    }
    Ok(labels.join(".").trim_end_matches('.').to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use super::{
        build_ptr_query, candidate_ips_from_servers, parse_dns_servers, parse_ptr_response,
    };
    use crate::ServerInfo;

    fn server(address: &str, ip: &str, dyn_ip: &str) -> ServerInfo {
        ServerInfo {
            endpoint: format!("{address}:4661"),
            name: "server".to_string(),
            address: address.to_string(),
            ip: ip.to_string(),
            dyn_ip: dyn_ip.to_string(),
            port: 4661,
            users: 0,
            files: 0,
            static_server: false,
            priority: "normal".to_string(),
            failed_count: 0,
            current: false,
            hard_files: 0,
            ping: 0,
            soft_files: 0,
            obfuscation_tcp_port: None,
            udp_flags: None,
            description: String::new(),
            version: String::new(),
            enabled: true,
            connected: false,
            connecting: false,
            host_name: None,
            host_name_status: None,
            host_name_resolved_at: None,
            host_name_error: None,
        }
    }

    #[test]
    fn dns_servers_accept_ipv4_with_default_or_explicit_port() {
        assert_eq!(
            parse_dns_servers(&[
                "9.9.9.9".to_string(),
                "1.1.1.1:5353".to_string(),
                "dns.example.invalid".to_string()
            ]),
            vec![
                SocketAddrV4::new(Ipv4Addr::new(9, 9, 9, 9), 53),
                SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 5353)
            ]
        );
    }

    #[test]
    fn server_candidates_are_ipv4_only_and_deduplicated() {
        let servers = [
            server("203.0.113.10", "198.51.100.20", ""),
            server("server.example.invalid", "198.51.100.20", "192.0.2.30"),
        ];

        assert_eq!(
            candidate_ips_from_servers(&servers),
            vec![
                Ipv4Addr::new(192, 0, 2, 30),
                Ipv4Addr::new(198, 51, 100, 20),
                Ipv4Addr::new(203, 0, 113, 10)
            ]
        );
    }

    #[test]
    fn ptr_response_parser_reads_compressed_answer_name() {
        let query = build_ptr_query(Ipv4Addr::new(203, 0, 113, 7));
        let mut response = query;
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0;
        response[7] = 1;
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        let mut rdata = Vec::new();
        for label in ["node", "example", "net"] {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);

        assert_eq!(
            parse_ptr_response(&response).unwrap().as_deref(),
            Some("node.example.net")
        );
    }
}
