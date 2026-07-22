//! Bound public-IPv4 egress probes for the VPN Guard (eMuleBB `PublicIpProbe`).
//!
//! Verify the *observed* public exit of the P2P data plane two independent ways,
//! each from a socket bound **and** egress-pinned (`IP_UNICAST_IF`) to the active
//! tunnel interface — exactly the pin the eD2k/Kad data-plane sockets use — so we
//! check the real egress, not a routing assumption:
//!
//! * [`http_probe`] — the **TCP** leg: an HTTP/1.0 GET to a plain-text IP echo
//!   (parity with `PublicIpProbe::StartBoundPublicIpv4Probe`).
//! * [`stun_probe_bound`] — the **UDP** leg: a STUN Binding Request (parity with
//!   `PublicIpProbe::StartBoundStunIpv4Probe`), delegating to [`crate::stun`].
//!
//! The VPN Guard runs both and requires each to resolve an allowlisted public IP
//! (see `emulebb-core` `vpn_guard`); a probe that fails or returns an out-of-range
//! address fails the guard cycle closed. Provider/server lists mirror
//! `PublicIpProbeSeams.h` / `StunProbeSeams.h`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tracing::{info, warn};

use crate::networking::require_bind_if_index;

/// HTTP IPv4-echo providers (host, path), tried in order. Mirrors
/// `PublicIpProbeSeams::GetPublicIpv4ProbeProviders`. Plain HTTP (port 80),
/// bodies are the bare IPv4.
const HTTP_PROVIDERS: &[(&str, &str)] = &[
    ("api.ipify.org", "/"),
    ("ipv4.icanhazip.com", "/"),
    ("checkip.amazonaws.com", "/"),
    ("v4.ident.me", "/"),
    ("ipecho.net", "/plain"),
];

/// One bound egress-probe outcome. Field parity with eMuleBB
/// `PublicIpProbe::SBoundPublicIpv4ProbeResult` (the subset the guard verdict and
/// REST status need).
#[derive(Debug, Clone, Default)]
pub struct BoundProbeResult {
    /// Whether the probe was attempted (false only when it could not start).
    pub attempted: bool,
    /// Whether a public IPv4 was resolved.
    pub succeeded: bool,
    /// The resolved public IPv4, when `succeeded`.
    pub public_ip: Option<Ipv4Addr>,
    /// The provider URL / STUN server label that answered (or was last tried).
    pub provider: String,
    /// The failure detail when `!succeeded`.
    pub error: Option<String>,
}

impl BoundProbeResult {
    fn success(public_ip: Ipv4Addr, provider: String) -> Self {
        Self {
            attempted: true,
            succeeded: true,
            public_ip: Some(public_ip),
            provider,
            error: None,
        }
    }

    fn failure(provider: String, error: String) -> Self {
        Self {
            attempted: true,
            succeeded: false,
            public_ip: None,
            provider,
            error: Some(error),
        }
    }
}

/// TCP/HTTP egress leg: GET a bare-IPv4 echo from a socket bound + egress-pinned to
/// `bind_ip`'s tunnel interface. Tries each provider until one resolves an IPv4;
/// returns the last failure otherwise. Never `Err` (the outcome is the result).
pub async fn http_probe(bind_ip: Ipv4Addr, timeout: Duration) -> BoundProbeResult {
    let bind_if_index = match require_bind_if_index(bind_ip, "public IP HTTP probe") {
        Ok(index) => index,
        Err(err) => return BoundProbeResult::failure("http".to_string(), err.to_string()),
    };
    let mut attempts = Vec::new();
    for &(host, path) in HTTP_PROVIDERS {
        let provider = format!("http://{host}{path}");
        info!(provider = %provider, bind_ip = %bind_ip, bind_if_index, "VPN Guard HTTP public IPv4 probe attempt");
        match tokio::time::timeout(timeout, http_probe_one(bind_ip, bind_if_index, host, path))
            .await
        {
            Ok(Ok(ip)) => {
                info!(provider = %provider, bind_ip = %bind_ip, bind_if_index, public_ip = %ip, "VPN Guard HTTP public IPv4 probe succeeded");
                return BoundProbeResult::success(ip, provider);
            }
            Ok(Err(err)) => {
                let detail = err.to_string();
                warn!(provider = %provider, bind_ip = %bind_ip, bind_if_index, error = %detail, "VPN Guard HTTP public IPv4 probe failed");
                attempts.push(format!("{provider}: {detail}"));
            }
            Err(_) => {
                warn!(provider = %provider, bind_ip = %bind_ip, bind_if_index, "VPN Guard HTTP public IPv4 probe timed out");
                attempts.push(format!("{provider}: HTTP probe timed out"));
            }
        }
    }
    BoundProbeResult::failure(
        "http".to_string(),
        if attempts.is_empty() {
            "no HTTP providers".to_string()
        } else {
            attempts.join("; ")
        },
    )
}

/// One provider: resolve, bind + egress-pin the TCP socket, connect(:80), send a
/// minimal GET, read the response, parse the first IPv4 from the body.
async fn http_probe_one(
    bind_ip: Ipv4Addr,
    bind_if_index: u32,
    host: &str,
    path: &str,
) -> Result<Ipv4Addr> {
    let server = tokio::net::lookup_host((host, 80))
        .await
        .with_context(|| format!("HTTP probe DNS lookup failed for {host}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .with_context(|| format!("no IPv4 address for HTTP probe host {host}"))?;

    let socket = TcpSocket::new_v4().context("failed to create HTTP probe socket")?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .with_context(|| format!("failed to bind HTTP probe socket on {bind_ip}"))?;
    // Egress-pin to the tunnel interface before connect so the request leaves via
    // the tunnel — identical to the eD2k/Kad data-plane sockets.
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        Some(bind_if_index),
    )
    .with_context(|| format!("failed to pin HTTP probe egress for {bind_ip}"))?;

    let mut stream = socket
        .connect(SocketAddr::V4(server))
        .await
        .with_context(|| format!("failed to connect HTTP probe to {server}"))?;

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: eMuleBB/1\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("failed to send HTTP probe request to {host}"))?;

    let mut response = Vec::with_capacity(1024);
    stream
        .take(64 * 1024)
        .read_to_end(&mut response)
        .await
        .with_context(|| format!("failed to read HTTP probe response from {host}"))?;

    let text = String::from_utf8_lossy(&response);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&text);
    first_ipv4_in(body).with_context(|| format!("no IPv4 in HTTP probe response from {host}"))
}

/// UDP/STUN egress leg: delegate to the bound + egress-pinned STUN probe.
pub async fn stun_probe_bound(bind_ip: Ipv4Addr, timeout: Duration) -> BoundProbeResult {
    info!(bind_ip = %bind_ip, server_count = crate::stun::DEFAULT_STUN_SERVERS.len(), "VPN Guard STUN public IPv4 probe starting");
    match crate::stun::stun_probe_servers_detailed(
        crate::stun::DEFAULT_STUN_SERVERS,
        bind_ip,
        timeout,
    )
    .await
    {
        Ok(outcome) => {
            let ip = *outcome.endpoint.ip();
            info!(provider = %outcome.server, bind_ip = %bind_ip, public_ip = %ip, "VPN Guard STUN public IPv4 probe succeeded");
            BoundProbeResult::success(ip, outcome.server)
        }
        Err(err) => {
            let detail = err.to_string();
            warn!(bind_ip = %bind_ip, error = %detail, "VPN Guard STUN public IPv4 probe failed");
            BoundProbeResult::failure("stun".to_string(), detail)
        }
    }
}

/// First IPv4 dotted-quad appearing in `text` (echo bodies are the bare IP, maybe
/// with trailing whitespace; be tolerant of surrounding markup).
fn first_ipv4_in(text: &str) -> Option<Ipv4Addr> {
    let mut token = String::new();
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() || ch == '.' {
            token.push(ch);
        } else {
            if let Ok(ip) = token.parse::<Ipv4Addr>() {
                return Some(ip);
            }
            token.clear();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_ipv4_body() {
        assert_eq!(
            first_ipv4_in("203.0.113.7\n"),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
        assert_eq!(
            first_ipv4_in("  8.8.4.4  "),
            Some(Ipv4Addr::new(8, 8, 4, 4))
        );
    }

    #[test]
    fn parses_ipv4_amid_markup() {
        assert_eq!(
            first_ipv4_in("Current IP Address: 176.10.104.9</body>"),
            Some(Ipv4Addr::new(176, 10, 104, 9))
        );
    }

    #[test]
    fn rejects_non_ipv4_and_out_of_range_octets() {
        assert_eq!(first_ipv4_in("not-an-ip"), None);
        assert_eq!(first_ipv4_in(""), None);
        // 999 is not a valid octet; the token fails to parse.
        assert_eq!(first_ipv4_in("999.1.1.1"), None);
    }

    #[test]
    fn success_and_failure_result_shapes() {
        let ok = BoundProbeResult::success(Ipv4Addr::new(1, 2, 3, 4), "http://x/".to_string());
        assert!(ok.attempted && ok.succeeded && ok.error.is_none());
        assert_eq!(ok.public_ip, Some(Ipv4Addr::new(1, 2, 3, 4)));
        let bad = BoundProbeResult::failure("stun".to_string(), "boom".to_string());
        assert!(bad.attempted && !bad.succeeded && bad.public_ip.is_none());
        assert_eq!(bad.error.as_deref(), Some("boom"));
    }
}
