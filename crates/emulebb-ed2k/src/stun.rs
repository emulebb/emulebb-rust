//! RFC 5389 STUN Binding probe for active UDP egress verification.
//!
//! Counterpart to the eMuleBB (`StunProbeSeams.h` / `PublicIpProbe.cpp`) and
//! libtorrent (`aux::stun_probe`) implementations; the three share one design:
//!
//! * race a fixed set of public STUN servers concurrently and accept the first
//!   valid reflexive address (resilience comes from the fan-out, not retransmits);
//! * each per-server probe binds and egress-pins the socket to the data-plane
//!   interface (`IP_UNICAST_IF` via [`pin_egress_to_interface`]) so the reflexive
//!   address reflects the real UDP egress (e.g. a VPN tunnel);
//! * each probe `connect()`s to its server so the kernel drops datagrams from any
//!   other source — an off-path host cannot inject a spoofed Binding response;
//! * single send, no retransmit;
//! * IPv4 gate only (matching emulebb-rust's IPv4-only policy).
//!
//! DNS resolution of the server hostnames is acceptable and done per probe.
//!
//! [`pin_egress_to_interface`]: emulebb_kad_dht::socket_opts::pin_egress_to_interface

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rand::RngCore;
use tokio::net::UdpSocket;

use crate::networking::resolve_bind_if_index;

const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_FAMILY_IPV4: u8 = 0x01;
const STUN_HEADER_LEN: usize = 20;

/// Default per-server probe timeout, matching the eMuleBB/libtorrent probes (5s).
pub const DEFAULT_STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// Public STUN servers raced by [`stun_probe`]. Kept in sync (same set, same
/// order) with `StunProbeSeams::GetStunIpv4ProbeServers` (eMuleBB) and the
/// libtorrent default list. Google is UDP-only on 19302; the rest answer on the
/// IANA STUN port 3478.
pub const DEFAULT_STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 3478),
];

/// Race [`DEFAULT_STUN_SERVERS`] from a socket bound to `bind_ip` and return the
/// first reflexive public IPv4 observed. Fails only if every server fails.
///
/// `bind_ip` should be the resolved data-plane bind address (the VPN tunnel IP)
/// so the probe is egress-pinned exactly like the eD2k/Kad sockets; pass an
/// unspecified address (`0.0.0.0`) for a default-route baseline probe.
pub async fn stun_probe(bind_ip: Ipv4Addr, timeout: Duration) -> Result<Ipv4Addr> {
    stun_probe_servers(DEFAULT_STUN_SERVERS, bind_ip, timeout)
        .await
        .map(|endpoint| *endpoint.ip())
}

/// Race an explicit server set, returning the first reflexive endpoint (ip:port).
/// See [`stun_probe`] (which discards the port). The port is the source port of
/// this socket's mapping toward the winning server; use it only for NAT-behavior
/// classification, never as an advertised port.
pub async fn stun_probe_servers(
    servers: &[(&'static str, u16)],
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<SocketAddrV4> {
    let mut set = tokio::task::JoinSet::new();
    for &(host, port) in servers {
        set.spawn(async move {
            // Bound the whole per-server probe (DNS + connect + send + recv) with
            // one deadline, consistent with the libtorrent/eMuleBB probes.
            match tokio::time::timeout(timeout, probe_one(host, port, bind_ip)).await {
                Ok(result) => result,
                Err(_) => Err(anyhow!("STUN probe to {host}:{port} timed out")),
            }
        });
    }

    let mut last_err: Option<anyhow::Error> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(endpoint)) => {
                set.abort_all();
                return Ok(endpoint);
            }
            Ok(Err(err)) => last_err = Some(err),
            Err(err) => last_err = Some(anyhow!("STUN probe task failed: {err}")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no STUN servers configured")))
}

/// NAT mapping behavior, classified by comparing the external port this socket is
/// mapped to across two different STUN servers (the RFC 5780 mapping-behavior
/// test). This is the eD2k-relevant signal for whether a fixed advertised UDP port
/// will match what peers observe as our reask source port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    /// Same external port toward both servers: endpoint-independent (cone) mapping
    /// — our advertised UDP port is what peers see; reask/HighID reachability is
    /// solid.
    EndpointIndependent,
    /// Different external port per destination: symmetric NAT — each peer sees a
    /// different source port, so a fixed advertised UDP port cannot match the reask
    /// `(ip, udp_port)` lookup; inbound reask is fragile (peers fall back to TCP).
    Symmetric,
    /// Could not classify (a probe failed / timed out); no conclusion.
    Inconclusive,
}

/// Classify the NAT mapping behavior by probing two distinct STUN servers from the
/// SAME local socket and comparing the reflexive port. Independent of the dormant
/// Kad firewall check; available immediately. Uses one unconnected socket (so both
/// servers observe the same mapping) bound + egress-pinned to `bind_ip` like the
/// data-plane sockets. NOTE: this classifies the gateway's behavior (a property of
/// the gateway, not the socket), so it generalizes to the eD2k/Kad socket; it does
/// NOT yield an advertisable port (see the parse note).
pub async fn stun_probe_mapping_behavior(
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> NatMappingBehavior {
    let mut hosts = DEFAULT_STUN_SERVERS.iter();
    let Some(&first) = hosts.next() else {
        return NatMappingBehavior::Inconclusive;
    };
    let Some(&second) = hosts.find(|(host, _)| *host != first.0) else {
        return NatMappingBehavior::Inconclusive;
    };

    let socket = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0)).await {
        Ok(socket) => socket,
        Err(_) => return NatMappingBehavior::Inconclusive,
    };
    if emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        resolve_bind_if_index(bind_ip),
    )
    .is_err()
    {
        return NatMappingBehavior::Inconclusive;
    }

    let port_first = probe_port_unconnected(&socket, first.0, first.1, timeout).await;
    let port_second = probe_port_unconnected(&socket, second.0, second.1, timeout).await;
    classify_mapping_ports(port_first, port_second)
}

/// Pure classification of two reflexive ports observed from one socket toward two
/// servers (factored out for unit testing).
fn classify_mapping_ports(port_first: Option<u16>, port_second: Option<u16>) -> NatMappingBehavior {
    match (port_first, port_second) {
        (Some(a), Some(b)) if a == b => NatMappingBehavior::EndpointIndependent,
        (Some(_), Some(_)) => NatMappingBehavior::Symmetric,
        _ => NatMappingBehavior::Inconclusive,
    }
}

/// Send one Binding request to `host:port` over an already-bound *unconnected*
/// socket and return the reflexive port, filtering replies by the server IP (we
/// cannot `connect()` since the socket is shared across two servers).
async fn probe_port_unconnected(
    socket: &UdpSocket,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Option<u16> {
    let server = tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })?;
    let mut txid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut txid);
    let request = build_request(&txid);
    tokio::time::timeout(timeout, async {
        socket.send_to(&request, SocketAddr::V4(server)).await.ok()?;
        let mut buf = [0u8; 1500];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await.ok()?;
            if from.ip() == IpAddr::V4(*server.ip()) {
                return parse_response(&buf[..len], &txid).ok().map(|e| e.port());
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// One server probe: resolve, bind + egress-pin, `connect()`, single send, parse.
/// The caller bounds the whole probe with a timeout (see `stun_probe_servers`).
async fn probe_one(host: &'static str, port: u16, bind_ip: Ipv4Addr) -> Result<SocketAddrV4> {
    let server = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("STUN DNS lookup failed for {host}:{port}"))?
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
        .with_context(|| format!("no IPv4 address for STUN server {host}:{port}"))?;

    let mut txid = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut txid);
    let request = build_request(&txid);

    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .with_context(|| format!("failed to bind STUN probe socket on {bind_ip}"))?;
    // Egress-pin to the tunnel interface (IP_UNICAST_IF) so the reflexive address
    // reflects the real UDP egress — solid VPN binding, identical to the eD2k/Kad
    // data-plane sockets. No-op for an unspecified/default-route bind.
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        resolve_bind_if_index(bind_ip),
    )
    .with_context(|| format!("failed to pin STUN probe egress for {bind_ip}"))?;

    // connect() so the kernel drops datagrams from any source other than the
    // server: defends a security gate from spoofed responses and lets us use
    // send()/recv() without inspecting the sender.
    socket
        .connect(SocketAddr::V4(server))
        .await
        .with_context(|| format!("failed to connect STUN probe socket to {server}"))?;
    // Single send, no retransmit: resilience is the multi-server race.
    socket
        .send(&request)
        .await
        .with_context(|| format!("failed to send STUN binding request to {server}"))?;

    let mut buf = [0u8; 1500];
    let len = socket
        .recv(&mut buf)
        .await
        .with_context(|| format!("failed to receive STUN response from {server}"))?;

    parse_response(&buf[..len], &txid)
        .with_context(|| format!("invalid STUN binding response from {server}"))
}

/// Build the 20-byte STUN Binding Request: type, zero length, magic cookie, and
/// the 96-bit transaction id (no attributes).
fn build_request(txid: &[u8; 12]) -> [u8; STUN_HEADER_LEN] {
    let mut req = [0u8; STUN_HEADER_LEN];
    req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // bytes 2..4 (message length) stay 0 — the request carries no attributes.
    req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req[8..20].copy_from_slice(txid);
    req
}

/// Parse a STUN Binding Success response and extract the reflexive IPv4 endpoint
/// (address + port) from its `XOR-MAPPED-ADDRESS` (preferred) or legacy
/// `MAPPED-ADDRESS` attribute. IPv6 mapped addresses are skipped (project is
/// IPv4-only). NOTE: the port is the *source* port of this socket's outbound
/// mapping toward the STUN server, NOT a listen port — it is meaningful only for
/// NAT-mapping-behavior classification ([`stun_probe_mapping_behavior`]), never as
/// an advertised eD2k port (use the UPnP mapping / Kad-observed port for that).
fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Result<SocketAddrV4> {
    if buf.len() < STUN_HEADER_LEN {
        bail!("response too short ({} bytes)", buf.len());
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != STUN_BINDING_SUCCESS {
        bail!("not a STUN binding success response");
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != STUN_MAGIC_COOKIE {
        bail!("bad STUN magic cookie");
    }
    if &buf[8..20] != txid {
        bail!("STUN transaction id mismatch");
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total = buf.len().min(STUN_HEADER_LEN + msg_len);
    let mut pos = STUN_HEADER_LEN;
    while pos + 4 <= total {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let alen = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let vpos = pos + 4;
        if vpos + alen > total {
            break;
        }

        if (attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_MAPPED_ADDRESS) && alen >= 8 {
            // value layout: reserved(1) family(1) port(2) address(4 for IPv4)
            let family = buf[vpos + 1];
            if family == STUN_FAMILY_IPV4 {
                let mut port = u16::from_be_bytes([buf[vpos + 2], buf[vpos + 3]]);
                let mut addr =
                    u32::from_be_bytes([buf[vpos + 4], buf[vpos + 5], buf[vpos + 6], buf[vpos + 7]]);
                if attr_type == ATTR_XOR_MAPPED_ADDRESS {
                    addr ^= STUN_MAGIC_COOKIE;
                    port ^= (STUN_MAGIC_COOKIE >> 16) as u16;
                }
                return Ok(SocketAddrV4::new(Ipv4Addr::from(addr), port));
            }
            // family 0x02 (IPv6): intentionally skipped, IPv4-only client.
        }
        // attributes are padded to a 4-byte boundary
        pos = vpos + ((alen + 3) & !3);
    }
    bail!("no IPv4 mapped-address attribute in response")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    #[test]
    fn build_request_has_correct_header() {
        let req = build_request(&TXID);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        // no attributes -> message length 0
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &TXID);
    }

    /// Build a Binding Success response carrying a single mapped-address
    /// attribute (xor-encoded when `xor` is set) for `ip:port`.
    fn success_response(ip: Ipv4Addr, port: u16, xor: bool, txid: &[u8; 12]) -> Vec<u8> {
        let attr_type = if xor {
            ATTR_XOR_MAPPED_ADDRESS
        } else {
            ATTR_MAPPED_ADDRESS
        };
        let (enc_port, enc_addr) = if xor {
            (
                port ^ (STUN_MAGIC_COOKIE >> 16) as u16,
                u32::from(ip) ^ STUN_MAGIC_COOKIE,
            )
        } else {
            (port, u32::from(ip))
        };

        let mut attr = Vec::new();
        attr.push(0x00); // reserved
        attr.push(STUN_FAMILY_IPV4); // family
        attr.extend_from_slice(&enc_port.to_be_bytes());
        attr.extend_from_slice(&enc_addr.to_be_bytes());

        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16 + 4).to_be_bytes()); // attr header + value
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend_from_slice(&attr_type.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&attr);
        msg
    }

    #[test]
    fn parses_xor_mapped_address() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let msg = success_response(ip, 51413, true, &TXID);
        assert_eq!(
            parse_response(&msg, &TXID).unwrap(),
            SocketAddrV4::new(ip, 51413)
        );
    }

    #[test]
    fn parses_legacy_mapped_address() {
        let ip = Ipv4Addr::new(198, 51, 100, 42);
        let msg = success_response(ip, 4662, false, &TXID);
        assert_eq!(
            parse_response(&msg, &TXID).unwrap(),
            SocketAddrV4::new(ip, 4662)
        );
    }

    #[test]
    fn classifies_mapping_behavior_from_ports() {
        // Same external port toward both servers -> endpoint-independent (cone).
        assert_eq!(
            classify_mapping_ports(Some(50000), Some(50000)),
            NatMappingBehavior::EndpointIndependent
        );
        // Different port per destination -> symmetric NAT.
        assert_eq!(
            classify_mapping_ports(Some(50000), Some(50001)),
            NatMappingBehavior::Symmetric
        );
        // A failed probe -> inconclusive.
        assert_eq!(
            classify_mapping_ports(Some(50000), None),
            NatMappingBehavior::Inconclusive
        );
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        let mut wrong = TXID;
        wrong[0] ^= 0xff;
        assert!(parse_response(&msg, &wrong).is_err());
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        msg[4] ^= 0xff;
        assert!(parse_response(&msg, &TXID).is_err());
    }

    #[test]
    fn rejects_non_success_type() {
        let mut msg = success_response(Ipv4Addr::new(203, 0, 113, 7), 1234, true, &TXID);
        msg[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        assert!(parse_response(&msg, &TXID).is_err());
    }

    #[test]
    fn rejects_short_response() {
        assert!(parse_response(&[0u8; 8], &TXID).is_err());
    }

    #[test]
    fn skips_ipv6_attribute_and_reports_missing() {
        // A success response whose only mapped-address attribute is IPv6 must be
        // reported as "no IPv4 address" rather than mis-parsed.
        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(24u16).to_be_bytes()); // attr header(4) + value(20)
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&TXID);
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&(20u16).to_be_bytes());
        msg.push(0x00); // reserved
        msg.push(0x02); // family = IPv6
        msg.extend_from_slice(&[0u8; 2]); // port
        msg.extend_from_slice(&[0u8; 16]); // 128-bit address
        assert!(parse_response(&msg, &TXID).is_err());
    }
}
