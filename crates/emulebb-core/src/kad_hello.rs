//! Kad HELLO tag builders and the firewalled-response (UDP/TCP self-check
//! responder) helpers.
//!
//! Pure tag/predicate helpers plus the async HELLO request/response builders and
//! the inbound FIREWALLED(2)_REQ responders (the connect-back probe + ACK).
//! Moved verbatim out of `lib.rs` during the maintainability restructuring; the
//! inbound Kad packet dispatch (`handle_kad_local_store_packet`) stays in
//! `lib.rs` and calls these. Imported `pub(crate)` from the crate root so the
//! dispatch and the test module reach them by their bare names.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use emulebb_ed2k::{
    ed2k_server::Ed2kServerState,
    ed2k_tcp::{
        Ed2kHelloIdentity, emule_connect_options, enrich_hello_identity, send_kad_firewall_tcp_ack,
    },
    kad_firewall::KadFirewallState,
};
use emulebb_kad_dht::DhtNode;
use emulebb_kad_proto::{
    Firewalled2Req, FirewalledRes, HelloReq, HelloRes, KAD_VERSION, KadPacket, NodeId, Tag,
    TagValue, tag_name,
};
use tokio::{
    net::{TcpListener, TcpSocket},
    sync::{Mutex, RwLock},
};

use crate::Ed2kNetworkConfig;

const KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS: u64 = 20;

/// Decide whether an inbound Kad HELLO (req/res) should request a
/// `HELLO_RES_ACK` to complete the three-way IP-verification handshake.
///
/// Mirrors the oracle `bAddedOrUpdated && !bValidReceiverKey` predicate in
/// `Process_KADEMLIA2_HELLO_REQ`: only request the ACK when the contact was
/// added or updated and the peer has not already proven a valid receiver key.
pub(crate) fn should_request_hello_res_ack(
    added_or_updated: bool,
    receiver_verify_key_valid: bool,
) -> bool {
    added_or_updated && !receiver_verify_key_valid
}

/// Mask a KADEMLIA2_REQ type byte to its low 5 bits and reject the malformed
/// type 0, mirroring `Process_KADEMLIA2_REQ` (`byType &= 0x1F`, throw on 0).
///
/// Returns the masked type (which doubles as the max contact count to return)
/// or `None` when the request must be dropped.
pub(crate) fn kad_req_masked_count(type_byte: u8) -> Option<u8> {
    match type_byte & 0x1F {
        0 => None,
        masked => Some(masked),
    }
}

/// Whether an inbound publish for `target` is close enough to our own ID to be
/// accepted, mirroring the oracle publish responders
/// (`Process_KADEMLIA2_PUBLISH_*_REQ`): drop the publish when
/// `XOR(own_id, target).Get32BitChunk(0) > SEARCHTOLERANCE` unless the publisher
/// is on a LAN IP (which is exempt from the tolerance gate).
pub(crate) fn kad_publish_within_tolerance(
    own_id: NodeId,
    target: NodeId,
    publisher_ip: IpAddr,
) -> bool {
    if let IpAddr::V4(ip) = publisher_ip
        && (ip.is_private() || ip.is_loopback() || ip.is_link_local())
    {
        return true;
    }
    own_id.distance(&target).chunk_u32(0) <= emulebb_kad_proto::constants::SEARCHTOLERANCE
}

pub(crate) fn build_kad_hello_response_tags(
    kad_udp_port: u16,
    can_advertise_source_udp_port: bool,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    // HELLO_RES is emitted by the same oracle `SendMyDetails`
    // (KademliaUDPListener.cpp:146-168) as HELLO_REQ, so the two tags carry the
    // identical gates: SOURCEUPORT only when advertising our intern Kad port
    // (`!GetUseExternKadPort()`), and KADMISCOPTIONS only on v8+ AND when we
    // request an ACK or are UDP/TCP firewalled. (KAD_VERSION is well past v8, so
    // the version gate is always satisfied here.) Previously this builder always
    // emitted both, unlike the request builder and the oracle.
    let mut tags = Vec::new();
    if can_advertise_source_udp_port {
        tags.push(Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::U16(kad_udp_port),
        ));
    }
    if request_ack || udp_firewalled || tcp_firewalled {
        let misc_options = u8::from(udp_firewalled)
            | (u8::from(tcp_firewalled) << 1)
            | (u8::from(request_ack) << 2);
        tags.push(Tag::new_short(
            tag_name::KADMISCOPTIONS,
            TagValue::U8(misc_options),
        ));
    }
    tags
}

pub(crate) fn build_kad_hello_request_tags(
    kad_udp_port: u16,
    can_advertise_source_udp_port: bool,
    udp_firewalled: bool,
    tcp_firewalled: bool,
    request_ack: bool,
) -> Vec<Tag> {
    // Mirror the oracle SendMyDetails (KademliaUDPListener.cpp:146-169): the two
    // tags are independent and additive, not mutually exclusive. SOURCEUPORT is
    // written whenever we advertise our intern Kad port (!GetUseExternKadPort),
    // and KADMISCOPTIONS is written (v8+) whenever we request an ACK or are
    // firewalled. A firewalled node on its intern port therefore emits BOTH.
    let mut tags = Vec::new();
    if can_advertise_source_udp_port {
        tags.push(Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::U16(kad_udp_port),
        ));
    }
    if request_ack || udp_firewalled || tcp_firewalled {
        let misc_options = u8::from(udp_firewalled)
            | (u8::from(tcp_firewalled) << 1)
            | (u8::from(request_ack) << 2);
        tags.push(Tag::new_short(
            tag_name::KADMISCOPTIONS,
            TagValue::U8(misc_options),
        ));
    }
    tags
}

pub(crate) async fn build_kad_hello_request(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<HelloReq> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address while building Kad HELLO request")?
        .port();
    let firewall = kad_firewall.lock().await;
    let tcp_firewalled = resolve_tcp_firewalled_with_firewall(
        ed2k_listener,
        server_state,
        firewall.tcp_firewalled(),
    )
    .await;

    Ok(HelloReq {
        node_id: dht.own_id(),
        tcp_port,
        version: KAD_VERSION,
        tags: build_kad_hello_request_tags(
            bind_addr.port(),
            // Stock advertises SOURCEUPORT (our intern Kad UDP port) whenever
            // `!GetUseExternKadPort()`, i.e. always for a node on its intern port
            // — NOT gated on the UDP firewall verdict. rust uses a single intern
            // Kad port, so this is unconditionally true; a fresh/firewalled node
            // still advertises its port exactly like stock.
            true,
            firewall.udp_verified && !firewall.udp_open,
            tcp_firewalled,
            request_ack,
        ),
    })
}

/// Resolve the TCP-firewalled verdict when the Kad firewall verdict has already
/// been read from a held [`KadFirewallState`] guard, avoiding a re-lock (the
/// tokio mutex is not reentrant). Same priority as [`current_tcp_firewalled`]:
/// server first, then the supplied Kad verdict, then the listener fallback.
pub(crate) async fn resolve_tcp_firewalled_with_firewall(
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_verdict: Option<bool>,
) -> bool {
    if let Some(tcp_firewalled) = server_state.read().await.tcp_firewalled() {
        return tcp_firewalled;
    }
    if let Some(tcp_firewalled) = kad_verdict {
        return tcp_firewalled;
    }
    ed2k_listener
        .local_addr()
        .map(|addr| addr.port() == 0)
        .unwrap_or(true)
}

pub(crate) async fn build_kad_hello_response(
    dht: &DhtNode,
    ed2k_listener: &TcpListener,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    request_ack: bool,
) -> Result<HelloRes> {
    let bind_addr = dht.bind_addr()?;
    let tcp_port = ed2k_listener
        .local_addr()
        .context("failed to read eD2K listener address while building Kad HELLO response")?
        .port();
    let firewall = kad_firewall.lock().await;
    let tcp_firewalled = resolve_tcp_firewalled_with_firewall(
        ed2k_listener,
        server_state,
        firewall.tcp_firewalled(),
    )
    .await;

    Ok(HelloRes {
        node_id: dht.own_id(),
        tcp_port,
        version: KAD_VERSION,
        tags: build_kad_hello_response_tags(
            bind_addr.port(),
            // Mirror the request builder: SOURCEUPORT is advertised whenever we are
            // on our intern Kad port (`!GetUseExternKadPort()`), unconditionally for
            // rust's single-port model — not gated on the UDP firewall verdict.
            true,
            firewall.udp_verified && !firewall.udp_open,
            tcp_firewalled,
            request_ack,
        ),
    })
}

pub(crate) fn firewalled_response_ip_for_sender(from: SocketAddr) -> Option<u32> {
    match from.ip() {
        IpAddr::V4(ip) => Some(u32::from_be_bytes(ip.octets())),
        IpAddr::V6(_) => None,
    }
}

async fn send_kad_firewalled_response(dht: &DhtNode, from: SocketAddr) -> Result<()> {
    let Some(ip) = firewalled_response_ip_for_sender(from) else {
        tracing::debug!("ignoring Kad FIREWALLED request from non-IPv4 peer {from}");
        return Ok(());
    };

    dht.send_packet(from, &KadPacket::FirewalledRes(FirewalledRes { ip }))
        .await
        .with_context(|| format!("failed to send Kad FIREWALLED_RES to {from}"))?;
    Ok(())
}

async fn probe_kad_firewalled_tcp(
    bind_ip: Ipv4Addr,
    peer_addr: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    let bind_if_index =
        emulebb_ed2k::networking::require_bind_if_index(bind_ip, "Kad TCP firewall probe")?;
    let socket = match peer_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => {
            anyhow::bail!("cannot probe IPv6 Kad TCP peer from IPv4 bind address {bind_ip}");
        }
    }
    .context("failed to create Kad TCP firewall probe socket")?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .with_context(|| format!("failed to bind Kad TCP firewall probe socket to {bind_ip}"))?;
    // WHY: this probe is a P2P TCP data-plane connection; binding the source IP
    // is not enough under split-tunnel routing, so pin the SYN to the same
    // interface used by the eD2K TCP paths before connect.
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        Some(bind_if_index),
    )
    .with_context(|| format!("failed to pin Kad TCP firewall probe egress for {bind_ip}"))?;
    tokio::time::timeout(timeout, socket.connect(peer_addr))
        .await
        .with_context(|| format!("timed out probing Kad TCP firewall peer {peer_addr}"))?
        .with_context(|| format!("failed to connect Kad TCP firewall probe to {peer_addr}"))?;
    Ok(())
}

pub(crate) fn spawn_kad_firewalled_response(
    dht: DhtNode,
    bind_ip: Ipv4Addr,
    from: SocketAddr,
    tcp_port: u16,
) {
    tokio::spawn(async move {
        if let Err(error) = send_kad_firewalled_response(&dht, from).await {
            tracing::debug!("Kad FIREWALLED_RES failed for {from}: {error:#}");
            return;
        }
        if tcp_port == 0 {
            return;
        }

        let peer_addr = SocketAddr::new(from.ip(), tcp_port);
        let timeout = Duration::from_secs(KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS);
        match probe_kad_firewalled_tcp(bind_ip, peer_addr, timeout).await {
            Ok(()) => {
                if let Err(error) = dht.send_packet(from, &KadPacket::FirewalledAckRes).await {
                    tracing::debug!("Kad FIREWALLED_ACK_RES failed for {from}: {error:#}");
                }
            }
            Err(error) => {
                tracing::debug!("Kad TCP firewall probe failed for {peer_addr}: {error:#}");
            }
        }
    });
}

async fn kad_firewall_ack_hello_identity(
    dht: &DhtNode,
    listener_addr: SocketAddr,
    server_state: &Arc<RwLock<Ed2kServerState>>,
    kad_firewall: &Arc<Mutex<KadFirewallState>>,
    network: &Ed2kNetworkConfig,
) -> Result<Ed2kHelloIdentity> {
    let identity = Ed2kHelloIdentity {
        user_hash: network.user_hash,
        client_id: 0,
        tcp_port: listener_addr.port(),
        udp_port: dht
            .bind_addr()
            .context("failed to resolve Kad bind address for firewall ACK hello")?
            .port(),
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(network.config.obfuscation_enabled),
        direct_udp_callback: false,
    };
    Ok(enrich_hello_identity(identity, server_state, kad_firewall).await)
}

pub(crate) fn spawn_modern_kad_firewalled_response(
    dht: DhtNode,
    listener_addr: SocketAddr,
    server_state: Arc<RwLock<Ed2kServerState>>,
    kad_firewall: Arc<Mutex<KadFirewallState>>,
    network: Ed2kNetworkConfig,
    from: SocketAddr,
    req: Firewalled2Req,
) {
    tokio::spawn(async move {
        if let Err(error) = send_kad_firewalled_response(&dht, from).await {
            tracing::debug!("Kad FIREWALLED_RES failed for modern request from {from}: {error:#}");
            return;
        }
        if req.tcp_port == 0 {
            return;
        }

        let peer_addr = SocketAddr::new(from.ip(), req.tcp_port);
        let timeout = Duration::from_secs(KAD_FIREWALLED_TCP_PROBE_TIMEOUT_SECS);
        let hello_identity = match kad_firewall_ack_hello_identity(
            &dht,
            listener_addr,
            &server_state,
            &kad_firewall,
            &network,
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => {
                tracing::debug!(
                    "failed to build Kad firewall ACK hello for {peer_addr}: {error:#}"
                );
                return;
            }
        };

        match send_kad_firewall_tcp_ack(
            network.bind_ip,
            peer_addr,
            hello_identity,
            req.user_hash.0,
            req.connect_options,
            timeout,
        )
        .await
        {
            Ok(mode) => tracing::debug!(
                transport = mode.as_str(),
                "sent Kad TCP firewall ACK to {peer_addr}"
            ),
            Err(error) => {
                tracing::debug!("Kad modern TCP firewall ACK failed for {peer_addr}: {error:#}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kad_hello_advertises_source_uport_even_when_firewalled() {
        // Stock advertises TAG_SOURCEUPORT whenever on the intern Kad port
        // (!GetUseExternKadPort), independent of the firewall verdict. A firewalled
        // node therefore still emits SOURCEUPORT (plus KADMISCOPTIONS).
        for build in [
            build_kad_hello_request_tags as fn(u16, bool, bool, bool, bool) -> Vec<Tag>,
            build_kad_hello_response_tags,
        ] {
            let tags = build(4672, true, true, true, false);
            use emulebb_kad_proto::TagName::Short;
            assert!(
                tags.iter()
                    .any(|tag| tag.name == Short(tag_name::SOURCEUPORT)),
                "firewalled hello must still advertise SOURCEUPORT"
            );
            assert!(
                tags.iter()
                    .any(|tag| tag.name == Short(tag_name::KADMISCOPTIONS)),
                "firewalled hello also carries KADMISCOPTIONS"
            );
        }
    }

    #[tokio::test]
    async fn kad_tcp_firewall_probe_requires_resolved_bind_interface_index() {
        let err = probe_kad_firewalled_tcp(
            Ipv4Addr::new(203, 0, 113, 234),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44)), 4662),
            Duration::from_millis(1),
        )
        .await
        .expect_err("unassigned bind IP must fail closed before probing");

        assert!(
            err.to_string()
                .contains("not assigned to a local interface")
        );
    }
}
