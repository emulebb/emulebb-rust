use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use emulebb_kad_proto::Ed2kHash;

use super::{
    OP_EDONKEYPROT, OP_GLOBSERVSTATREQ, ResolvedServerEntry, ServerUdpPacket,
    decode_server_udp_datagram, encode_server_udp_datagram, encode_udp_search_request,
    encode_udp_source_request, server_status::server_status_challenge,
};

pub(super) async fn bind_server_udp_socket(bind_ip: Ipv4Addr) -> Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .await
        .with_context(|| format!("failed to bind ED2K server UDP helper on {bind_ip}:0"))?;
    let bind_if_index = crate::networking::require_bind_if_index(bind_ip, "ED2K server UDP")?;
    // Egress-pin to the VPN tunnel interface (IP_UNICAST_IF) — solid VPN binding.
    emulebb_kad_dht::socket_opts::pin_egress_to_interface(
        socket2::SockRef::from(&socket),
        Some(bind_if_index),
    )
    .with_context(|| format!("failed to pin ED2K server UDP egress for {bind_ip}"))?;
    Ok(socket)
}

async fn send_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    let (endpoint, packet) = encode_server_udp_datagram(server, opcode, payload);
    socket.send_to(&packet, endpoint).await.with_context(|| {
        format!(
            "failed to send ED2K server UDP opcode=0x{opcode:02X} to {}",
            endpoint
        )
    })?;
    Ok(())
}

/// Send `OP_GLOBSERVSTATREQ` with a fresh 4-byte challenge and return it so the
/// caller can store it and validate the echoed challenge in the response, exactly
/// as eMule's `CServerList::Process` (`SetChallenge`) does.
pub(super) async fn send_server_udp_status_request(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<u32> {
    let challenge = server_status_challenge();
    send_server_udp_packet(socket, server, OP_GLOBSERVSTATREQ, &challenge.to_le_bytes()).await?;
    Ok(challenge)
}

pub(super) async fn send_udp_keyword_search(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    search_payload: &[u8],
) -> Result<()> {
    let (opcode, payload) = encode_udp_search_request(server, search_payload);
    send_server_udp_packet(socket, server, opcode, &payload).await
}

pub(super) async fn send_udp_source_search(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    file_hash: Ed2kHash,
    file_size: u64,
) -> Result<()> {
    let (opcode, payload) = encode_udp_source_request(server, file_hash, file_size);
    send_server_udp_packet(socket, server, opcode, &payload).await
}

pub(super) async fn read_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<Option<ServerUdpPacket>> {
    let mut buffer = vec![0u8; 65_535];
    let (len, from) = socket
        .recv_from(&mut buffer)
        .await
        .context("failed to receive ED2K server UDP datagram")?;
    let Some(packet) = decode_server_udp_datagram(server, &buffer[..len]) else {
        return Ok(None);
    };
    if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
        return Ok(None);
    }
    Ok(Some(ServerUdpPacket {
        opcode: packet[1],
        payload: packet[2..].to_vec(),
        from,
    }))
}
