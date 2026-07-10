use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use emulebb_kad_proto::Ed2kHash;

use super::{
    Ed2kUdpSourceRequestTarget, OP_EDONKEYPROT, OP_GLOBSERVSTATREQ, OP_SERVER_DESC_REQ,
    ResolvedServerEntry, ServerUdpPacket, decode_server_udp_datagram,
    diagnostics::dump_ed2k_server_udp_packet, encode_server_udp_datagram,
    encode_udp_search_request, encode_udp_source_request_batch,
    server_description::server_description_challenge, server_status::server_status_challenge,
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

pub(super) async fn send_server_udp_description_request(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<u32> {
    let challenge = server_description_challenge();
    send_server_udp_packet(socket, server, OP_SERVER_DESC_REQ, &challenge.to_le_bytes()).await?;
    Ok(challenge)
}

async fn send_server_udp_packet(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    let (endpoint, packet) = encode_server_udp_datagram(server, opcode, payload);
    let transport_mode = if packet.first().copied() == Some(OP_EDONKEYPROT) {
        "plaintext"
    } else {
        "obfuscated"
    };
    dump_ed2k_server_udp_packet(server, "tx", endpoint, transport_mode, opcode, payload);
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
    let encoded = encode_udp_source_request_batch(
        server,
        &[Ed2kUdpSourceRequestTarget {
            file_hash,
            file_size,
        }],
    )
    .context("ED2K UDP source search had no encodable target")?;
    send_server_udp_packet(socket, server, encoded.opcode, &encoded.payload).await
}

pub(super) async fn send_udp_source_search_batch(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    targets: &[Ed2kUdpSourceRequestTarget],
) -> Result<()> {
    let encoded = encode_udp_source_request_batch(server, targets)
        .context("ED2K UDP source search batch had no encodable targets")?;
    send_server_udp_packet(socket, server, encoded.opcode, &encoded.payload).await
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
    let transport_mode = if buffer[..len].first().copied() == Some(OP_EDONKEYPROT) {
        "plaintext"
    } else {
        "obfuscated"
    };
    let Some(packet) = decode_server_udp_datagram(server, &buffer[..len]) else {
        return Ok(None);
    };
    if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
        return Ok(None);
    }
    let opcode = packet[1];
    let payload = packet[2..].to_vec();
    dump_ed2k_server_udp_packet(server, "rx", from, transport_mode, opcode, &payload);
    Ok(Some(ServerUdpPacket {
        opcode,
        payload,
        from,
    }))
}

pub(super) async fn read_server_udp_packet_from_any(
    socket: &UdpSocket,
    servers: &[ResolvedServerEntry],
) -> Result<Option<(ResolvedServerEntry, ServerUdpPacket)>> {
    let mut buffer = vec![0u8; 65_535];
    let (len, from) = socket
        .recv_from(&mut buffer)
        .await
        .context("failed to receive ED2K server UDP datagram")?;
    let transport_mode = if buffer[..len].first().copied() == Some(OP_EDONKEYPROT) {
        "plaintext"
    } else {
        "obfuscated"
    };
    for server in udp_response_candidate_servers(servers, from) {
        let Some(packet) = decode_server_udp_datagram(server, &buffer[..len]) else {
            continue;
        };
        if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
            continue;
        }
        let opcode = packet[1];
        let payload = packet[2..].to_vec();
        dump_ed2k_server_udp_packet(server, "rx", from, transport_mode, opcode, &payload);
        return Ok(Some((
            server.clone(),
            ServerUdpPacket {
                opcode,
                payload,
                from,
            },
        )));
    }
    Ok(None)
}

fn udp_response_candidate_servers(
    servers: &[ResolvedServerEntry],
    from: SocketAddr,
) -> impl Iterator<Item = &ResolvedServerEntry> {
    servers
        .iter()
        .filter(move |server| from.ip() == IpAddr::V4(server.ip))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::{ConfiguredServerEntry, ResolvedServerEntry};
    use super::udp_response_candidate_servers;

    fn resolved(ip: Ipv4Addr, port: u16) -> ResolvedServerEntry {
        ResolvedServerEntry {
            entry: ConfiguredServerEntry {
                host: ip.to_string(),
                port,
                name: None,
                description: None,
                udp_flags: 0,
                udp_key: 0,
                udp_key_ip: 0,
                obfuscation_port_tcp: 0,
                obfuscation_port_udp: 0,
                soft_files: 0,
                hard_files: 0,
            },
            ip,
        }
    }

    #[test]
    fn udp_response_candidates_match_queried_server_ip() {
        let first = resolved(Ipv4Addr::new(192, 0, 2, 10), 4661);
        let second = resolved(Ipv4Addr::new(192, 0, 2, 20), 4661);
        let queried = vec![first, second];

        let matched =
            udp_response_candidate_servers(&queried, (Ipv4Addr::new(192, 0, 2, 20), 4236).into())
                .collect::<Vec<_>>();

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].ip, Ipv4Addr::new(192, 0, 2, 20));
        assert!(
            udp_response_candidate_servers(
                &queried,
                (Ipv4Addr::new(198, 51, 100, 20), 4236).into(),
            )
            .next()
            .is_none()
        );
    }
}
