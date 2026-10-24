use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow};
use rand::RngExt;
use tokio::net::UdpSocket;

use emulebb_kad_proto::Ed2kHash;

#[cfg(feature = "packet-diagnostics")]
use super::diagnostics::{Ed2kServerPacketCapture, Ed2kServerSendAttempt};
use super::{
    Ed2kUdpSourceRequestTarget, OP_EDONKEYPROT, OP_GLOBSERVSTATREQ, OP_SERVER_DESC_REQ,
    ResolvedServerEntry, ServerUdpPacket, decode_server_udp_datagram,
    decode_server_udp_datagram_with_key, diagnostics::dump_ed2k_server_udp_packet,
    encode_server_list_request, encode_server_udp_crypt_ping, encode_server_udp_datagram,
    encode_udp_search_request, encode_udp_source_request_batch, legacy_udp::ServerListRequest,
    server_description::server_description_challenge, server_status::server_status_challenge,
    server_udp_crypt_ping_endpoint,
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

pub(super) async fn send_server_udp_packet(
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
    #[cfg(feature = "packet-diagnostics")]
    let send_attempt = {
        let mut clear_frame = Vec::with_capacity(payload.len() + 2);
        clear_frame.extend_from_slice(&[OP_EDONKEYPROT, opcode]);
        clear_frame.extend_from_slice(payload);
        Ed2kServerSendAttempt::udp(
            Some(server),
            endpoint,
            Ed2kServerPacketCapture {
                direction: "tx",
                transport_mode,
                obfuscated: Some(transport_mode == "obfuscated"),
                protocol_marker: Some(OP_EDONKEYPROT),
                opcode: Some(opcode),
                raw: &packet,
                clear_frame: Some(&clear_frame),
                payload: Some(payload),
                outcome: "attempted",
                note: None,
            },
        )
    };
    #[cfg(not(feature = "packet-diagnostics"))]
    dump_ed2k_server_udp_packet(server, "tx", endpoint, transport_mode, opcode, payload);
    let send_result = socket.send_to(&packet, endpoint).await.with_context(|| {
        format!(
            "failed to send ED2K server UDP opcode=0x{opcode:02X} to {}",
            endpoint
        )
    });
    match send_result {
        Ok(sent_len) if sent_len == packet.len() => {
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.succeeded();
            Ok(())
        }
        Ok(sent_len) => {
            let error = anyhow!(
                "short ED2K server UDP send to {endpoint}: wrote {sent_len} of {} bytes",
                packet.len()
            );
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.failed(error.to_string());
            Err(error)
        }
        Err(error) => {
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.failed(format!("{error:#}"));
            Err(error)
        }
    }
}

/// Request the server's peer list using the client-safe `OP_SERVER_LIST_REQ2`
/// empty body. `OP_SERVER_LIST_REQ` is reserved for servers announcing their
/// own endpoint and is covered by the codec without making this client pretend
/// to be a server.
pub(super) async fn send_server_udp_list_request(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<()> {
    let (opcode, payload) = encode_server_list_request(ServerListRequest::Client);
    send_server_udp_packet(socket, server, opcode, &payload).await
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

/// Send stock's raw crypt-ping discovery probe to `base_port + 12`. The random
/// non-zero challenge is both the echoed status challenge and the temporary
/// response decryption key; the request itself is intentionally not framed.
pub(super) async fn send_server_udp_crypt_status_request(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
) -> Result<u32> {
    let challenge = loop {
        let value = rand::rng().random::<u32>();
        if value != 0 {
            break value;
        }
    };
    let padding_len = usize::from(rand::rng().random::<u8>() & 0x0F);
    let padding = (0..padding_len)
        .map(|_| rand::rng().random::<u8>())
        .collect::<Vec<_>>();
    let packet = encode_server_udp_crypt_ping(challenge, &padding);
    let endpoint = server_udp_crypt_ping_endpoint(server);
    #[cfg(feature = "packet-diagnostics")]
    let send_attempt = Ed2kServerSendAttempt::udp(
        Some(server),
        endpoint,
        Ed2kServerPacketCapture {
            direction: "tx",
            transport_mode: "crypt-ping",
            obfuscated: Some(false),
            protocol_marker: None,
            opcode: None,
            raw: &packet,
            clear_frame: None,
            payload: None,
            outcome: "attempted",
            note: Some(format!(
                "server UDP crypt-ping challenge={challenge} padding_len={padding_len}"
            )),
        },
    );
    let send_result = socket
        .send_to(&packet, endpoint)
        .await
        .with_context(|| format!("failed to send ED2K server UDP crypt-ping to {endpoint}"));
    match send_result {
        Ok(sent_len) if sent_len == packet.len() => {
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.succeeded();
            Ok(challenge)
        }
        Ok(sent_len) => {
            let error = anyhow!(
                "short ED2K server UDP crypt-ping send to {endpoint}: wrote {sent_len} of {} bytes",
                packet.len()
            );
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.failed(error.to_string());
            Err(error)
        }
        Err(error) => {
            #[cfg(feature = "packet-diagnostics")]
            send_attempt.failed(format!("{error:#}"));
            Err(error)
        }
    }
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
    read_server_udp_packet_with_key(socket, server, None).await
}

pub(super) async fn read_server_udp_packet_with_key(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    decryption_key: Option<u32>,
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
    let Some(packet) = decode_server_udp_datagram_with_key(server, &buffer[..len], decryption_key)
    else {
        #[cfg(feature = "packet-diagnostics")]
        dump_ed2k_server_udp_packet(
            Some(server),
            from,
            Ed2kServerPacketCapture {
                direction: "rx",
                transport_mode,
                obfuscated: Some(transport_mode == "obfuscated"),
                protocol_marker: None,
                opcode: None,
                raw: &buffer[..len],
                clear_frame: None,
                payload: None,
                outcome: "dropped",
                note: Some(format!(
                    "server UDP datagram decode failed decryption_key={decryption_key:?}"
                )),
            },
        );
        return Ok(None);
    };
    if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
        #[cfg(feature = "packet-diagnostics")]
        dump_ed2k_server_udp_packet(
            Some(server),
            from,
            Ed2kServerPacketCapture {
                direction: "rx",
                transport_mode,
                obfuscated: Some(transport_mode == "obfuscated"),
                protocol_marker: packet.first().copied(),
                opcode: packet.get(1).copied(),
                raw: &buffer[..len],
                clear_frame: Some(&packet),
                payload: None,
                outcome: "dropped",
                note: Some(format!(
                    "server UDP decoded frame is invalid decryption_key={decryption_key:?}"
                )),
            },
        );
        return Ok(None);
    }
    let opcode = packet[1];
    let payload = packet[2..].to_vec();
    #[cfg(feature = "packet-diagnostics")]
    dump_ed2k_server_udp_packet(
        Some(server),
        from,
        Ed2kServerPacketCapture {
            direction: "rx",
            transport_mode,
            obfuscated: Some(transport_mode == "obfuscated"),
            protocol_marker: Some(OP_EDONKEYPROT),
            opcode: Some(opcode),
            raw: &buffer[..len],
            clear_frame: Some(&packet),
            payload: Some(&payload),
            outcome: "accepted",
            note: decryption_key.map(|key| format!("server UDP response decryption_key={key}")),
        },
    );
    #[cfg(not(feature = "packet-diagnostics"))]
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
    #[cfg(feature = "packet-diagnostics")]
    let mut candidate_count = 0usize;
    #[cfg(feature = "packet-diagnostics")]
    let mut rejected_clear_frame = None;
    for server in udp_response_candidate_servers(servers, from) {
        #[cfg(feature = "packet-diagnostics")]
        {
            candidate_count += 1;
        }
        let Some(packet) = decode_server_udp_datagram(server, &buffer[..len]) else {
            continue;
        };
        if packet.len() < 2 || packet[0] != OP_EDONKEYPROT {
            #[cfg(feature = "packet-diagnostics")]
            if rejected_clear_frame.is_none() {
                rejected_clear_frame = Some(packet);
            }
            continue;
        }
        let opcode = packet[1];
        let payload = packet[2..].to_vec();
        #[cfg(feature = "packet-diagnostics")]
        dump_ed2k_server_udp_packet(
            Some(server),
            from,
            Ed2kServerPacketCapture {
                direction: "rx",
                transport_mode,
                obfuscated: Some(transport_mode == "obfuscated"),
                protocol_marker: Some(OP_EDONKEYPROT),
                opcode: Some(opcode),
                raw: &buffer[..len],
                clear_frame: Some(&packet),
                payload: Some(&payload),
                outcome: "accepted",
                note: None,
            },
        );
        #[cfg(not(feature = "packet-diagnostics"))]
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
    #[cfg(feature = "packet-diagnostics")]
    dump_ed2k_server_udp_packet(
        None,
        from,
        Ed2kServerPacketCapture {
            direction: "rx",
            transport_mode,
            obfuscated: Some(transport_mode == "obfuscated"),
            protocol_marker: rejected_clear_frame
                .as_deref()
                .and_then(|packet| packet.first().copied()),
            opcode: rejected_clear_frame
                .as_deref()
                .and_then(|packet| packet.get(1).copied()),
            raw: &buffer[..len],
            clear_frame: rejected_clear_frame.as_deref(),
            payload: None,
            outcome: "dropped",
            note: Some(format!(
                "server UDP datagram rejected by {candidate_count} candidate decoder(s)"
            )),
        },
    );
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
    use std::time::Duration;

    use tokio::{net::UdpSocket, time::timeout};

    use super::super::{
        ConfiguredServerEntry, OP_EDONKEYPROT, OP_SERVER_DESC_REQ, ResolvedServerEntry,
    };
    use super::{send_server_udp_packet, udp_response_candidate_servers};

    fn resolved(ip: Ipv4Addr, port: u16) -> ResolvedServerEntry {
        ResolvedServerEntry {
            entry: ConfiguredServerEntry {
                host: ip.to_string(),
                port,
                name: None,
                description: None,
                dynamic_host: None,
                udp_flags: 0,
                udp_key: 0,
                udp_key_ip: 0,
                obfuscation_port_tcp: 0,
                obfuscation_port_udp: 0,
                soft_files: 0,
                hard_files: 0,
                priority: "normal".to_string(),
                static_server: false,
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

    #[tokio::test]
    async fn server_udp_send_reaches_the_resolved_udp_endpoint() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let receiver_port = receiver.local_addr().unwrap().port();
        let server = resolved(Ipv4Addr::LOCALHOST, receiver_port.checked_sub(4).unwrap());
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let payload = [0xAA, 0xBB];

        send_server_udp_packet(&sender, &server, OP_SERVER_DESC_REQ, &payload)
            .await
            .unwrap();

        let mut datagram = [0u8; 16];
        let (len, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &datagram[..len],
            &[OP_EDONKEYPROT, OP_SERVER_DESC_REQ, 0xAA, 0xBB]
        );
    }
}
