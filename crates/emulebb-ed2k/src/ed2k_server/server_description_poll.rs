//! One-shot, paced UDP metadata refresh for non-connected servers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{debug, warn};

use crate::reachability::ExternalReachability;

use super::server_entry::ConfiguredServerEntry;
use super::{
    Ed2kServerListEvent, Ed2kServerListEventSender, Ed2kServerState, OP_GLOBSERVSTATRES,
    OP_SERVER_DESC_RES, ResolvedServerEntry, resolve_server_entry,
    server_description::decode_server_description_response,
    server_status::decode_server_status_response,
    udp_runtime::{
        bind_server_udp_socket, read_server_udp_packet_with_key,
        send_server_udp_crypt_status_request, send_server_udp_description_request,
        send_server_udp_status_request,
    },
};

const SERVER_METADATA_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_CRYPT_PING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const SERVER_METADATA_PACING: Duration = Duration::from_secs(1);
const SERVER_CONNECTION_WAIT_POLL: Duration = Duration::from_millis(100);

pub(super) async fn poll_server_descriptions(
    bind_ip: std::net::Ipv4Addr,
    configured_servers: Vec<ConfiguredServerEntry>,
    state: Arc<RwLock<Ed2kServerState>>,
    public_ip: ExternalReachability,
    crypt_enabled: bool,
    shutdown: Arc<AtomicBool>,
    events: Option<Ed2kServerListEventSender>,
) {
    let Some(events) = events else {
        return;
    };
    // Stock's server-stat walk is active only while an ED2K server session is
    // established. Waiting also gives OP_IDCHANGE a chance to establish the
    // public IPv4 needed to bind a newly learned UDP key.
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        if state.read().await.connected {
            break;
        }
        tokio::time::sleep(SERVER_CONNECTION_WAIT_POLL).await;
    }
    let socket = match bind_server_udp_socket(bind_ip).await {
        Ok(socket) => socket,
        Err(error) => {
            warn!("server description poll disabled: {error}");
            return;
        }
    };
    for configured in configured_servers {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let mut server = match resolve_server_entry(&configured).await {
            Ok(server) => server,
            Err(error) => {
                debug!(
                    "skipping server description poll for {}: {error}",
                    configured.base_endpoint_text()
                );
                continue;
            }
        };
        let connected_endpoint = {
            let guard = state.read().await;
            guard.connected.then_some(guard.endpoint).flatten()
        };
        if connected_endpoint == Some(server.base_endpoint()) {
            continue;
        }
        if let Err(error) = poll_one_server(
            &socket,
            &mut server,
            public_ip.get(),
            crypt_enabled,
            &events,
        )
        .await
        {
            debug!(
                "server description poll failed for {}: {error}",
                server.base_endpoint()
            );
        }
        tokio::time::sleep(SERVER_METADATA_PACING).await;
    }
}

async fn poll_one_server(
    socket: &UdpSocket,
    server: &mut ResolvedServerEntry,
    public_ip: Option<std::net::Ipv4Addr>,
    crypt_enabled: bool,
    events: &Ed2kServerListEventSender,
) -> anyhow::Result<()> {
    poll_one_server_with_timeouts(
        socket,
        server,
        public_ip,
        crypt_enabled,
        events,
        SERVER_CRYPT_PING_RESPONSE_TIMEOUT,
        SERVER_METADATA_RESPONSE_TIMEOUT,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "testable bounded server metadata transaction"
)]
async fn poll_one_server_with_timeouts(
    socket: &UdpSocket,
    server: &mut ResolvedServerEntry,
    public_ip: Option<std::net::Ipv4Addr>,
    crypt_enabled: bool,
    events: &Ed2kServerListEventSender,
    crypt_timeout: Duration,
    response_timeout: Duration,
) -> anyhow::Result<()> {
    let crypt_discovery = public_ip.is_some() && crypt_enabled;
    let (status_challenge, status_packet, status_started) = if crypt_discovery {
        let challenge = send_server_udp_crypt_status_request(socket, server).await?;
        let started = tokio::time::Instant::now();
        match receive_opcode(
            socket,
            server,
            OP_GLOBSERVSTATRES,
            Some(challenge),
            crypt_timeout,
        )
        .await
        {
            Ok(packet) => (challenge, packet, started),
            Err(error) => {
                debug!(
                    "server crypt-ping failed for {}; trying plaintext status: {error}",
                    server.base_endpoint()
                );
                let challenge = send_server_udp_status_request(socket, server).await?;
                let started = tokio::time::Instant::now();
                let packet =
                    receive_opcode(socket, server, OP_GLOBSERVSTATRES, None, response_timeout)
                        .await?;
                (challenge, packet, started)
            }
        }
    } else {
        let challenge = send_server_udp_status_request(socket, server).await?;
        let started = tokio::time::Instant::now();
        let packet =
            receive_opcode(socket, server, OP_GLOBSERVSTATRES, None, response_timeout).await?;
        (challenge, packet, started)
    };
    let Some(status) =
        decode_server_status_response(&status_packet.payload, status_challenge, server.entry.port)
    else {
        anyhow::bail!("status challenge mismatch");
    };
    let ping_ms = u32::try_from(status_started.elapsed().as_millis()).unwrap_or(u32::MAX);
    let udp_key_ip = (status.udp_key != 0)
        .then(|| public_ip.map(|ip| u32::from_le_bytes(ip.octets())))
        .flatten()
        .unwrap_or_default();
    server.entry.soft_files = status.soft_files;
    server.entry.hard_files = status.hard_files;
    server.entry.udp_flags = status.udp_flags;
    server.entry.udp_key = status.udp_key;
    server.entry.udp_key_ip = udp_key_ip;
    server.entry.obfuscation_port_tcp = status.obfuscation_port_tcp;
    server.entry.obfuscation_port_udp = status.obfuscation_port_udp;
    let _ = events.send(Ed2kServerListEvent::StatusUpdated {
        endpoint: server.entry.base_endpoint_text(),
        users: status.users,
        files: status.files,
        max_users: status.max_users,
        low_id_users: status.low_id_users,
        ping_ms,
        soft_files: status.soft_files,
        hard_files: status.hard_files,
        udp_flags: status.udp_flags,
        udp_key: status.udp_key,
        udp_key_ip,
        obfuscation_port_tcp: status.obfuscation_port_tcp,
        obfuscation_port_udp: status.obfuscation_port_udp,
    });

    let description_challenge = send_server_udp_description_request(socket, server).await?;
    let description_packet =
        receive_opcode(socket, server, OP_SERVER_DESC_RES, None, response_timeout).await?;
    let Some(metadata) =
        decode_server_description_response(&description_packet.payload, description_challenge)?
    else {
        anyhow::bail!("description challenge mismatch");
    };
    let _ = events.send(Ed2kServerListEvent::MetadataUpdated {
        endpoint: server.entry.base_endpoint_text(),
        name: metadata.name,
        description: metadata.description,
        dynamic_host: metadata.dynamic_host,
        version: metadata.version,
        auxiliary_ports: metadata.auxiliary_ports,
    });
    Ok(())
}

async fn receive_opcode(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    expected_opcode: u8,
    decryption_key: Option<u32>,
    timeout: Duration,
) -> anyhow::Result<super::ServerUdpPacket> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(packet) =
                read_server_udp_packet_with_key(socket, server, decryption_key).await?
                && packet.opcode == expected_opcode
                && packet.from.ip() == std::net::IpAddr::V4(server.ip)
            {
                return Ok(packet);
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("response timed out"))?
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::net::UdpSocket;

    use super::*;
    use crate::ed2k_server::{
        OP_EDONKEYPROT, OP_GLOBSERVSTATREQ, OP_SERVER_DESC_REQ,
        server_entry::ConfiguredServerEntry, server_events::ed2k_server_list_event_channel,
    };

    async fn bind_plain_and_crypt_ports() -> (u16, UdpSocket, UdpSocket) {
        for _ in 0..100 {
            let plain = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let plain_port = plain.local_addr().unwrap().port();
            if !(5..=65_527).contains(&plain_port) {
                continue;
            }
            let base_port = plain_port - 4;
            if let Ok(crypt) = UdpSocket::bind((Ipv4Addr::LOCALHOST, base_port + 12)).await {
                return (base_port, plain, crypt);
            }
        }
        panic!("could not allocate paired server UDP ports");
    }

    fn framed(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(payload.len() + 2);
        packet.push(OP_EDONKEYPROT);
        packet.push(opcode);
        packet.extend_from_slice(payload);
        packet
    }

    #[tokio::test]
    async fn crypt_ping_timeout_falls_back_and_persists_status_before_description() {
        let (base_port, plain, crypt) = bind_plain_and_crypt_ports().await;
        let configured =
            ConfiguredServerEntry::from_endpoint_text(&format!("127.0.0.1:{base_port}")).unwrap();
        let mut server = ResolvedServerEntry {
            entry: configured,
            ip: Ipv4Addr::LOCALHOST,
        };
        let responder = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let (crypt_len, _) = crypt.recv_from(&mut buffer).await.unwrap();
            assert!((4..=19).contains(&crypt_len));

            let (status_len, client) = plain.recv_from(&mut buffer).await.unwrap();
            assert_eq!(buffer[0], OP_EDONKEYPROT);
            assert_eq!(buffer[1], OP_GLOBSERVSTATREQ);
            assert_eq!(status_len, 6);
            let challenge = u32::from_le_bytes(buffer[2..6].try_into().unwrap());
            let mut status = challenge.to_le_bytes().to_vec();
            status.extend_from_slice(&1234u32.to_le_bytes());
            status.extend_from_slice(&5678u32.to_le_bytes());
            status.extend_from_slice(&6000u32.to_le_bytes());
            status.extend_from_slice(&200u32.to_le_bytes());
            status.extend_from_slice(&300u32.to_le_bytes());
            status.extend_from_slice(&0u32.to_le_bytes());
            status.extend_from_slice(&44u32.to_le_bytes());
            status.extend_from_slice(&0u16.to_le_bytes());
            status.extend_from_slice(&0u16.to_le_bytes());
            status.extend_from_slice(&0u32.to_le_bytes());
            plain
                .send_to(&framed(OP_GLOBSERVSTATRES, &status), client)
                .await
                .unwrap();

            let (description_len, client) = plain.recv_from(&mut buffer).await.unwrap();
            assert_eq!(buffer[0], OP_EDONKEYPROT);
            assert_eq!(buffer[1], OP_SERVER_DESC_REQ);
            assert_eq!(description_len, 6);
            let mut description = 6u16.to_le_bytes().to_vec();
            description.extend_from_slice(b"Server");
            description.extend_from_slice(&11u16.to_le_bytes());
            description.extend_from_slice(b"Description");
            plain
                .send_to(&framed(OP_SERVER_DESC_RES, &description), client)
                .await
                .unwrap();
        });
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (events, mut inbox) = ed2k_server_list_event_channel();

        poll_one_server_with_timeouts(
            &client,
            &mut server,
            Some(Ipv4Addr::new(198, 51, 100, 9)),
            true,
            &events,
            Duration::from_millis(25),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        responder.await.unwrap();

        let status = inbox.try_recv().unwrap();
        match status {
            Ed2kServerListEvent::StatusUpdated {
                endpoint,
                users,
                files,
                max_users,
                low_id_users,
                soft_files,
                hard_files,
                udp_key,
                udp_key_ip,
                ..
            } => {
                assert_eq!(
                    endpoint,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, base_port)).to_string()
                );
                assert_eq!(users, 1234);
                assert_eq!(files, 5678);
                assert_eq!(max_users, 6000);
                assert_eq!(low_id_users, 44);
                assert_eq!(soft_files, 200);
                assert_eq!(hard_files, 300);
                assert_eq!(udp_key, 0);
                assert_eq!(udp_key_ip, 0);
            }
            other => panic!("unexpected first metadata event: {other:?}"),
        }
        assert_eq!(
            inbox.try_recv().unwrap(),
            Ed2kServerListEvent::MetadataUpdated {
                endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, base_port)).to_string(),
                name: Some("Server".to_string()),
                description: Some("Description".to_string()),
                dynamic_host: None,
                version: None,
                auxiliary_ports: Vec::new(),
            }
        );
    }
}
