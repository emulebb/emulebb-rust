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

use super::server_entry::ConfiguredServerEntry;
use super::{
    Ed2kServerListEvent, Ed2kServerListEventSender, Ed2kServerState, OP_GLOBSERVSTATRES,
    OP_SERVER_DESC_RES, ResolvedServerEntry, resolve_server_entry,
    server_description::decode_server_description_response,
    server_status::decode_server_status_response,
    udp_runtime::{
        bind_server_udp_socket, read_server_udp_packet, send_server_udp_description_request,
        send_server_udp_status_request,
    },
};

const SERVER_METADATA_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_METADATA_PACING: Duration = Duration::from_secs(1);

pub(super) async fn poll_server_descriptions(
    bind_ip: std::net::Ipv4Addr,
    configured_servers: Vec<ConfiguredServerEntry>,
    state: Arc<RwLock<Ed2kServerState>>,
    shutdown: Arc<AtomicBool>,
    events: Option<Ed2kServerListEventSender>,
) {
    let Some(events) = events else {
        return;
    };
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
        let server = match resolve_server_entry(&configured).await {
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
        if let Err(error) = poll_one_server(&socket, &server, &events).await {
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
    server: &ResolvedServerEntry,
    events: &Ed2kServerListEventSender,
) -> anyhow::Result<()> {
    let status_challenge = send_server_udp_status_request(socket, server).await?;
    let status_packet = receive_opcode(socket, server, OP_GLOBSERVSTATRES).await?;
    if decode_server_status_response(&status_packet.payload, status_challenge).is_none() {
        anyhow::bail!("status challenge mismatch");
    }

    let description_challenge = send_server_udp_description_request(socket, server).await?;
    let description_packet = receive_opcode(socket, server, OP_SERVER_DESC_RES).await?;
    let Some(metadata) =
        decode_server_description_response(&description_packet.payload, description_challenge)?
    else {
        anyhow::bail!("description challenge mismatch");
    };
    let _ = events.send(Ed2kServerListEvent::MetadataUpdated {
        endpoint: server.entry.base_endpoint_text(),
        name: metadata.name,
        description: metadata.description,
    });
    Ok(())
}

async fn receive_opcode(
    socket: &UdpSocket,
    server: &ResolvedServerEntry,
    expected_opcode: u8,
) -> anyhow::Result<super::ServerUdpPacket> {
    tokio::time::timeout(SERVER_METADATA_RESPONSE_TIMEOUT, async {
        loop {
            if let Some(packet) = read_server_udp_packet(socket, server).await?
                && packet.opcode == expected_opcode
            {
                return Ok(packet);
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("response timed out"))?
}
