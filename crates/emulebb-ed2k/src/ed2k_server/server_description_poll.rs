//! One-shot, paced UDP metadata refresh for non-connected servers.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::UdpSocket,
    sync::{RwLock, watch},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::reachability::ExternalReachability;

use super::{
    Ed2kServerConnectPlan, Ed2kServerListEvent, Ed2kServerListEventSender, Ed2kServerState,
    OP_GLOBSERVSTATRES, OP_SERVER_DESC_RES, OP_SERVER_LIST_RES, ResolvedServerEntry,
    configured_server_entries, decode_server_list, ed2k_server_list_event_channel,
    resolve_server_entry,
    server_description::decode_server_description_response,
    server_status::decode_server_status_response,
    udp_runtime::{
        bind_server_udp_socket, read_server_udp_packet_with_key,
        send_server_udp_crypt_status_request, send_server_udp_description_request,
        send_server_udp_list_request, send_server_udp_status_request,
    },
};

const SERVER_METADATA_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_CRYPT_PING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const SERVER_METADATA_PACING: Duration = Duration::from_secs(1);
const SERVER_CONNECTION_WAIT_POLL: Duration = Duration::from_millis(100);

#[expect(
    clippy::too_many_arguments,
    reason = "long-lived poll task receives its owned runtime dependencies explicitly"
)]
pub(super) async fn poll_server_descriptions(
    bind_ip: std::net::Ipv4Addr,
    mut server_connect_plan: watch::Receiver<Ed2kServerConnectPlan>,
    state: Arc<RwLock<Ed2kServerState>>,
    public_ip: ExternalReachability,
    shutdown: Arc<AtomicBool>,
    server_enabled: Arc<AtomicBool>,
    events: Option<Ed2kServerListEventSender>,
    task_cancel: CancellationToken,
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
    let mut last_polled = None;
    'runtime: loop {
        if task_cancel.is_cancelled() || shutdown.load(Ordering::Relaxed) {
            return;
        }
        let plan = server_connect_plan.borrow_and_update().clone();
        let state_snapshot = state.read().await.clone();
        if !server_enabled.load(Ordering::SeqCst) || !state_snapshot.connected {
            if !wait_for_poll_trigger(&mut server_connect_plan, &task_cancel).await {
                return;
            }
            continue;
        }
        let poll_key = (plan.clone(), state_snapshot.session_generation);
        if last_polled.as_ref() == Some(&poll_key) {
            if !wait_for_poll_trigger(&mut server_connect_plan, &task_cancel).await {
                return;
            }
            continue;
        }
        last_polled = Some(poll_key);
        let configured_servers = match configured_server_entries(plan.config()) {
            Ok(servers) => servers,
            Err(error) => {
                warn!("server description poll skipped invalid live plan: {error}");
                continue;
            }
        };

        for configured in configured_servers {
            match observe_plan(&server_connect_plan) {
                PlanObservation::Current => {}
                PlanObservation::Changed => continue 'runtime,
                PlanObservation::Closed => return,
            }
            let mut server = tokio::select! {
                result = resolve_server_entry(&configured) => match result {
                    Ok(server) => server,
                    Err(error) => {
                        debug!(
                            "skipping server description poll for {}: {error}",
                            configured.base_endpoint_text()
                        );
                        continue;
                    }
                },
                changed = server_connect_plan.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue 'runtime;
                }
                () = wait_for_session_invalidation(
                    &state,
                    &server_enabled,
                    &shutdown,
                    state_snapshot.session_generation,
                ) => continue 'runtime,
                () = task_cancel.cancelled() => return,
            };
            if state_snapshot.endpoint == Some(server.base_endpoint()) {
                continue;
            }

            let (transaction_events, mut transaction_inbox) = ed2k_server_list_event_channel();
            let result = tokio::select! {
                result = poll_one_server(
                    &socket,
                    &mut server,
                    public_ip.get(),
                    plan.config().obfuscation_enabled,
                    plan.config().add_servers_from_server,
                    &transaction_events,
                ) => result,
                changed = server_connect_plan.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue 'runtime;
                }
                () = wait_for_session_invalidation(
                    &state,
                    &server_enabled,
                    &shutdown,
                    state_snapshot.session_generation,
                ) => continue 'runtime,
                () = task_cancel.cancelled() => return,
            };
            let current_state = state.read().await.clone();
            match observe_plan(&server_connect_plan) {
                PlanObservation::Current => {}
                PlanObservation::Changed => continue 'runtime,
                PlanObservation::Closed => return,
            }
            if !server_enabled.load(Ordering::SeqCst)
                || !current_state.connected
                || current_state.session_generation != state_snapshot.session_generation
            {
                continue 'runtime;
            }
            drop(transaction_events);
            while let Ok(event) = transaction_inbox.try_recv() {
                if events.send(event).is_err() {
                    return;
                }
            }
            if let Err(error) = result {
                debug!(
                    "server description poll failed for {}: {error}",
                    server.base_endpoint()
                );
            }
            tokio::select! {
                () = tokio::time::sleep(SERVER_METADATA_PACING) => {}
                changed = server_connect_plan.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    continue 'runtime;
                }
                () = wait_for_session_invalidation(
                    &state,
                    &server_enabled,
                    &shutdown,
                    state_snapshot.session_generation,
                ) => continue 'runtime,
                () = task_cancel.cancelled() => return,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlanObservation {
    Current,
    Changed,
    Closed,
}

fn observe_plan(server_connect_plan: &watch::Receiver<Ed2kServerConnectPlan>) -> PlanObservation {
    match server_connect_plan.has_changed() {
        Ok(false) => PlanObservation::Current,
        Ok(true) => PlanObservation::Changed,
        Err(_) => PlanObservation::Closed,
    }
}

async fn wait_for_session_invalidation(
    state: &Arc<RwLock<Ed2kServerState>>,
    server_enabled: &AtomicBool,
    shutdown: &AtomicBool,
    expected_generation: u64,
) {
    loop {
        let current_state = state.read().await;
        if shutdown.load(Ordering::Relaxed)
            || !server_enabled.load(Ordering::SeqCst)
            || !current_state.connected
            || current_state.session_generation != expected_generation
        {
            return;
        }
        drop(current_state);
        tokio::time::sleep(SERVER_CONNECTION_WAIT_POLL).await;
    }
}

async fn wait_for_poll_trigger(
    server_connect_plan: &mut watch::Receiver<Ed2kServerConnectPlan>,
    task_cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        changed = server_connect_plan.changed() => changed.is_ok(),
        () = task_cancel.cancelled() => false,
        () = tokio::time::sleep(SERVER_CONNECTION_WAIT_POLL) => true,
    }
}

async fn poll_one_server(
    socket: &UdpSocket,
    server: &mut ResolvedServerEntry,
    public_ip: Option<std::net::Ipv4Addr>,
    crypt_enabled: bool,
    add_servers_from_server: bool,
    events: &Ed2kServerListEventSender,
) -> anyhow::Result<()> {
    poll_one_server_with_timeouts(
        socket,
        server,
        public_ip,
        crypt_enabled,
        add_servers_from_server,
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
    add_servers_from_server: bool,
    events: &Ed2kServerListEventSender,
    crypt_timeout: Duration,
    response_timeout: Duration,
) -> anyhow::Result<()> {
    if !server.entry.udp_key_is_valid_for(public_ip) {
        server.entry.udp_key = 0;
    }
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

    if add_servers_from_server {
        let list_result = async {
            send_server_udp_list_request(socket, server).await?;
            receive_opcode(socket, server, OP_SERVER_LIST_RES, None, response_timeout).await
        }
        .await;
        match list_result {
            Ok(packet) => {
                let discovered = decode_server_list(&packet.payload);
                if !discovered.is_empty() {
                    let _ = events.send(Ed2kServerListEvent::DiscoveredServers(discovered));
                }
            }
            Err(error) => debug!(
                "UDP server-list request failed for {}: {error}",
                server.base_endpoint()
            ),
        }
    }

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
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{Arc, atomic::AtomicBool},
        time::Duration,
    };

    use tokio::{net::UdpSocket, sync::watch};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::{
        config::Ed2kRuntimeConfig,
        ed2k_server::{
            Ed2kServerConnectMode, Ed2kServerConnectPlan, OP_EDONKEYPROT, OP_GLOBSERVSTATREQ,
            OP_SERVER_DESC_REQ, server_entry::ConfiguredServerEntry,
            server_events::ed2k_server_list_event_channel,
        },
        reachability::ExternalReachability,
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

    fn automatic_plan(endpoint: Option<String>) -> Ed2kServerConnectPlan {
        let mut config = Ed2kRuntimeConfig::default();
        config.obfuscation_enabled = false;
        config.server_endpoints = endpoint.into_iter().collect();
        Ed2kServerConnectPlan::new(config, Ed2kServerConnectMode::Automatic)
    }

    #[tokio::test]
    async fn live_plan_replacement_discards_stale_events_and_polls_added_server() {
        let (removed_port, removed, _removed_crypt) = bind_plain_and_crypt_ports().await;
        let (added_port, added, _added_crypt) = bind_plain_and_crypt_ports().await;
        let (plan_sender, plan_receiver) =
            watch::channel(automatic_plan(Some(format!("127.0.0.1:{removed_port}"))));
        let state = Arc::new(RwLock::new(Ed2kServerState {
            endpoint: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 1))),
            connected: true,
            session_generation: 7,
            ..Ed2kServerState::default()
        }));
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_enabled = Arc::new(AtomicBool::new(true));
        let (events, mut inbox) = ed2k_server_list_event_channel();
        let task_cancel = CancellationToken::new();
        let poller = tokio::spawn(poll_server_descriptions(
            Ipv4Addr::LOCALHOST,
            plan_receiver,
            Arc::clone(&state),
            ExternalReachability::default(),
            Arc::clone(&shutdown),
            Arc::clone(&server_enabled),
            Some(events),
            task_cancel.clone(),
        ));

        let mut buffer = [0u8; 256];
        let (removed_len, _) =
            tokio::time::timeout(Duration::from_secs(1), removed.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(removed_len, 6);
        assert_eq!(buffer[..2], [OP_EDONKEYPROT, OP_GLOBSERVSTATREQ]);

        plan_sender.send_replace(automatic_plan(None));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), inbox.recv())
                .await
                .is_err()
        );

        let added_responder = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let (status_len, client) = added.recv_from(&mut buffer).await.unwrap();
            assert_eq!(status_len, 6);
            assert_eq!(buffer[..2], [OP_EDONKEYPROT, OP_GLOBSERVSTATREQ]);
            let challenge = u32::from_le_bytes(buffer[2..6].try_into().unwrap());
            let mut status = challenge.to_le_bytes().to_vec();
            status.extend_from_slice(&123u32.to_le_bytes());
            status.extend_from_slice(&456u32.to_le_bytes());
            status.extend_from_slice(&[0u8; 12]);
            added
                .send_to(&framed(OP_GLOBSERVSTATRES, &status), client)
                .await
                .unwrap();

            let (description_len, client) = added.recv_from(&mut buffer).await.unwrap();
            assert_eq!(description_len, 6);
            assert_eq!(buffer[..2], [OP_EDONKEYPROT, OP_SERVER_DESC_REQ]);
            let mut description = 6u16.to_le_bytes().to_vec();
            description.extend_from_slice(b"Server");
            description.extend_from_slice(&5u16.to_le_bytes());
            description.extend_from_slice(b"Added");
            added
                .send_to(&framed(OP_SERVER_DESC_RES, &description), client)
                .await
                .unwrap();
        });
        plan_sender.send_replace(automatic_plan(Some(format!("127.0.0.1:{added_port}"))));

        let added_endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, added_port)).to_string();
        let status = tokio::time::timeout(Duration::from_secs(1), inbox.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            status,
            Ed2kServerListEvent::StatusUpdated { endpoint, .. } if endpoint == added_endpoint
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), inbox.recv())
                .await
                .unwrap()
                .unwrap(),
            Ed2kServerListEvent::MetadataUpdated {
                endpoint: added_endpoint,
                name: Some("Server".to_string()),
                description: Some("Added".to_string()),
                dynamic_host: None,
                version: None,
                auxiliary_ports: Vec::new(),
            }
        );

        added_responder.await.unwrap();
        task_cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), poller)
            .await
            .unwrap()
            .unwrap();
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
            false,
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

    #[tokio::test]
    async fn udp_server_list_request_is_opt_in_and_emits_discovery() {
        let (base_port, plain, _crypt) = bind_plain_and_crypt_ports().await;
        let configured =
            ConfiguredServerEntry::from_endpoint_text(&format!("127.0.0.1:{base_port}")).unwrap();
        let mut server = ResolvedServerEntry {
            entry: configured,
            ip: Ipv4Addr::LOCALHOST,
        };
        let responder = tokio::spawn(async move {
            let mut buffer = [0u8; 256];
            let (status_len, client) = plain.recv_from(&mut buffer).await.unwrap();
            assert_eq!(status_len, 6);
            assert_eq!(buffer[..2], [OP_EDONKEYPROT, OP_GLOBSERVSTATREQ]);
            let challenge = u32::from_le_bytes(buffer[2..6].try_into().unwrap());
            let mut status = challenge.to_le_bytes().to_vec();
            status.extend_from_slice(&123u32.to_le_bytes());
            status.extend_from_slice(&456u32.to_le_bytes());
            status.extend_from_slice(&[0u8; 12]);
            plain
                .send_to(&framed(OP_GLOBSERVSTATRES, &status), client)
                .await
                .unwrap();

            let (list_len, client) = plain.recv_from(&mut buffer).await.unwrap();
            assert_eq!(list_len, 2);
            assert_eq!(
                buffer[..2],
                [OP_EDONKEYPROT, crate::ed2k_server::OP_SERVER_LIST_REQ2]
            );
            let list = [1, 198, 51, 100, 8, 0x35, 0x12];
            plain
                .send_to(&framed(OP_SERVER_LIST_RES, &list), client)
                .await
                .unwrap();

            let (description_len, client) = plain.recv_from(&mut buffer).await.unwrap();
            assert_eq!(description_len, 6);
            assert_eq!(buffer[..2], [OP_EDONKEYPROT, OP_SERVER_DESC_REQ]);
            let mut description = 6u16.to_le_bytes().to_vec();
            description.extend_from_slice(b"Server");
            description.extend_from_slice(&4u16.to_le_bytes());
            description.extend_from_slice(b"Desc");
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
            None,
            false,
            true,
            &events,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        responder.await.unwrap();

        assert!(matches!(
            inbox.try_recv().unwrap(),
            Ed2kServerListEvent::StatusUpdated { .. }
        ));
        assert_eq!(
            inbox.try_recv().unwrap(),
            Ed2kServerListEvent::DiscoveredServers(vec![(Ipv4Addr::new(198, 51, 100, 8), 4661)])
        );
        assert!(matches!(
            inbox.try_recv().unwrap(),
            Ed2kServerListEvent::MetadataUpdated { .. }
        ));
    }
}
