use super::*;
use std::collections::{HashMap, HashSet};
use tokio::{net::TcpStream, sync::oneshot, time::Instant as TokioInstant};

use crate::ed2k_server::{
    Ed2kServerSearchInbox, OP_CALLBACKREQUEST,
    background::{BackgroundServerSearchContext, start_background_server_search},
};

struct BackgroundTestContext {
    session: ServerSessionContext,
    reachability_authority: ReachabilityRuntimeAuthority,
}

impl std::ops::Deref for BackgroundTestContext {
    type Target = ServerSessionContext;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

async fn connected_background_test_session() -> (ServerSession, TcpStream) {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = TcpStream::connect(addr).await.unwrap();
    let (stream, peer_addr) = listener.accept().await.unwrap();
    (ServerSession::from_stream_for_test(stream, peer_addr), peer)
}

async fn mark_background_session_connected(
    session: &mut ServerSession,
    endpoint: SocketAddr,
    generation: u64,
    our_client_id: u32,
) {
    session.login_accepted = true;
    session.assigned_client_id = Some(our_client_id);
    *session.state.write().await = Ed2kServerState {
        endpoint: Some(endpoint),
        client_id: session.assigned_client_id,
        connected: true,
        session_generation: generation,
        ..Ed2kServerState::default()
    };
}

async fn read_source_request_frame(peer: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 6];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], OP_EDONKEYPROT);
    let frame_len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; frame_len - 1];
    peer.read_exact(&mut payload).await.unwrap();
    (header[5], payload)
}

#[tokio::test]
async fn background_callback_writes_only_on_the_expected_server_generation() {
    let live_endpoint = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let generation = 7;
    let target_low_id = 0x0012_3456;
    let (mut session, mut peer) = connected_background_test_session().await;
    mark_background_session_connected(
        &mut session,
        live_endpoint,
        generation,
        u32::from_le_bytes([198, 51, 100, 2]),
    )
    .await;
    let server = background_test_server(live_endpoint);
    let shared_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::default()));
    let (response, receive_response) = oneshot::channel();

    let pending = start_background_server_search(
        &mut session,
        BackgroundServerSearchContext {
            server: &server,
            connect_options: 0,
            shared_catalog: &shared_catalog,
            bind_ip: crate::test_bind_ip(),
            tcp_port: 4662,
        },
        BackgroundServerSearchRequest::Callback {
            expected_server_endpoint: live_endpoint,
            expected_session_generation: generation,
            client_id: target_low_id,
            deadline: TokioInstant::now() + Duration::from_secs(1),
            cancel: CancellationToken::new(),
            response,
        },
    )
    .await
    .unwrap();

    assert!(pending.is_none());
    assert!(receive_response.await.unwrap().is_ok());
    let (opcode, payload) = read_source_request_frame(&mut peer).await;
    assert_eq!(opcode, OP_CALLBACKREQUEST);
    assert_eq!(payload, target_low_id.to_le_bytes());
}

#[tokio::test]
async fn background_callback_rejects_a_stale_or_ineligible_route_without_writing() {
    let live_endpoint = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 4661));
    let other_endpoint = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 11), 4661));
    let high_id = u32::from_le_bytes([198, 51, 100, 2]);
    for (label, expected_endpoint, expected_generation, our_client_id) in [
        ("generation", live_endpoint, 7, high_id),
        ("endpoint", other_endpoint, 8, high_id),
        ("our-lowid", live_endpoint, 8, 0x0000_1234),
    ] {
        let (mut session, peer) = connected_background_test_session().await;
        mark_background_session_connected(&mut session, live_endpoint, 8, our_client_id).await;
        let server = background_test_server(live_endpoint);
        let shared_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::default()));
        let (response, receive_response) = oneshot::channel();

        let pending = start_background_server_search(
            &mut session,
            BackgroundServerSearchContext {
                server: &server,
                connect_options: 0,
                shared_catalog: &shared_catalog,
                bind_ip: crate::test_bind_ip(),
                tcp_port: 4662,
            },
            BackgroundServerSearchRequest::Callback {
                expected_server_endpoint: expected_endpoint,
                expected_session_generation: expected_generation,
                client_id: 0x0012_3456,
                deadline: TokioInstant::now() + Duration::from_secs(1),
                cancel: CancellationToken::new(),
                response,
            },
        )
        .await
        .unwrap();

        assert!(pending.is_none(), "{label}");
        assert!(receive_response.await.unwrap().is_err(), "{label}");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), peer.readable())
                .await
                .is_err(),
            "{label} mismatch wrote a callback frame"
        );
    }
}

#[tokio::test]
async fn background_source_batch_sends_one_complete_frame_per_target() {
    let small = Ed2kServerSourceBatchTarget {
        file_hash: Ed2kHash([0x31; 16]),
        file_size: u64::from(u32::MAX),
    };
    let large = Ed2kServerSourceBatchTarget {
        file_hash: Ed2kHash([0x32; 16]),
        file_size: u64::from(u32::MAX) + 1,
    };

    for (connect_options, server_flags, expected_opcode, targets) in [
        (0, Some(0), OP_GETSOURCES, vec![small]),
        (0, Some(0), OP_GETSOURCES, vec![small, large]),
        (
            0x01,
            Some(SERVER_TCP_FLAG_TCPOBFUSCATION),
            OP_GETSOURCES_OBFU,
            vec![small, large],
        ),
    ] {
        let (mut session, mut peer) = connected_background_test_session().await;
        session.server_flags = server_flags;

        let (opcode, pending_hashes) =
            send_source_request_batch(&mut session, &targets, connect_options)
                .await
                .unwrap();

        assert_eq!(opcode, expected_opcode);
        assert_eq!(pending_hashes.len(), targets.len());
        for target in targets {
            let (wire_opcode, payload) = read_source_request_frame(&mut peer).await;
            assert_eq!(wire_opcode, expected_opcode);
            assert_eq!(
                payload,
                encode_source_request(target.file_hash, target.file_size)
            );
        }
    }
}

#[tokio::test]
async fn source_request_decoder_recovers_fragmented_coalesced_frames() {
    let first_payload = encode_source_request(Ed2kHash([0x41; 16]), 42);
    let second_payload = encode_source_request(Ed2kHash([0x42; 16]), u64::from(u32::MAX) + 1);
    let mut wire = encode_packet(OP_GETSOURCES_OBFU, &first_payload, false).unwrap();
    wire.extend_from_slice(&encode_packet(OP_GETSOURCES_OBFU, &second_payload, false).unwrap());
    let (mut session, mut peer) = connected_background_test_session().await;

    let writer = tokio::spawn(async move {
        for chunk in wire.chunks(3) {
            peer.write_all(chunk).await.unwrap();
            tokio::task::yield_now().await;
        }
    });

    let first = session.read_packet().await.unwrap().unwrap();
    let second = session.read_packet().await.unwrap().unwrap();
    assert_eq!(first.opcode, OP_GETSOURCES_OBFU);
    assert_eq!(first.payload, first_payload);
    assert_eq!(second.opcode, OP_GETSOURCES_OBFU);
    assert_eq!(second.payload, second_payload);
    writer.await.unwrap();
}

#[tokio::test]
async fn background_search_channel_round_trips_results() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let expected = Ed2kSearchFile {
        file_hash: Ed2kHash([0x44; 16]),
        client_id: 0,
        client_port: 0,
        file_name: Some("ubuntu.iso".to_string()),
        file_size: Some(123),
        file_type: Some("Doc".to_string()),
        media_artist: None,
        media_album: None,
        media_title: None,
        media_length_seconds: None,
        media_bitrate_kbps: None,
        media_codec: None,
        source_count: Some(7),
        complete_source_count: Some(3),
        rating: None,
        aich_hash: None,
        directory: None,
    };
    let expected_for_task = expected.clone();

    let responder = tokio::spawn(async move {
        let request = inbox.receiver.recv().await.unwrap();
        match request {
            BackgroundServerSearchRequest::Keyword {
                query, response, ..
            } => {
                assert_eq!(query, "ubuntu linux");
                let _ = response.send(Ok(vec![expected_for_task]));
            }
            other => panic!("unexpected background request: {other:?}"),
        }
    });

    let results = search_keyword_via_background_session(
        &handle,
        "ubuntu linux",
        Default::default(),
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(results, vec![expected]);
    responder.await.unwrap();
}

#[tokio::test]
async fn cancelled_background_keyword_search_is_not_dispatched() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    cancel.cancel();

    let results = search_keyword_via_background_session(
        &handle,
        "cancelled query",
        Default::default(),
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert!(results.is_empty());
    assert!(matches!(
        inbox.receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn background_source_search_channel_round_trips_results() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let file_hash = Ed2kHash([0x51; 16]);
    let expected = Ed2kFoundSource {
        file_hash,
        ip: Ipv4Addr::new(10, 20, 30, 40),
        tcp_port: 4662,
        client_id: u32::from_le_bytes([10, 20, 30, 40]),
        low_id: false,
        obfuscated: true,
        obfuscation_options: Some(0x03),
        user_hash: Some([0x61; 16]),
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    };
    let expected_for_task = expected.clone();

    let responder = tokio::spawn(async move {
        let request = inbox.receiver.recv().await.unwrap();
        match request {
            BackgroundServerSearchRequest::Source {
                file_hash: requested_hash,
                file_size,
                response,
                ..
            } => {
                assert_eq!(requested_hash, file_hash);
                assert_eq!(file_size, 42);
                let _ = response.send(Ok(vec![expected_for_task]));
            }
            other => panic!("unexpected background request: {other:?}"),
        }
    });

    let results = search_source_via_background_session(
        &handle,
        file_hash,
        42,
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(results, vec![expected]);
    responder.await.unwrap();
}

#[tokio::test]
async fn background_source_batch_search_channel_round_trips_results_by_hash() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let file_hash_a = Ed2kHash([0x54; 16]);
    let file_hash_b = Ed2kHash([0x55; 16]);
    let expected = Ed2kFoundSource {
        file_hash: file_hash_b,
        ip: Ipv4Addr::new(10, 20, 30, 41),
        tcp_port: 4662,
        client_id: u32::from_le_bytes([10, 20, 30, 41]),
        low_id: false,
        obfuscated: true,
        obfuscation_options: Some(0x03),
        user_hash: Some([0x62; 16]),
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    };
    let expected_for_task = expected.clone();

    let responder = tokio::spawn(async move {
        let request = inbox.receiver.recv().await.unwrap();
        match request {
            BackgroundServerSearchRequest::SourceBatch {
                targets, response, ..
            } => {
                assert_eq!(
                    targets,
                    vec![
                        Ed2kServerSourceBatchTarget {
                            file_hash: file_hash_a,
                            file_size: 42,
                        },
                        Ed2kServerSourceBatchTarget {
                            file_hash: file_hash_b,
                            file_size: 84,
                        },
                    ]
                );
                let _ = response.send(Ok(HashMap::from([(file_hash_b, vec![expected_for_task])])));
            }
            other => panic!("unexpected background request: {other:?}"),
        }
    });

    let results = search_source_batch_via_background_session(
        &handle,
        &[
            Ed2kServerSourceBatchTarget {
                file_hash: file_hash_a,
                file_size: 42,
            },
            Ed2kServerSourceBatchTarget {
                file_hash: file_hash_b,
                file_size: 84,
            },
        ],
        Duration::from_secs(1),
        &cancel,
    )
    .await
    .unwrap();

    assert_eq!(results.get(&file_hash_b), Some(&vec![expected]));
    responder.await.unwrap();
}

#[tokio::test]
async fn background_source_search_waits_while_queued_before_dispatch() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let file_hash = Ed2kHash([0x52; 16]);
    let queued_handle = handle.clone();
    let search = tokio::spawn(async move {
        let cancel = CancellationToken::new();
        search_source_via_background_session(
            &queued_handle,
            file_hash,
            42,
            Duration::from_millis(20),
            &cancel,
        )
        .await
    });

    tokio::time::sleep(Duration::from_millis(60)).await;
    let request = inbox.receiver.recv().await.unwrap();
    match request {
        BackgroundServerSearchRequest::Source {
            file_hash: requested_hash,
            timeout,
            response,
            ..
        } => {
            assert_eq!(requested_hash, file_hash);
            assert_eq!(timeout, Duration::from_millis(20));
            let _ = response.send(Ok(Vec::new()));
        }
        other => panic!("unexpected background request: {other:?}"),
    }

    assert_eq!(search.await.unwrap().unwrap(), Vec::new());
}

#[tokio::test]
async fn background_source_search_cancel_stops_queued_wait() {
    let (handle, _inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    cancel.cancel();

    let results = search_source_via_background_session(
        &handle,
        Ed2kHash([0x53; 16]),
        42,
        Duration::from_secs(60),
        &cancel,
    )
    .await
    .unwrap();

    assert!(results.is_empty());
}

#[tokio::test]
async fn background_udp_source_search_preserves_responding_server() {
    let mut server = test_udp_obfuscated_server();
    let file_hash = Ed2kHash([0x73; 16]);
    let source_ip = [10, 20, 30, 40];
    let (response, receive_response) = tokio::sync::oneshot::channel();
    let mut pending = Some(PendingBackgroundServerSearch::Source {
        file_hash,
        deadline: tokio::time::Instant::now() + Duration::from_secs(1),
        response,
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut payload = Vec::new();
    payload.extend_from_slice(&file_hash.0);
    payload.push(1);
    payload.extend_from_slice(&source_ip);
    payload.extend_from_slice(&4662u16.to_le_bytes());
    let response_port = server_udp_endpoint(&server).port();

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBFOUNDSOURCES,
            payload,
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .unwrap();

    let sources = receive_response.await.unwrap().unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(server.base_endpoint()));
}

#[test]
fn background_udp_keyword_search_keeps_pending_after_malformed_reply() {
    let mut server = test_udp_obfuscated_server();
    let (response, _receive_response) = tokio::sync::oneshot::channel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut pending = Some(PendingBackgroundServerSearch::Keyword {
        query: "linux".to_string(),
        deadline,
        results: Vec::new(),
        page_count: 0,
        cancel: CancellationToken::new(),
        response,
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let response_port = server_udp_endpoint(&server).port();

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBSEARCHRES,
            payload: vec![1, 0, 0],
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .unwrap();

    match pending {
        Some(PendingBackgroundServerSearch::Keyword {
            query,
            deadline: actual_deadline,
            page_count,
            ..
        }) => {
            assert_eq!(query, "linux");
            assert_eq!(actual_deadline, deadline);
            assert_eq!(page_count, 0);
        }
        other => panic!("malformed UDP search reply consumed pending search: {other:?}"),
    }
}

#[test]
fn background_udp_source_search_keeps_pending_after_malformed_reply() {
    let mut server = test_udp_obfuscated_server();
    let file_hash = Ed2kHash([0x73; 16]);
    let (response, _receive_response) = tokio::sync::oneshot::channel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut pending = Some(PendingBackgroundServerSearch::Source {
        file_hash,
        deadline,
        response,
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let response_port = server_udp_endpoint(&server).port();

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBFOUNDSOURCES,
            payload: vec![1, 0, 0],
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .unwrap();

    match pending {
        Some(PendingBackgroundServerSearch::Source {
            file_hash: actual_hash,
            deadline: actual_deadline,
            ..
        }) => {
            assert_eq!(actual_hash, file_hash);
            assert_eq!(actual_deadline, deadline);
        }
        other => panic!("malformed UDP source reply consumed pending search: {other:?}"),
    }
}

fn server_status_payload(
    challenge: u32,
    users: u32,
    files: u32,
    udp_flags: Option<u32>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&challenge.to_le_bytes());
    payload.extend_from_slice(&users.to_le_bytes());
    payload.extend_from_slice(&files.to_le_bytes());
    if let Some(flags) = udp_flags {
        payload.extend_from_slice(&0u32.to_le_bytes()); // maxusers@12
        payload.extend_from_slice(&0u32.to_le_bytes()); // softfiles@16
        payload.extend_from_slice(&0u32.to_le_bytes()); // hardfiles@20
        payload.extend_from_slice(&flags.to_le_bytes()); // udpflags@24
    }
    payload
}

fn extended_server_status_payload(challenge: u32, udp_flags: u32, udp_key: u32) -> Vec<u8> {
    let mut payload = server_status_payload(challenge, 4242, 99000, Some(udp_flags));
    payload[12..16].copy_from_slice(&5000u32.to_le_bytes()); // max users@12
    payload[16..20].copy_from_slice(&200u32.to_le_bytes()); // soft files@16
    payload[20..24].copy_from_slice(&300u32.to_le_bytes()); // hard files@20
    payload.extend_from_slice(&25u32.to_le_bytes()); // lowid users@28
    payload.extend_from_slice(&4675u16.to_le_bytes()); // obfuscated UDP port@32
    payload.extend_from_slice(&4665u16.to_le_bytes()); // obfuscated TCP port@34
    payload.extend_from_slice(&udp_key.to_le_bytes()); // server UDP key@36
    payload
}

#[test]
fn server_status_matching_challenge_records_users_files_and_udp_flags() {
    let mut server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let challenge = 0x55AA_BEEF;
    let mut outstanding = Some(challenge);
    let mut pending = None;
    let response_port = server.entry.port;

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBSERVSTATRES,
            payload: server_status_payload(challenge, 4242, 99000, Some(0x0000_0331)),
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut outstanding,
        Some(u32::from_le_bytes([198, 51, 100, 9])),
        41,
        None,
    )
    .unwrap();

    let guard = state.blocking_read();
    assert_eq!(guard.server_users, Some(4242));
    assert_eq!(guard.server_files, Some(99000));
    assert_eq!(guard.server_ping_ms, Some(41));
    assert_eq!(guard.server_udp_flags, Some(0x0000_0331));
    // The challenge is consumed so a replayed reply is ignored.
    assert_eq!(outstanding, None);
}

#[test]
fn server_status_mismatched_challenge_is_discarded() {
    let mut server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut outstanding = Some(0x55AA_0001);
    let mut pending = None;
    let response_port = server.entry.port;

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBSERVSTATRES,
            // Echoes a different challenge than the one we issued.
            payload: server_status_payload(0x55AA_0002, 5, 6, None),
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut outstanding,
        None,
        0,
        None,
    )
    .unwrap();

    let guard = state.blocking_read();
    assert_eq!(guard.server_users, None);
    assert_eq!(guard.server_files, None);
    // The outstanding challenge stays armed until the right reply arrives.
    assert_eq!(outstanding, Some(0x55AA_0001));
}

#[test]
fn server_status_refreshes_key_binding_ports_and_persistence_event() {
    let mut server = test_server(0, 0);
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let challenge = 0x1357_2468;
    let public_client_id = u32::from_le_bytes([198, 51, 100, 9]);
    let udp_flags = SERVER_UDP_FLAG_UDPOBFUSCATION | SERVER_UDP_FLAG_TCPOBFUSCATION;
    let udp_key = 0xAABB_CCDD;
    let mut outstanding = Some(challenge);
    let mut pending = None;
    let response_port = server.entry.port;
    let (events, mut event_inbox) = ed2k_server_list_event_channel();

    handle_background_udp_packet(
        &mut server,
        &ServerUdpPacket {
            opcode: OP_GLOBSERVSTATRES,
            payload: extended_server_status_payload(challenge, udp_flags, udp_key),
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        },
        &mut pending,
        &state,
        &mut outstanding,
        Some(public_client_id),
        37,
        Some(&events),
    )
    .unwrap();

    assert_eq!(server.entry.udp_flags, udp_flags);
    assert_eq!(server.entry.udp_key, udp_key);
    assert_eq!(server.entry.udp_key_ip, public_client_id);
    assert_eq!(server.entry.obfuscation_port_tcp, 4665);
    assert_eq!(server.entry.obfuscation_port_udp, 4675);
    let guard = state.blocking_read();
    assert_eq!(guard.server_udp_key, Some(udp_key));
    assert_eq!(guard.server_udp_key_ip, Some(public_client_id));
    assert_eq!(guard.server_max_users, Some(5000));
    assert_eq!(guard.server_low_id_users, Some(25));
    assert_eq!(guard.server_ping_ms, Some(37));
    assert_eq!(guard.server_obfuscation_port_tcp, Some(4665));
    assert_eq!(guard.server_obfuscation_port_udp, Some(4675));
    drop(guard);
    assert_eq!(
        event_inbox.try_recv().unwrap(),
        Ed2kServerListEvent::StatusUpdated {
            endpoint: server.base_endpoint().to_string(),
            users: 4242,
            files: 99000,
            max_users: 5000,
            low_id_users: 25,
            ping_ms: 37,
            soft_files: 200,
            hard_files: 300,
            udp_flags,
            udp_key,
            udp_key_ip: public_client_id,
            obfuscation_port_tcp: 4665,
            obfuscation_port_udp: 4675,
        }
    );
}

#[tokio::test]
async fn server_obfuscation_handshake_encrypts_login_request() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    };
    let expected_login = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(
            hello_identity,
            HELLO_NICKNAME,
            ServerSessionRole::KeywordSearch,
        ),
        false,
    )
    .unwrap();
    let expected_login_for_server = expected_login.clone();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut handshake_prefix = [0u8; 1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 1];
        stream.read_exact(&mut handshake_prefix).await.unwrap();
        assert!(!matches!(
            handshake_prefix[0],
            OP_EDONKEYPROT | super::OP_EMULEPROT | super::OP_PACKEDPROT
        ));
        let client_padding_len =
            usize::from(handshake_prefix[1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
        let mut client_padding = vec![0u8; client_padding_len];
        stream.read_exact(&mut client_padding).await.unwrap();

        let client_public =
            BigUint::from_bytes_be(&handshake_prefix[1..1 + SERVER_OBFUSCATION_PUBLIC_KEY_LEN]);
        let prime = BigUint::from_bytes_be(&SERVER_OBFUSCATION_PRIME_BYTES);
        let generator = BigUint::from(2u8);
        let server_secret = BigUint::from_bytes_be(&[0x42; 16]);
        let server_public = biguint_to_fixed_be(
            &generator.modpow(&server_secret, &prime),
            SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
        )
        .unwrap();
        let shared_secret = biguint_to_fixed_be(
            &client_public.modpow(&server_secret, &prime),
            SERVER_OBFUSCATION_PUBLIC_KEY_LEN,
        )
        .unwrap();
        let mut send_cipher = derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_SERVER);
        let mut receive_cipher =
            derive_server_cipher(&shared_secret, EMULE_TCP_CRYPT_MAGIC_REQUESTER);

        let mut server_reply = Vec::with_capacity(SERVER_OBFUSCATION_PUBLIC_KEY_LEN + 10);
        server_reply.extend_from_slice(&server_public);
        let mut encrypted_reply = Vec::with_capacity(10);
        encrypted_reply.extend_from_slice(&EMULE_TCP_CRYPT_MAGIC_SYNC.to_le_bytes());
        encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_reply.push(EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        encrypted_reply.push(3);
        encrypted_reply.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        send_cipher.apply(&mut encrypted_reply);
        server_reply.extend_from_slice(&encrypted_reply);
        stream.write_all(&server_reply).await.unwrap();

        let mut response_header = [0u8; 6];
        stream.read_exact(&mut response_header).await.unwrap();
        receive_cipher.apply(&mut response_header);
        assert_eq!(
            u32::from_le_bytes(response_header[..4].try_into().unwrap()),
            EMULE_TCP_CRYPT_MAGIC_SYNC
        );
        assert_eq!(response_header[4], EMULE_ENCRYPTION_METHOD_OBFUSCATION);
        let response_padding_len = usize::from(response_header[5]);

        let mut encrypted_tail = vec![0u8; response_padding_len + expected_login_for_server.len()];
        stream.read_exact(&mut encrypted_tail).await.unwrap();
        receive_cipher.apply(&mut encrypted_tail);
        assert_eq!(
            &encrypted_tail[response_padding_len..],
            expected_login_for_server.as_slice()
        );

        let mut id_change = encode_packet(OP_IDCHANGE, &[0x10, 0x20, 0x30, 0x40], false).unwrap();
        send_cipher.apply(&mut id_change);
        stream.write_all(&id_change).await.unwrap();
    });

    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    // Bind the client socket to the same loopback address as the listener.
    let mut session = ServerSession::connect(
        crate::test_bind_ip(),
        endpoint,
        state,
        "test",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    session
        .negotiate_obfuscation_and_send(&expected_login)
        .await
        .unwrap();

    let packet = session.read_packet().await.unwrap().unwrap();
    assert_eq!(packet.opcode, OP_IDCHANGE);
    assert_eq!(packet.payload, [0x10, 0x20, 0x30, 0x40]);

    server.await.unwrap();
}

fn background_test_context(
    state: Arc<RwLock<Ed2kServerState>>,
    connect_timeout: Duration,
) -> BackgroundTestContext {
    let (callback_sessions, _callback_session_inbox) =
        crate::ed2k_tcp::ed2k_callback_session_channel();
    let reachability_authority = ReachabilityRuntimeAuthority::new();
    let session = ServerSessionContext {
        bind_ip: crate::test_bind_ip(),
        nat: Arc::new(NatManager::default()),
        hello_identity: Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: 0,
            direct_udp_callback: false,
        },
        nickname: HELLO_NICKNAME.to_string(),
        last_client_id: Arc::new(AtomicU32::new(0)),
        probe_search_term: None,
        shared_catalog: Arc::new(RwLock::new(IndexedSharedCatalog::default())),
        state,
        kad_firewall: Arc::new(Mutex::new(KadFirewallState::default())),
        keepalive_interval: None,
        connect_timeout,
        rotation_interval: None,
        shutdown: Arc::new(AtomicBool::new(false)),
        session_cancel: CancellationToken::new(),
        public_ip: reachability_authority.reader(),
        activation: super::super::types::ServerSessionActivation::active(),
        server_list_events: None,
        add_servers_from_server: false,
        offer_files_capability_enabled: true,
        callback_sessions,
    };
    BackgroundTestContext {
        session,
        reachability_authority,
    }
}

async fn run_test_server_session(
    server: &ResolvedServerEntry,
    context: &BackgroundTestContext,
    inbox: &Arc<Mutex<Ed2kServerSearchInbox>>,
) -> anyhow::Result<ServerSessionExit> {
    let reachability = active_server_reachability(&context.reachability_authority);
    run_one_server_session(server, context, inbox, &reachability.writer).await
}

async fn handle_test_server_packet(
    session: &mut ServerSession,
    packet: Ed2kPacket,
    context: &BackgroundTestContext,
    allow_probe_search: bool,
) -> anyhow::Result<()> {
    let reachability = active_server_reachability(&context.reachability_authority);
    handle_server_packet(
        session,
        packet,
        context,
        &reachability.writer,
        allow_probe_search,
    )
    .await
}

fn background_test_server(endpoint: SocketAddr) -> ResolvedServerEntry {
    let SocketAddr::V4(endpoint_v4) = endpoint else {
        panic!("ED2K test server must use IPv4");
    };
    let mut server = test_server(0, 0);
    server.entry.host = endpoint_v4.ip().to_string();
    server.entry.port = endpoint_v4.port();
    server.ip = *endpoint_v4.ip();
    server
}

async fn read_client_frame(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; TCP_PACKET_HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], OP_EDONKEYPROT);
    let payload_len =
        u32::from_le_bytes(header[1..5].try_into().unwrap()).saturating_sub(1) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.unwrap();
    (header[5], payload)
}

async fn read_login_request_payload(stream: &mut TcpStream) -> Vec<u8> {
    let (opcode, payload) = read_client_frame(stream).await;
    assert_eq!(opcode, OP_LOGINREQUEST);
    payload
}

async fn read_login_request(stream: &mut TcpStream) {
    let _ = read_login_request_payload(stream).await;
}

fn push_server_ident_named_u32(payload: &mut Vec<u8>, name: &str, value: u32) {
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&value.to_le_bytes());
}

fn push_server_ident_numeric_u32(payload: &mut Vec<u8>, name: u8, value: u32) {
    payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT32);
    payload.push(name);
    payload.extend_from_slice(&value.to_le_bytes());
}

fn offer_files_v1_server_ident() -> Vec<u8> {
    let mut payload = vec![0u8; 22];
    payload.extend_from_slice(&5u32.to_le_bytes());
    push_server_ident_named_u32(&mut payload, "offerfiles_v", OFFER_FILES_CAPABILITY_VERSION);
    push_server_ident_named_u32(&mut payload, "offerfiles_batch_max", 25);
    push_server_ident_named_u32(&mut payload, "offerfiles_min_interval_ms", 10);
    push_server_ident_numeric_u32(&mut payload, ST_SOFTFILES, 1_000);
    push_server_ident_numeric_u32(&mut payload, ST_HARDFILES, 26);
    payload
}

fn background_offer_file() -> Ed2kSharedEntry {
    Ed2kSharedEntry {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "offerfiles-v1.bin".to_string(),
        file_size: 1_234,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        media: Default::default(),
        all_time_uploaded_bytes: 0,
        complete_parts: Vec::new(),
        publish: Default::default(),
    }
}

#[tokio::test]
async fn background_offer_files_v1_waits_for_server_ident_before_first_batch() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let login = read_login_request_payload(&mut stream).await;
        assert_eq!(u32::from_le_bytes(login[22..26].try_into().unwrap()), 5);
        let mut capability_tag = vec![TAGTYPE_UINT32, 12, 0];
        capability_tag.extend_from_slice(b"offerfiles_v");
        capability_tag.extend_from_slice(&OFFER_FILES_CAPABILITY_VERSION.to_le_bytes());
        assert!(login.ends_with(&capability_tag));

        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), read_client_frame(&mut stream))
                .await
                .is_err(),
            "v1 publication must wait for the first server identity snapshot"
        );

        stream
            .write_all(
                &encode_packet(OP_SERVERIDENT, &offer_files_v1_server_ident(), false).unwrap(),
            )
            .await
            .unwrap();
        let (opcode, payload) =
            tokio::time::timeout(Duration::from_secs(1), read_client_frame(&mut stream))
                .await
                .expect("negotiated first offer should be sent after server identity");
        assert_eq!(opcode, OP_OFFERFILES);
        assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
    });

    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(2));
    context
        .shared_catalog
        .write()
        .await
        .push(background_offer_file());
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let server = background_test_server(endpoint);
    let inbox = Arc::new(Mutex::new(inbox));
    let session = run_test_server_session(&server, &context, &inbox);

    let (session_result, server_result) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(session, server_task)
    })
    .await
    .expect("background v1 handshake should complete promptly");
    server_result.unwrap();
    assert!(
        session_result.is_err(),
        "mock server closes after the assertion"
    );
}

#[tokio::test]
async fn background_offer_files_v1_timeout_reconnects_before_legacy_publish() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut advertised_stream, _) = listener.accept().await.unwrap();
        let advertised_login = read_login_request_payload(&mut advertised_stream).await;
        assert_eq!(
            u32::from_le_bytes(advertised_login[22..26].try_into().unwrap()),
            5
        );
        assert!(
            advertised_login
                .windows("offerfiles_v".len())
                .any(|window| window == b"offerfiles_v")
        );

        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        advertised_stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();

        let mut unexpected_offer = [0u8; 1];
        let advertised_read = tokio::time::timeout(
            Duration::from_secs(3),
            advertised_stream.read(&mut unexpected_offer),
        )
        .await
        .expect("ambiguous v1 connection should close after the negotiation timeout")
        .unwrap();
        assert_eq!(
            advertised_read, 0,
            "ambiguous v1 connection must close before any offer-files bytes are sent"
        );

        let (mut fallback_stream, _) =
            tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("client should reconnect without offerfiles_v")
                .unwrap();
        let fallback_login = read_login_request_payload(&mut fallback_stream).await;
        assert_eq!(
            u32::from_le_bytes(fallback_login[22..26].try_into().unwrap()),
            4
        );
        assert!(
            !fallback_login
                .windows("offerfiles_v".len())
                .any(|window| window == b"offerfiles_v")
        );

        fallback_stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        let (opcode, payload) = tokio::time::timeout(
            Duration::from_secs(1),
            read_client_frame(&mut fallback_stream),
        )
        .await
        .expect("legacy offer should be sent only on the fallback connection");
        assert_eq!(opcode, OP_OFFERFILES);
        assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
    });

    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(4));
    context
        .shared_catalog
        .write()
        .await
        .push(background_offer_file());
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let server = background_test_server(endpoint);
    let inbox = Arc::new(Mutex::new(inbox));
    let session = run_test_server_session(&server, &context, &inbox);

    let (session_result, server_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(session, server_task)
    })
    .await
    .expect("background fallback handshake should complete promptly");
    server_result.unwrap();
    assert!(
        session_result.is_err(),
        "mock server closes after the assertion"
    );
}

#[tokio::test]
async fn background_login_stall_expires_the_whole_pending_attempt() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_millis(75));
    let (_, inbox) = new_ed2k_server_search_channel(1);

    let error = run_test_server_session(
        &background_test_server(endpoint),
        &context,
        &Arc::new(Mutex::new(inbox)),
    )
    .await
    .expect_err("a server that never assigns an ID must time out");

    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Ed2kServerFailure>())
        .expect("login timeout should retain its classified failure");
    assert_eq!(failure.phase, Ed2kServerFailurePhase::Connect);
    assert_eq!(failure.reason, Ed2kServerFailureReason::TimeoutUnreachable);
    assert!(!failure.counts_toward_dead_server());
    let state = state.read().await;
    assert!(!state.connecting);
    assert!(!state.connected);
    assert_eq!(state.endpoint, None);
    server_task.abort();
}

#[tokio::test]
async fn zero_id_stays_connecting_until_the_pending_attempt_times_out() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (zero_sent, zero_observed) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &0u32.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        let _ = zero_sent.send(());
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_millis(150));
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);

    let observe_pending = async {
        zero_observed.await.unwrap();
        tokio::time::timeout(Duration::from_millis(75), async {
            loop {
                let snapshot = state.read().await.clone();
                if snapshot.connecting && !snapshot.connected && snapshot.client_id.is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("zero ID should leave the session visibly pending");
    };
    let (result, ()) = tokio::join!(
        run_test_server_session(&server, &context, &inbox),
        observe_pending
    );

    let error = result.expect_err("zero ID must not accept the login");
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Ed2kServerFailure>())
        .expect("zero-ID timeout should retain its classified failure");
    assert_eq!(failure.reason, Ed2kServerFailureReason::TimeoutUnreachable);
    let state = state.read().await;
    assert!(!state.connecting);
    assert!(!state.connected);
    assert_eq!(state.client_id, None);
    server_task.abort();
}

#[tokio::test]
async fn valid_id_after_zero_accepts_the_still_pending_login() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &0u32.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_millis(500));
    let shutdown = Arc::clone(&context.shutdown);
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);

    let observe_connected = async {
        let snapshot = tokio::time::timeout(Duration::from_millis(250), async {
            loop {
                let snapshot = state.read().await.clone();
                if snapshot.connected {
                    break snapshot;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a valid ID after zero should accept the pending login");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        snapshot
    };
    let (result, snapshot) = tokio::join!(
        run_test_server_session(&server, &context, &inbox),
        observe_connected
    );

    assert_eq!(result.unwrap(), ServerSessionExit::IntentionalShutdown);
    assert!(!snapshot.connecting);
    assert!(snapshot.connected);
    assert_eq!(
        snapshot.client_id,
        Some(u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]))
    );
    assert_eq!(snapshot.tcp_firewalled(), Some(false));
    server_task.abort();
}

#[tokio::test]
async fn shutdown_preempts_a_silent_pending_login() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (login_sent, login_seen) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        let _ = login_sent.send(());
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(5));
    let shutdown = Arc::clone(&context.shutdown);
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);

    let request_shutdown = async {
        login_seen.await.unwrap();
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    };
    let (result, ()) = tokio::join!(
        run_test_server_session(&server, &context, &inbox),
        request_shutdown
    );

    assert_eq!(result.unwrap(), ServerSessionExit::IntentionalShutdown);
    let state = state.read().await;
    assert!(!state.connecting);
    assert!(!state.connected);
    server_task.abort();
}

#[tokio::test]
async fn reject_before_id_change_does_not_abort_login() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        stream
            .write_all(&encode_packet(OP_REJECT, &[], false).unwrap())
            .await
            .unwrap();
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(1));
    let shutdown = Arc::clone(&context.shutdown);
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);

    let observe_connected = async {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.read().await.connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("OP_REJECT must leave the login attempt awaiting OP_IDCHANGE");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    };
    let (result, ()) = tokio::join!(
        run_test_server_session(&server, &context, &inbox),
        observe_connected
    );

    assert_eq!(result.unwrap(), ServerSessionExit::IntentionalShutdown);
    server_task.abort();
}

#[tokio::test]
async fn reject_does_not_complete_or_disconnect_pending_background_search() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        loop {
            let (opcode, _) = read_client_frame(&mut stream).await;
            if opcode == OP_SEARCHREQUEST {
                break;
            }
        }
        let mut replies = encode_packet(OP_REJECT, &[0xAA, 0x55], false).unwrap();
        replies.extend_from_slice(
            &encode_packet(OP_SEARCHRESULT, &0u32.to_le_bytes(), false).unwrap(),
        );
        stream.write_all(&replies).await.unwrap();
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(1));
    let shutdown = Arc::clone(&context.shutdown);
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);
    let cancel = CancellationToken::new();

    let search = async {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.read().await.connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background session should accept login");
        let result = search_keyword_via_background_session(
            &handle,
            "reject followed by result",
            Default::default(),
            Duration::from_secs(1),
            &cancel,
        )
        .await;
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    };
    let (session_result, search_result) =
        tokio::join!(run_test_server_session(&server, &context, &inbox), search);

    assert_eq!(
        session_result.unwrap(),
        ServerSessionExit::IntentionalShutdown
    );
    assert!(search_result.unwrap().is_empty());
    server_task.abort();
}

#[tokio::test]
async fn uncorrelated_reject_does_not_downgrade_negotiated_offer_pacing() {
    let (mut session, _peer) = connected_background_test_session().await;
    let policy = OfferFilesPolicy::validate(1, 25, 10, 1_000, 1_001).unwrap();
    session.login_accepted = true;
    session.offer_files_pacing = OfferFilesPacingMode::Negotiated(policy);
    let context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_REJECT,
            payload: Vec::new(),
        },
        &context,
        false,
    )
    .await
    .unwrap();

    assert_eq!(
        session.offer_files_pacing,
        OfferFilesPacingMode::Negotiated(policy)
    );
}

#[tokio::test]
async fn malformed_uncorrelated_search_result_is_packet_local() {
    let (mut session, _peer) = connected_background_test_session().await;
    let context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SEARCHRESULT,
            payload: vec![0x01],
        },
        &context,
        false,
    )
    .await
    .unwrap();

    let mut status = 123u32.to_le_bytes().to_vec();
    status.extend_from_slice(&456u32.to_le_bytes());
    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SERVERSTATUS,
            payload: status,
        },
        &context,
        false,
    )
    .await
    .unwrap();

    let state = session.state.read().await;
    assert_eq!(state.server_users, Some(123));
    assert_eq!(state.server_files, Some(456));
}

#[tokio::test]
async fn malformed_typed_replies_preserve_pending_request_and_session() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let file_hash = Ed2kHash([0x61; 16]);
    let stale_hash = Ed2kHash([0x62; 16]);
    let result_hash = Ed2kHash([0x63; 16]);
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();

        loop {
            let (opcode, _) = read_client_frame(&mut stream).await;
            if opcode == OP_SEARCHREQUEST {
                break;
            }
        }
        let mut first_page = 1u32.to_le_bytes().to_vec();
        first_page.extend_from_slice(&result_hash.0);
        first_page.extend_from_slice(&0u32.to_le_bytes());
        first_page.extend_from_slice(&4662u16.to_le_bytes());
        first_page.extend_from_slice(&0u32.to_le_bytes());
        first_page.push(1);
        stream
            .write_all(&encode_packet(OP_SEARCHRESULT, &first_page, false).unwrap())
            .await
            .unwrap();

        let (opcode, payload) = read_client_frame(&mut stream).await;
        assert_eq!(opcode, OP_QUERY_MORE_RESULT);
        assert!(payload.is_empty());

        let mut keyword_replies = encode_packet(OP_SEARCHRESULT, &[0x01], false).unwrap();
        keyword_replies.extend_from_slice(
            &encode_packet(OP_SEARCHRESULT, &0u32.to_le_bytes(), false).unwrap(),
        );
        stream.write_all(&keyword_replies).await.unwrap();

        loop {
            let (opcode, payload) = read_client_frame(&mut stream).await;
            if matches!(opcode, OP_GETSOURCES | OP_GETSOURCES_OBFU) {
                assert_eq!(&payload[..16], &file_hash.0);
                break;
            }
        }
        stream
            .write_all(&encode_packet(OP_FOUNDSOURCES, &file_hash.0, false).unwrap())
            .await
            .unwrap();

        let mut stale_response = stale_hash.0.to_vec();
        stale_response.push(0);
        let mut valid_response = file_hash.0.to_vec();
        valid_response.push(0);
        valid_response.extend_from_slice(&[0xAA, 0xBB]);
        let mut replies = encode_packet(OP_FOUNDSOURCES, &file_hash.0, false).unwrap();
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &stale_response, false).unwrap());
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &valid_response, false).unwrap());
        stream.write_all(&replies).await.unwrap();
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(1));
    let shutdown = Arc::clone(&context.shutdown);
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);
    let cancel = CancellationToken::new();

    let requests = async {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.read().await.connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background session should accept login");

        let keyword_results = search_keyword_via_background_session(
            &handle,
            "malformed result",
            Default::default(),
            Duration::from_secs(1),
            &cancel,
        )
        .await
        .expect("valid final page must complete the original keyword request");
        assert_eq!(keyword_results.len(), 1);
        assert_eq!(keyword_results[0].file_hash, result_hash);

        let results = search_source_via_background_session(
            &handle,
            file_hash,
            123,
            Duration::from_secs(1),
            &cancel,
        )
        .await
        .expect("valid matching reply must complete the original source request");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        results
    };
    let (session_result, results) =
        tokio::join!(run_test_server_session(&server, &context, &inbox), requests);

    assert_eq!(
        session_result.unwrap(),
        ServerSessionExit::IntentionalShutdown
    );
    assert!(results.is_empty());
    server_task.abort();
}

#[tokio::test]
async fn malformed_batch_reply_preserves_partial_results_and_pending_hashes() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let file_hash_a = Ed2kHash([0x71; 16]);
    let file_hash_b = Ed2kHash([0x72; 16]);
    let stale_hash = Ed2kHash([0x73; 16]);
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        let high_id = u32::from_le_bytes([0x10, 0x20, 0x30, 0x40]);
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &high_id.to_le_bytes(), false).unwrap())
            .await
            .unwrap();

        let mut requested = HashSet::new();
        while requested.len() < 2 {
            let (opcode, payload) = read_client_frame(&mut stream).await;
            if matches!(opcode, OP_GETSOURCES | OP_GETSOURCES_OBFU) {
                requested.insert(Ed2kHash(payload[..16].try_into().unwrap()));
            }
        }
        assert_eq!(requested, HashSet::from([file_hash_a, file_hash_b]));

        let mut valid_a = file_hash_a.0.to_vec();
        valid_a.push(0);
        let mut stale = stale_hash.0.to_vec();
        stale.push(0);
        let mut valid_b = file_hash_b.0.to_vec();
        valid_b.push(0);
        valid_b.push(0xAA);
        let mut replies = encode_packet(OP_FOUNDSOURCES, &[0x01; 8], false).unwrap();
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &valid_a, false).unwrap());
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &file_hash_b.0, false).unwrap());
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &stale, false).unwrap());
        replies.extend_from_slice(&encode_packet(OP_FOUNDSOURCES, &valid_b, false).unwrap());
        stream.write_all(&replies).await.unwrap();
        std::future::pending::<()>().await;
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let context = background_test_context(Arc::clone(&state), Duration::from_secs(1));
    let shutdown = Arc::clone(&context.shutdown);
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);
    let cancel = CancellationToken::new();

    let request = async {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if state.read().await.connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background session should accept login");

        let results = search_source_batch_via_background_session(
            &handle,
            &[
                Ed2kServerSourceBatchTarget {
                    file_hash: file_hash_a,
                    file_size: 123,
                },
                Ed2kServerSourceBatchTarget {
                    file_hash: file_hash_b,
                    file_size: 456,
                },
            ],
            Duration::from_secs(1),
            &cancel,
        )
        .await
        .expect("valid replies must complete the original batch");
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        results
    };
    let (session_result, results) =
        tokio::join!(run_test_server_session(&server, &context, &inbox), request);

    assert_eq!(
        session_result.unwrap(),
        ServerSessionExit::IntentionalShutdown
    );
    assert_eq!(results.len(), 2);
    assert_eq!(results.get(&file_hash_a), Some(&Vec::new()));
    assert_eq!(results.get(&file_hash_b), Some(&Vec::new()));
    server_task.abort();
}
