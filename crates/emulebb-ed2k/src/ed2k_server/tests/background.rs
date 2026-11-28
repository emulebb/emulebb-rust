use super::*;

#[tokio::test]
async fn cancelled_queued_keyword_request_cannot_keep_its_result_stream_open() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let (result_sink, mut observations) = tokio::sync::mpsc::channel(1);
    let cancel = CancellationToken::new();
    let search = search_keyword_via_background_session(
        &handle,
        "sample query",
        Default::default(),
        Duration::from_secs(1),
        &cancel,
        Some(result_sink),
    );
    let queued = async {
        let request = inbox.receiver.recv().await.unwrap();
        cancel.cancel();
        request
    };
    let (outcome, request) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(search, queued)
    })
    .await
    .unwrap();
    assert_eq!(
        outcome.unwrap(),
        Ed2kBackgroundKeywordSearchOutcome::Replied(Vec::new())
    );
    // Retain the queued request as a disconnected runtime would, without
    // retaining the caller's result channel or allowing a later upgrade.
    let BackgroundServerSearchRequest::Keyword { result_sink, .. } = request else {
        panic!("expected keyword request");
    };
    assert!(result_sink.unwrap().upgrade().is_none());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), observations.recv())
            .await
            .unwrap()
            .is_none()
    );
}
use std::collections::{HashMap, HashSet};
use tokio::{net::TcpStream, sync::oneshot, time::Instant as TokioInstant};

use crate::ed2k_server::{
    Ed2kServerSearchInbox, OP_CALLBACK_FAIL, OP_CALLBACKREQUEST, OP_SERVERLIST, ProbeSearchState,
    background::{BackgroundServerSearchContext, start_background_server_search},
};

fn test_server_udp_packet(opcode: u8, payload: Vec<u8>, peer: SocketAddr) -> ServerUdpPacket {
    ServerUdpPacket {
        opcode,
        payload,
        evidence: Ed2kServerUdpEvidence::new(1, Ed2kServerUdpTransport::Plaintext, peer),
    }
}

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
    let mut refusal = receive_response.await.unwrap().unwrap();
    let (opcode, payload) = read_source_request_frame(&mut peer).await;
    assert_eq!(opcode, OP_CALLBACKREQUEST);
    assert_eq!(payload, target_low_id.to_le_bytes());
    let context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));
    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_CALLBACK_FAIL,
            payload: vec![1],
        },
        &context,
        false,
    )
    .await
    .unwrap();
    assert_eq!(refusal.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_CALLBACK_FAIL,
            payload: vec![],
        },
        &context,
        false,
    )
    .await
    .unwrap();
    assert_eq!(refusal.try_recv(), Ok(()));
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
    use crate::ed2k_transfer::ED2K_LEGACY_FILE_SIZE_MAX;

    let small = Ed2kServerSourceBatchTarget {
        file_hash: Ed2kHash([0x31; 16]),
        file_size: ED2K_LEGACY_FILE_SIZE_MAX,
    };
    let large = Ed2kServerSourceBatchTarget {
        file_hash: Ed2kHash([0x32; 16]),
        file_size: ED2K_LEGACY_FILE_SIZE_MAX + 1,
    };

    for (connect_options, server_flags, expected_opcode, targets, sent_targets) in [
        (0, None, OP_GETSOURCES, vec![large], vec![]),
        (0, Some(0), OP_GETSOURCES, vec![small, large], vec![small]),
        (
            0,
            Some(SERVER_TCP_FLAG_LARGEFILES),
            OP_GETSOURCES,
            vec![small, large],
            vec![small, large],
        ),
        (
            0x01,
            Some(SERVER_TCP_FLAG_TCPOBFUSCATION | SERVER_TCP_FLAG_LARGEFILES),
            OP_GETSOURCES_OBFU,
            vec![small, large],
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
        assert_eq!(pending_hashes.len(), sent_targets.len());
        for target in sent_targets {
            assert!(pending_hashes.contains(&target.file_hash));
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
                let _ = response.send(Ok(Ed2kBackgroundKeywordSearchOutcome::Replied(vec![
                    expected_for_task,
                ])));
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
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        results,
        Ed2kBackgroundKeywordSearchOutcome::Replied(vec![expected])
    );
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
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        results,
        Ed2kBackgroundKeywordSearchOutcome::Replied(Vec::new())
    );
    assert!(matches!(
        inbox.receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn background_keyword_wrapper_waits_for_the_session_owned_deadline() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let search = tokio::spawn(async move {
        search_keyword_via_background_session(
            &handle,
            "delayed dispatch",
            Default::default(),
            Duration::from_millis(10),
            &CancellationToken::new(),
            None,
        )
        .await
    });
    let request = inbox.receiver.recv().await.unwrap();
    let BackgroundServerSearchRequest::Keyword {
        timeout, response, ..
    } = request
    else {
        panic!("expected keyword search command")
    };
    assert_eq!(timeout, Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(30)).await;
    response
        .send(Ok(Ed2kBackgroundKeywordSearchOutcome::Replied(Vec::new())))
        .unwrap();

    assert_eq!(
        search.await.unwrap().unwrap(),
        Ed2kBackgroundKeywordSearchOutcome::Replied(Vec::new())
    );
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
                let _ = response.send(Ok(HashMap::from([(
                    file_hash_b,
                    Ed2kServerSourceSearchResult {
                        server_endpoint: SocketAddr::from(([127, 0, 0, 1], 4661)),
                        trace_id: 7,
                        transport_mode: "plaintext",
                        response_opcode: OP_FOUNDSOURCES,
                        sources: vec![expected_for_task],
                    },
                )])));
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
        &mut Vec::new(),
    )
    .await
    .unwrap();

    let result = results.get(&file_hash_b).unwrap();
    assert_eq!(result.trace_id, 7);
    assert_eq!(result.response_opcode, OP_FOUNDSOURCES);
    assert_eq!(result.sources, vec![expected]);
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
        &test_server_udp_packet(
            OP_GLOBFOUNDSOURCES,
            payload,
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .await
    .unwrap();

    let sources = receive_response.await.unwrap().unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(server.base_endpoint()));
}

#[tokio::test]
async fn background_udp_keyword_search_keeps_pending_after_malformed_reply() {
    let mut server = test_udp_obfuscated_server();
    let (response, _receive_response) = tokio::sync::oneshot::channel();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let mut pending = Some(PendingBackgroundServerSearch::Keyword {
        query: "linux".to_string(),
        deadline,
        results: Vec::new(),
        page_count: 0,
        cancel: CancellationToken::new(),
        result_sink: None,
        response,
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let response_port = server_udp_endpoint(&server).port();

    handle_background_udp_packet(
        &mut server,
        &test_server_udp_packet(
            OP_GLOBSEARCHRES,
            vec![1, 0, 0],
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .await
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

#[tokio::test]
async fn background_udp_source_search_keeps_pending_after_malformed_reply() {
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
        &test_server_udp_packet(
            OP_GLOBFOUNDSOURCES,
            vec![1, 0, 0],
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut None,
        None,
        0,
        None,
    )
    .await
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

#[tokio::test]
async fn server_status_matching_challenge_records_users_files_and_udp_flags() {
    let mut server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let challenge = 0x55AA_BEEF;
    let mut outstanding = Some(challenge);
    let mut pending = None;
    let response_port = server.entry.port;

    handle_background_udp_packet(
        &mut server,
        &test_server_udp_packet(
            OP_GLOBSERVSTATRES,
            server_status_payload(challenge, 4242, 99000, Some(0x0000_0331)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut outstanding,
        Some(u32::from_le_bytes([198, 51, 100, 9])),
        41,
        None,
    )
    .await
    .unwrap();

    let guard = state.read().await;
    assert_eq!(guard.server_users, Some(4242));
    assert_eq!(guard.server_files, Some(99000));
    assert_eq!(guard.server_ping_ms, Some(41));
    assert_eq!(guard.server_udp_flags, Some(0x0000_0331));
    // The challenge is consumed so a replayed reply is ignored.
    assert_eq!(outstanding, None);
}

#[tokio::test]
async fn server_status_mismatched_challenge_is_discarded() {
    let mut server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut outstanding = Some(0x55AA_0001);
    let mut pending = None;
    let response_port = server.entry.port;
    let (events, mut event_inbox) = ed2k_server_list_event_channel();

    handle_background_udp_packet(
        &mut server,
        &test_server_udp_packet(
            OP_GLOBSERVSTATRES,
            // Echoes a different challenge than the one we issued.
            server_status_payload(0x55AA_0002, 5, 6, None),
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut outstanding,
        None,
        0,
        Some(&events),
    )
    .await
    .unwrap();

    let guard = state.read().await;
    assert_eq!(guard.server_users, None);
    assert_eq!(guard.server_files, None);
    // The outstanding challenge stays armed until the right reply arrives.
    assert_eq!(outstanding, Some(0x55AA_0001));
    assert!(
        event_inbox.try_recv().is_err(),
        "a rejected status reply must not reach the authoritative mutation consumer"
    );
}

#[tokio::test]
async fn server_status_refreshes_key_binding_ports_and_persistence_event() {
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
        &test_server_udp_packet(
            OP_GLOBSERVSTATRES,
            extended_server_status_payload(challenge, udp_flags, udp_key),
            SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
        ),
        &mut pending,
        &state,
        &mut outstanding,
        Some(public_client_id),
        37,
        Some(&events),
    )
    .await
    .unwrap();

    assert_eq!(server.entry.udp_flags, udp_flags);
    assert_eq!(server.entry.udp_key, udp_key);
    assert_eq!(server.entry.udp_key_ip, public_client_id);
    assert_eq!(server.entry.obfuscation_port_tcp, 4665);
    assert_eq!(server.entry.obfuscation_port_udp, 4675);
    let guard = state.read().await;
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
            udp_evidence: Some(Ed2kServerUdpStatusEvidence::new(
                Ed2kServerUdpEvidence::new(
                    1,
                    Ed2kServerUdpTransport::Plaintext,
                    SocketAddr::from((Ipv4Addr::LOCALHOST, response_port)),
                ),
                challenge,
            )),
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
    let login_payload = encode_login_request(
        hello_identity,
        HELLO_NICKNAME,
        ServerSessionRole::KeywordSearch,
    );
    let expected_login = encode_packet(OP_LOGINREQUEST, &login_payload, false).unwrap();
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
        crate::networking::EgressBinding::new(
            crate::test_bind_ip(),
            crate::networking::EgressRoute::StrictInterface,
        ),
        endpoint,
        state,
        "test",
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    session
        .negotiate_obfuscation_and_send(OP_LOGINREQUEST, &login_payload)
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
        egress_route: crate::networking::EgressRoute::StrictInterface,
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
async fn cached_offer_batch_does_not_publish_withdrawn_content() {
    let root = crate::paths::unique_test_dir("cached-offer-withdrawal");
    let runtime = crate::ed2k_transfer::Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let catalog = runtime.shared_catalog();
    catalog.write().await.push(background_offer_file());
    let (mut session, mut peer) = connected_background_test_session().await;
    session.configure_offer_files_capability(false);
    session.offer_files_ranked_catalog = {
        let catalog = catalog.read().await;
        crate::ed2k_server::startup::ranked_offer_files(&catalog, true)
    };
    session.offer_files_refresh_catalog = false;
    assert_eq!(session.offer_files_ranked_catalog.len(), 1);
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    drop(mutation);
    let result = crate::ed2k_server::startup::send_offer_files_advertisement(
        &mut session,
        &catalog,
        Ipv4Addr::LOCALHOST,
        4662,
    )
    .await
    .unwrap();
    assert_eq!(result.entries_sent, 0);
    assert!(session.offer_files_published_hashes.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_client_frame(&mut peer))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn cached_offer_batch_preserves_a_copy_in_another_root() {
    let root = crate::paths::unique_test_dir("cached-offer-independent-root");
    let old_root = root.join("old");
    let other_root = root.join("other");
    std::fs::create_dir_all(&old_root).unwrap();
    std::fs::create_dir_all(&other_root).unwrap();
    let only_old = old_root.join("only-old.bin");
    let old_copy = old_root.join("both.bin");
    let other_copy = other_root.join("both.bin");
    std::fs::write(&only_old, b"only old root").unwrap();
    std::fs::write(&old_copy, b"independent copy").unwrap();
    std::fs::write(&other_copy, b"independent copy").unwrap();
    let mut metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
    metadata
        .replace_shared_directory_roots(
            &[&old_root, &other_root]
                .into_iter()
                .map(|path| emulebb_metadata::MetadataSharedDirectoryRoot {
                    path: path.to_string_lossy().into_owned(),
                    watch_enabled: false,
                    monitor_owned: false,
                    shareable: true,
                    accessible: true,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let runtime = crate::ed2k_transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
        &root,
        metadata.clone(),
    )
    .unwrap();
    runtime
        .ingest_local_file(&only_old, "only-old.bin")
        .await
        .unwrap();
    let shared = runtime
        .ingest_local_file(&old_copy, "both.bin")
        .await
        .unwrap();
    runtime
        .ingest_local_file(&other_copy, "both.bin")
        .await
        .unwrap();
    for (base, path) in [
        (&old_root, &only_old),
        (&old_root, &old_copy),
        (&other_root, &other_copy),
    ] {
        let native_path = crate::long_path::long_path(path);
        let fingerprint = metadata
            .local_file_instance(&native_path)
            .unwrap()
            .unwrap()
            .verified_fingerprint;
        let relative = native_path
            .strip_prefix(crate::long_path::long_path(base))
            .unwrap();
        assert!(
            metadata
                .admit_local_path_to_root(base, &native_path, relative, &fingerprint)
                .unwrap()
        );
    }
    runtime.refresh_complete_shared_catalog().await.unwrap();
    let catalog = runtime.shared_catalog();
    let (mut session, mut peer) = connected_background_test_session().await;
    session.configure_offer_files_capability(false);
    session.offer_files_ranked_catalog = {
        let catalog = catalog.read().await;
        crate::ed2k_server::startup::ranked_offer_files(&catalog, true)
    };
    session.offer_files_refresh_catalog = false;
    assert_eq!(session.offer_files_ranked_catalog.len(), 2);
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    metadata
        .set_shared_root_accessible(&old_root, false)
        .unwrap();
    drop(mutation);
    let sent = crate::ed2k_server::startup::send_offer_files_advertisement(
        &mut session,
        &catalog,
        Ipv4Addr::LOCALHOST,
        4662,
    )
    .await
    .unwrap();
    assert_eq!(sent.entries_sent, 1);
    let (opcode, payload) = read_client_frame(&mut peer).await;
    assert_eq!(opcode, OP_OFFERFILES);
    assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
    assert_eq!(&payload[4..20], hex::decode(shared.file_hash).unwrap());
}

#[tokio::test]
async fn cached_complete_offer_uses_live_partial_fields_after_withdrawal() {
    use crate::ed2k_transfer::ED2K_PART_SIZE;
    let root = crate::paths::unique_test_dir("cached-offer-partial-fallback");
    let source_dir = root.join("library");
    std::fs::create_dir_all(&source_dir).unwrap();
    let path = source_dir.join("complete-name.bin");
    let payload = vec![0x41; ED2K_PART_SIZE as usize + 32];
    std::fs::write(&path, &payload).unwrap();
    let metadata = emulebb_metadata::MetadataStore::in_memory().unwrap();
    let runtime = crate::ed2k_transfer::Ed2kTransferRuntime::load_or_create_with_metadata(
        &root,
        metadata.clone(),
    )
    .unwrap();
    let shared = runtime
        .ingest_local_file(&path, "complete-name.bin")
        .await
        .unwrap();
    crate::ed2k_transfer::test_support::admit_local_share(&runtime, &source_dir, &path).await;
    let complete = runtime.serving_view(&shared.file_hash).await.unwrap();
    let hashes = complete
        .md4_hashset
        .iter()
        .map(|hash| hex::decode(hash).unwrap().try_into().unwrap())
        .collect();
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime,
        shared.file_hash.parse().unwrap(),
        "partial-name.bin".into(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime.store_md4_hashset(job.token, hashes).await.unwrap();
    runtime
        .append_piece_block(
            job.token,
            0,
            0,
            ED2K_PART_SIZE,
            &payload[..ED2K_PART_SIZE as usize],
        )
        .await
        .unwrap();
    let catalog = runtime.shared_catalog();
    let (mut session, mut peer) = connected_background_test_session().await;
    session.configure_offer_files_capability(false);
    session.server_flags = Some(SERVER_TCP_FLAG_COMPRESSION);
    session.offer_files_ranked_catalog = {
        let catalog = catalog.read().await;
        crate::ed2k_server::startup::ranked_offer_files(&catalog, true)
    };
    session.offer_files_refresh_catalog = false;
    assert_eq!(session.offer_files_ranked_catalog.len(), 1);
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    metadata
        .withdraw_local_file_path(&crate::long_path::long_path(&path))
        .unwrap();
    drop(mutation);
    let sent = crate::ed2k_server::startup::send_offer_files_advertisement(
        &mut session,
        &catalog,
        Ipv4Addr::LOCALHOST,
        4662,
    )
    .await
    .unwrap();
    assert_eq!(sent.entries_sent, 1);
    let mut header = [0u8; TCP_PACKET_HEADER_LEN];
    peer.read_exact(&mut header).await.unwrap();
    let mut body = vec![0; u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize - 1];
    peer.read_exact(&mut body).await.unwrap();
    let body = decode_server_payload(header[0], body).unwrap();
    assert_eq!(header[5], OP_OFFERFILES);
    assert_eq!(u32::from_le_bytes(body[..4].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_le_bytes(body[20..24].try_into().unwrap()),
        super::super::OFFER_FILE_INCOMPLETE_SENTINEL_CLIENT_ID
    );
    assert!(
        body.windows(b"partial-name.bin".len())
            .any(|window| window == b"partial-name.bin")
    );
    assert!(
        !body
            .windows(b"complete-name.bin".len())
            .any(|window| window == b"complete-name.bin")
    );
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
async fn background_offer_files_v1_timeout_publishes_legacy_on_same_connection() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let (fallback_offer_sent, fallback_offer_observed) = oneshot::channel();
    let (fallback_state_asserted, fallback_state_release) = oneshot::channel();
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

        let (opcode, payload) = tokio::time::timeout(
            Duration::from_secs(6),
            read_client_frame(&mut advertised_stream),
        )
        .await
        .expect("legacy offer should be sent on the advertised connection");
        assert_eq!(opcode, OP_OFFERFILES);
        assert_eq!(u32::from_le_bytes(payload[..4].try_into().unwrap()), 1);
        fallback_offer_sent.send(()).unwrap();
        fallback_state_release.await.unwrap();
    });

    let context = background_test_context(Arc::clone(&state), Duration::from_secs(7));
    context
        .shared_catalog
        .write()
        .await
        .push(background_offer_file());
    let (_, inbox) = new_ed2k_server_search_channel(1);
    let server = background_test_server(endpoint);
    let inbox = Arc::new(Mutex::new(inbox));
    let session = run_test_server_session(&server, &context, &inbox);
    let observe_fallback_state = async {
        fallback_offer_observed.await.unwrap();
        let snapshot = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let snapshot = state.read().await.clone();
                if snapshot.offer_files_published_entries == 1 {
                    break snapshot;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fallback publication diagnostics should become visible");
        assert_eq!(snapshot.offer_files_mode.as_deref(), Some("legacy"));
        assert_eq!(snapshot.offer_files_batch_max, Some(200));
        assert_eq!(snapshot.offer_files_pending_entries, 0);
        assert_eq!(
            snapshot.offer_files_fallback_reason.as_deref(),
            Some("OP_SERVERIDENT capability timeout")
        );
        fallback_state_asserted.send(()).unwrap();
    };

    let (session_result, server_result, ()) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(session, server_task, observe_fallback_state)
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
    assert_eq!(
        context
            .last_client_id
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "a zero ID on a fresh runtime must leave successful-ID history empty"
    );
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
            None,
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
    assert_eq!(
        search_result.unwrap(),
        Ed2kBackgroundKeywordSearchOutcome::Replied(Vec::new())
    );
    server_task.abort();
}

#[tokio::test]
async fn silent_server_returns_timed_out_and_keeps_the_session_connected() {
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
            "silent server",
            Default::default(),
            Duration::from_millis(50),
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert!(state.read().await.connected);
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        result
    };
    let (session_result, search_result) =
        tokio::join!(run_test_server_session(&server, &context, &inbox), search);

    assert_eq!(
        session_result.unwrap(),
        ServerSessionExit::IntentionalShutdown
    );
    assert_eq!(search_result, Ed2kBackgroundKeywordSearchOutcome::TimedOut);
    server_task.abort();
}

#[tokio::test]
async fn connected_udp_status_is_due_during_regular_command_traffic() {
    assert_connected_udp_status_with_keepalive(None).await;
}

#[tokio::test]
async fn long_tcp_keepalive_timeout_does_not_delay_the_first_udp_status_request() {
    assert_connected_udp_status_with_keepalive(Some(Duration::from_secs(600))).await;
}

async fn assert_connected_udp_status_with_keepalive(keepalive: Option<Duration>) {
    let bind_ip = crate::test_bind_ip();
    let mut sockets = None;
    let mut occupied_tcp_candidates = Vec::new();
    // Let the OS choose an available TCP base port first. Independently
    // allocated ephemeral UDP ports can map to a reserved TCP range.
    for _ in 0..32 {
        let listener = TcpListener::bind((bind_ip, 0)).await.unwrap();
        if let Some(udp_port) = listener.local_addr().unwrap().port().checked_add(4)
            && let Ok(udp) = tokio::net::UdpSocket::bind((bind_ip, udp_port)).await
        {
            sockets = Some((listener, udp));
            break;
        }
        occupied_tcp_candidates.push(listener);
    }
    let (listener, status_socket) = sockets.expect("could not allocate paired server ports");
    drop(occupied_tcp_candidates);
    let server = background_test_server(listener.local_addr().unwrap());
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut context = background_test_context(Arc::clone(&state), Duration::from_secs(5));
    context.session.offer_files_capability_enabled = false;
    context.session.keepalive_interval = keepalive;
    let cancel = context.session_cancel.clone();
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let task = tokio::spawn(async move {
        run_test_server_session(&server, &context, &Arc::new(Mutex::new(inbox))).await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    read_login_request(&mut peer).await;
    let client_id = u32::from_le_bytes([192, 0, 2, 7]);
    peer.write_all(&encode_packet(OP_IDCHANGE, &client_id.to_le_bytes(), false).unwrap())
        .await
        .unwrap();

    let refresh = || {
        super::super::publish_shared_catalog_via_background_session(
            &handle,
            Duration::from_secs(5),
            &cancel,
        )
    };
    refresh().await.unwrap();
    assert!(state.read().await.connected);
    tokio::time::pause();

    // Stock checks its never-pinged server on the first eligible status tick.
    // Allow the Rust status wake interval plus one command interval, even
    // though each acknowledged refresh interrupts the session's idle wait.
    for _ in 0..4 {
        tokio::time::advance(Duration::from_secs(20)).await;
        refresh().await.unwrap();
    }
    let mut packet = [0; 32];
    let received = tokio::time::timeout(Duration::from_secs(1), status_socket.recv(&mut packet))
        .await
        .expect("connected server did not receive its first UDP status request during commands")
        .unwrap();
    assert_eq!(received, 6);
    assert_eq!(
        packet[..2],
        [OP_EDONKEYPROT, super::super::OP_GLOBSERVSTATREQ]
    );

    tokio::time::advance(Duration::from_secs(80)).await;
    refresh().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), status_socket.recv(&mut packet))
            .await
            .is_err(),
        "ordinary commands must not retrigger status before the reask interval"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut packet))
            .await
            .is_err(),
        "TCP keepalive must remain quiet before its deadline"
    );
    cancel.cancel();
    assert_eq!(
        task.await.unwrap().unwrap(),
        ServerSessionExit::ContinueOrder
    );
}

#[tokio::test]
async fn tcp_keepalive_deadline_follows_the_last_received_packet_during_commands() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let server = background_test_server(listener.local_addr().unwrap());
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut context = background_test_context(Arc::clone(&state), Duration::from_secs(5));
    context.session.offer_files_capability_enabled = false;
    context.session.keepalive_interval = Some(Duration::from_secs(60));
    let cancel = context.session_cancel.clone();
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let task = tokio::spawn(async move {
        run_test_server_session(&server, &context, &Arc::new(Mutex::new(inbox))).await
    });
    let (mut peer, _) = listener.accept().await.unwrap();
    read_login_request(&mut peer).await;
    peer.write_all(&encode_packet(OP_IDCHANGE, &0x070200c0u32.to_le_bytes(), false).unwrap())
        .await
        .unwrap();
    let refresh = || {
        super::super::publish_shared_catalog_via_background_session(
            &handle,
            Duration::from_secs(5),
            &cancel,
        )
    };
    refresh().await.unwrap();
    assert!(state.read().await.connected);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(40)).await;

    let mut server_status = 42u32.to_le_bytes().to_vec();
    server_status.extend_from_slice(&1u32.to_le_bytes());
    peer.write_all(&encode_packet(OP_SERVERSTATUS, &server_status, false).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.read().await.server_users == Some(42) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let received_at = tokio::time::Instant::now();

    for _ in 0..2 {
        tokio::time::advance(Duration::from_secs(15)).await;
        refresh().await.unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .is_err(),
        "the inbound server packet must reset the TCP idle deadline"
    );
    tokio::time::advance(
        (received_at + Duration::from_secs(61))
            .saturating_duration_since(tokio::time::Instant::now()),
    )
    .await;
    refresh().await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(2), read_client_frame(&mut peer))
        .await
        .expect("TCP keepalive was starved by the commands");
    assert_eq!(frame, (OP_OFFERFILES, 0u32.to_le_bytes().to_vec()));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .is_err()
    );
    cancel.cancel();
    assert_eq!(
        task.await.unwrap().unwrap(),
        ServerSessionExit::ContinueOrder
    );
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

fn empty_search_result_page(more_results_available: bool) -> Vec<u8> {
    let mut payload = 0u32.to_le_bytes().to_vec();
    payload.push(u8::from(more_results_available));
    payload
}

#[tokio::test]
async fn uncorrelated_search_result_cannot_advance_server_paging() {
    let (mut session, mut peer) = connected_background_test_session().await;
    let context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));
    session.phase = ServerSessionPhase::TimedOut;

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SEARCHRESULT,
            payload: empty_search_result_page(true),
        },
        &context,
        false,
    )
    .await
    .unwrap();

    assert_eq!(session.probe_search_state, ProbeSearchState::NotStarted);
    assert_eq!(session.phase, ServerSessionPhase::TimedOut);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_client_frame(&mut peer))
            .await
            .is_err(),
        "a late or unsolicited result must not emit OP_QUERY_MORE_RESULT"
    );
}

#[tokio::test]
async fn active_probe_pages_until_final_result_then_rejects_late_pages() {
    let (mut session, mut peer) = connected_background_test_session().await;
    let mut context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));
    context.session.probe_search_term = Some("probe ownership".to_string());
    session.login_accepted = true;

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SERVERLIST,
            payload: Vec::new(),
        },
        &context,
        true,
    )
    .await
    .unwrap();
    let (opcode, _payload) = read_client_frame(&mut peer).await;
    assert_eq!(opcode, OP_SEARCHREQUEST);
    assert_eq!(
        session.probe_search_state,
        ProbeSearchState::Active { received_pages: 0 }
    );
    assert_eq!(session.phase, ServerSessionPhase::SearchActive);

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SEARCHRESULT,
            payload: empty_search_result_page(true),
        },
        &context,
        true,
    )
    .await
    .unwrap();
    let (opcode, payload) = read_client_frame(&mut peer).await;
    assert_eq!(opcode, OP_QUERY_MORE_RESULT);
    assert!(payload.is_empty());
    assert_eq!(
        session.probe_search_state,
        ProbeSearchState::Active { received_pages: 1 }
    );
    assert_eq!(session.phase, ServerSessionPhase::AwaitingMore);

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SEARCHRESULT,
            payload: empty_search_result_page(false),
        },
        &context,
        true,
    )
    .await
    .unwrap();
    assert_eq!(session.probe_search_state, ProbeSearchState::Completed);
    assert_eq!(session.phase, ServerSessionPhase::Completed);

    handle_test_server_packet(
        &mut session,
        Ed2kPacket {
            opcode: OP_SEARCHRESULT,
            payload: empty_search_result_page(true),
        },
        &context,
        true,
    )
    .await
    .unwrap();
    assert_eq!(session.probe_search_state, ProbeSearchState::Completed);
    assert_eq!(session.phase, ServerSessionPhase::Completed);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_client_frame(&mut peer))
            .await
            .is_err(),
        "a late page must not restart a completed probe"
    );
}

#[tokio::test]
async fn probe_keyword_search_sends_only_five_more_requests() {
    let (mut session, mut peer) = connected_background_test_session().await;
    let context = background_test_context(Arc::clone(&session.state), Duration::from_secs(1));
    session.probe_search_state = ProbeSearchState::Active { received_pages: 0 };
    for page in 1..=6 {
        handle_test_server_packet(
            &mut session,
            Ed2kPacket {
                opcode: OP_SEARCHRESULT,
                payload: empty_search_result_page(true),
            },
            &context,
            true,
        )
        .await
        .unwrap();
        if page < 6 {
            assert_eq!(
                read_client_frame(&mut peer).await,
                (OP_QUERY_MORE_RESULT, Vec::new())
            );
        }
    }
    assert_eq!(session.probe_search_state, ProbeSearchState::Completed);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), peer.read_u8())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connected_keyword_search_keeps_six_pages_and_requests_more_only_five_times() {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_login_request(&mut stream).await;
        stream
            .write_all(&encode_packet(OP_IDCHANGE, &0x40302010u32.to_le_bytes(), false).unwrap())
            .await
            .unwrap();
        loop {
            let (opcode, _) = read_client_frame(&mut stream).await;
            if opcode == OP_SEARCHREQUEST {
                break;
            }
        }
        for page in 1..=6 {
            stream
                .write_all(&encode_packet(OP_SEARCHRESULT, &[1], false).unwrap())
                .await
                .unwrap();
            let reply = encode_packet(
                OP_SEARCHRESULT,
                &search_result_page_fixture(page, true),
                false,
            )
            .unwrap();
            stream.write_all(&reply).await.unwrap();
            if page < 6 {
                assert_eq!(
                    read_client_frame(&mut stream).await,
                    (OP_QUERY_MORE_RESULT, Vec::new())
                );
            }
        }
        assert!(
            !matches!(
                tokio::time::timeout(Duration::from_millis(100), stream.read_u8()).await,
                Ok(Ok(_))
            ),
            "search sent a sixth More request"
        );
    });
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let timeout = Duration::from_secs(3);
    let context = background_test_context(Arc::clone(&state), timeout);
    let (handle, inbox) = new_ed2k_server_search_channel(1);
    let inbox = Arc::new(Mutex::new(inbox));
    let server = background_test_server(endpoint);
    let search = async {
        tokio::time::timeout(timeout, async {
            while !state.read().await.connected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let result = search_keyword_via_background_session(
            &handle,
            "six pages",
            Default::default(),
            timeout,
            &CancellationToken::new(),
            None,
        )
        .await;
        context
            .shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        result
    };
    let (_, result) = tokio::join!(run_test_server_session(&server, &context, &inbox), search);
    let Ed2kBackgroundKeywordSearchOutcome::Replied(rows) = result.unwrap() else {
        panic!("expected accumulated result pages");
    };
    assert_eq!(
        rows.into_iter()
            .map(|row| row.file_hash.0[0])
            .collect::<Vec<_>>(),
        [1, 2, 3, 4, 5, 6]
    );
    tokio::time::timeout(timeout, server_task)
        .await
        .unwrap()
        .unwrap();
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

        let (result_sink, mut observations) = tokio::sync::mpsc::channel(1);
        let keyword_results = search_keyword_via_background_session(
            &handle,
            "malformed result",
            Default::default(),
            Duration::from_secs(1),
            &cancel,
            Some(result_sink),
        )
        .await
        .expect("valid final page must complete the original keyword request");
        let Ed2kBackgroundKeywordSearchOutcome::Replied(keyword_results) = keyword_results else {
            panic!("valid final page must be a server reply");
        };
        assert_eq!(keyword_results.len(), 1);
        assert_eq!(keyword_results[0].file_hash, result_hash);
        let observed = observations.try_recv().unwrap();
        assert_eq!(observed.server_endpoint, endpoint);
        assert_eq!(observed.file.file_hash, result_hash);
        assert!(observations.try_recv().is_err());

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
    let large_hash = Ed2kHash([0x74; 16]);
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
                let hash = Ed2kHash(payload[..16].try_into().unwrap());
                assert_ne!(hash, large_hash);
                requested.insert(hash);
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

        let mut capability_skipped = Vec::new();
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
                Ed2kServerSourceBatchTarget {
                    file_hash: large_hash,
                    file_size: crate::ed2k_transfer::ED2K_LEGACY_FILE_SIZE_MAX + 1,
                },
            ],
            Duration::from_secs(1),
            &cancel,
            &mut capability_skipped,
        )
        .await
        .expect("valid replies must complete the original batch");
        assert_eq!(capability_skipped, [large_hash]);
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
    let result_a = results.get(&file_hash_a).unwrap();
    let result_b = results.get(&file_hash_b).unwrap();
    assert!(result_a.sources.is_empty());
    assert!(result_b.sources.is_empty());
    assert_eq!(result_a.trace_id, result_b.trace_id);
    assert_eq!(result_a.server_endpoint, result_b.server_endpoint);
    server_task.abort();
}
