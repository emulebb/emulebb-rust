use super::*;
use std::collections::HashMap;
use tokio::net::TcpStream;

async fn connected_background_test_session() -> (ServerSession, TcpStream) {
    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = TcpStream::connect(addr).await.unwrap();
    let (stream, peer_addr) = listener.accept().await.unwrap();
    (ServerSession::from_stream_for_test(stream, peer_addr), peer)
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
        source_count: Some(7),
        complete_source_count: Some(3),
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
        &encode_login_request(hello_identity, HELLO_NICKNAME),
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
