use super::*;

#[tokio::test]
async fn background_search_channel_round_trips_results() {
    let (handle, mut inbox) = new_ed2k_server_search_channel(1);
    let cancel = CancellationToken::new();
    let expected = Ed2kSearchFile {
        file_hash: Ed2kHash([0x44; 16]),
        file_name: Some("ubuntu.iso".to_string()),
        file_size: Some(123),
        file_type: Some("Doc".to_string()),
        source_count: Some(7),
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
async fn background_udp_source_search_preserves_responding_server() {
    let server = test_udp_obfuscated_server();
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

    handle_background_udp_packet(
        &server,
        &ServerUdpPacket {
            opcode: OP_GLOBFOUNDSOURCES,
            payload,
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, server_udp_endpoint(&server).port())),
        },
        &mut pending,
        &state,
        &mut None,
    )
    .unwrap();

    let sources = receive_response.await.unwrap().unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].source_server, Some(server.base_endpoint()));
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

#[test]
fn server_status_matching_challenge_records_users_files_and_udp_flags() {
    let server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let challenge = 0x55AA_BEEF;
    let mut outstanding = Some(challenge);
    let mut pending = None;

    handle_background_udp_packet(
        &server,
        &ServerUdpPacket {
            opcode: OP_GLOBSERVSTATRES,
            payload: server_status_payload(challenge, 4242, 99000, Some(0x0000_0331)),
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, server.entry.port)),
        },
        &mut pending,
        &state,
        &mut outstanding,
    )
    .unwrap();

    let guard = state.blocking_read();
    assert_eq!(guard.server_users, Some(4242));
    assert_eq!(guard.server_files, Some(99000));
    assert_eq!(guard.server_udp_flags, Some(0x0000_0331));
    // The challenge is consumed so a replayed reply is ignored.
    assert_eq!(outstanding, None);
}

#[test]
fn server_status_mismatched_challenge_is_discarded() {
    let server = test_udp_obfuscated_server();
    let state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let mut outstanding = Some(0x55AA_0001);
    let mut pending = None;

    handle_background_udp_packet(
        &server,
        &ServerUdpPacket {
            opcode: OP_GLOBSERVSTATRES,
            // Echoes a different challenge than the one we issued.
            payload: server_status_payload(0x55AA_0002, 5, 6, None),
            from: SocketAddr::from((Ipv4Addr::LOCALHOST, server.entry.port)),
        },
        &mut pending,
        &state,
        &mut outstanding,
    )
    .unwrap();

    let guard = state.blocking_read();
    assert_eq!(guard.server_users, None);
    assert_eq!(guard.server_files, None);
    // The outstanding challenge stays armed until the right reply arrives.
    assert_eq!(outstanding, Some(0x55AA_0001));
}

#[tokio::test]
async fn server_obfuscation_handshake_encrypts_login_request() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
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
        &encode_login_request(hello_identity),
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
    let mut session = ServerSession::connect(
        Ipv4Addr::LOCALHOST,
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
