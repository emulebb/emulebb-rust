use super::*;

#[tokio::test]
async fn queue_only_peer_is_accepted_without_counting_as_failure() {
    let root = unique_test_dir("ed2k-queue-only-accepted");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 41010,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        drop(stream);
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &Ed2kFoundSource {
            file_hash,
            ip: test_bind_ip(),
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(test_bind_ip().octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "captured.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn accepted_peer_without_claimable_blocks_is_cancelled_as_no_needed_parts() {
    let root = unique_test_dir("ed2k-accepted-empty-window-cancel");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5C; 32_768];
    let payload_len = payload.len() as u64;
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "claimed.epub".to_string(),
            payload_len,
        ))
        .await
        .unwrap();
    assert!(
        transfer_runtime
            .mark_piece_requested(&file_hash_hex, 0)
            .await
            .unwrap()
    );

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 41010,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_PUBLICKEY,
                &peer_public_key.public_key_payload().unwrap(),
            ))
            .await
            .unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &peer_signature_payload(),
            ))
            .await
            .unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_len,
            false,
        );
        let filename_answer =
            encode_startup_multipacket_ext2_answer(&file_hash, payload_len, "claimed.epub", false);
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let cancel = read_packet(&mut stream).await;
        assert_eq!(cancel[0], OP_EDONKEYPROT);
        assert_eq!(cancel[5], OP_CANCELTRANSFER);
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &Ed2kFoundSource {
            file_hash,
            ip: test_bind_ip(),
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(test_bind_ip().octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "claimed.epub".to_string(),
        payload_len,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::NoNeededParts);
    server.await.unwrap();
}

#[tokio::test]
async fn queued_peer_waits_past_read_timeout_for_late_accept_upload() {
    let root = unique_test_dir("ed2k-queued-peer-late-accept");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "queued.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[5], OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 41010,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        stream.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[5], super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[5], super::OP_SIGNATURE);
        stream
            .write_all(&encode_packet(
                OP_EMULEPROT,
                super::OP_SIGNATURE,
                &peer_signature_payload(),
            ))
            .await
            .unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload.len() as u64,
            "queued.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);

        let file_desc = encode_packet(
            OP_EMULEPROT,
            super::OP_FILEDESC,
            &[0x05, 0x05, 0x00, 0x00, 0x00, b'q', b'u', b'e', b'u', b'e'],
        );
        stream.write_all(&file_desc).await.unwrap();

        let queue_ranking = super::encode_queue_ranking(1);
        stream.write_all(&queue_ranking).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1500)).await;

        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let sending_part = encode_sending_part(
            &file_hash,
            0,
            payload_for_server.len() as u64,
            &payload_for_server,
            false,
        )
        .unwrap();
        stream.write_all(&sending_part).await.unwrap();
    });

    let (reask_handle, mut reask_rx) = crate::ed2k_client_udp::reask_command_channel();
    let result = download_file_from_peer(Ed2kPeerDownloadOptions {
        bind_ip: test_bind_ip(),
        peer: &Ed2kFoundSource {
            file_hash,
            ip: test_bind_ip(),
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(test_bind_ip().octets()),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        },
        hello_identity: Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        secure_ident: &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        transfer_runtime: &transfer_runtime,
        canonical_name: "queued.epub".to_string(),
        file_size: 32_768,
        current_source_count: 0,
        timeout: Duration::from_secs(1),
        reask_register: Some(reask_handle),
    })
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    assert!(reask_rx.try_recv().is_err());
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn obfuscated_queued_peer_waits_for_late_accept_upload() {
    let root = unique_test_dir("ed2k-obfuscated-queued-peer-late-accept");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6B; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "queued-obfuscated.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_user_hash = [0x52; 16];
    let peer_public_key = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut transport = Ed2kTransport::accept(stream, peer_user_hash).await.unwrap();
        assert_eq!(transport.mode, Ed2kTransportMode::Obfuscated);

        let hello = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(hello.protocol, OP_EDONKEYPROT);
        assert_eq!(hello.opcode, OP_HELLO);

        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: peer_user_hash,
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        });
        transport.write_all(&hello_answer).await.unwrap();

        let secure_ident_probe = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(secure_ident_probe.protocol, OP_EMULEPROT);
        assert_eq!(secure_ident_probe.opcode, OP_SECIDENTSTATE);
        transport
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let public_key = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(public_key.protocol, OP_EMULEPROT);
        assert_eq!(public_key.opcode, super::OP_PUBLICKEY);
        let peer_public_key_packet = encode_packed_packet(
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        )
        .unwrap();
        transport.write_all(&peer_public_key_packet).await.unwrap();

        let signature = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(signature.protocol, OP_EMULEPROT);
        assert_eq!(signature.opcode, super::OP_SIGNATURE);
        let peer_signature =
            encode_packed_packet(super::OP_SIGNATURE, &peer_signature_payload()).unwrap();
        transport.write_all(&peer_signature).await.unwrap();

        let startup_request = transport.read_packet().await.unwrap().unwrap();
        assert_startup_multipacket_ext2(
            startup_request.protocol,
            startup_request.opcode,
            &startup_request.payload,
            &file_hash,
            payload.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload.len() as u64,
            "queued-obfuscated.epub",
            false,
        );
        transport.write_all(&filename_answer).await.unwrap();

        let start_upload = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(start_upload.protocol, OP_EDONKEYPROT);
        assert_eq!(start_upload.opcode, super::OP_STARTUPLOADREQ);

        let file_desc = encode_packet(
            OP_EMULEPROT,
            super::OP_FILEDESC,
            &[0x05, 0x05, 0x00, 0x00, 0x00, b'q', b'u', b'e', b'u', b'e'],
        );
        transport.write_all(&file_desc).await.unwrap();
        transport
            .write_all(&super::encode_queue_ranking(1))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(1500)).await;
        transport
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let request_parts = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(request_parts.protocol, OP_EDONKEYPROT);
        assert_eq!(request_parts.opcode, super::OP_REQUESTPARTS);
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts.payload, false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let sending_part = encode_sending_part(
            &file_hash,
            0,
            payload_for_server.len() as u64,
            &payload_for_server,
            false,
        )
        .unwrap();
        transport.write_all(&sending_part).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &Ed2kFoundSource {
            file_hash,
            ip: test_bind_ip(),
            tcp_port: peer_addr.port(),
            client_id: u32::from_le_bytes(test_bind_ip().octets()),
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS,),
            user_hash: Some(peer_user_hash),
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        },
        Ed2kHelloIdentity {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "queued-obfuscated.epub".to_string(),
        32_768,
        Duration::from_secs(1),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}
