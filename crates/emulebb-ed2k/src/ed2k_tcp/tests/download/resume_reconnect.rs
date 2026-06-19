use super::*;

#[tokio::test]
async fn small_file_download_resumes_partial_piece_after_reconnect() {
    let root = unique_test_dir("ed2k-small-file-download-resume-reconnect");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let split = 8_192usize;
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let source_name = "resume-download.epub";
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            source_name.to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut first_stream, _) = listener.accept().await.unwrap();
        let _hello = read_packet(&mut first_stream).await;
        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        first_stream.write_all(&hello_answer).await.unwrap();

        let _secure_ident_probe = read_packet(&mut first_stream).await;

        let startup_request = read_packet(&mut first_stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
        );
        first_stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut first_stream).await;
        first_stream
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let first_request_parts = read_packet(&mut first_stream).await;
        assert_eq!(first_request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, payload_for_server.len() as u64)]);

        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            split as u64,
            &payload_for_server[..split],
            false,
        )
        .unwrap();
        first_stream.write_all(&first_fragment).await.unwrap();
        drop(first_stream);

        let (mut resumed_stream, _) = listener.accept().await.unwrap();
        let _hello = read_packet(&mut resumed_stream).await;
        let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
            user_hash: [0x42; 16],
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        });
        resumed_stream.write_all(&hello_answer).await.unwrap();

        let _secure_ident_probe = read_packet(&mut resumed_stream).await;

        let startup_request = read_packet(&mut resumed_stream).await;
        assert_startup_multipacket_ext2_with_source_exchange(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            false,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
        );
        resumed_stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut resumed_stream).await;
        resumed_stream
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();

        let resumed_request_parts = read_packet(&mut resumed_stream).await;
        assert_eq!(resumed_request_parts[5], super::OP_REQUESTPARTS);
        let (requested_hash, resumed_ranges) =
            decode_request_parts_payload(&resumed_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            resumed_ranges,
            vec![(split as u64, payload_for_server.len() as u64)]
        );

        let resumed_fragment = encode_sending_part(
            &file_hash,
            split as u64,
            payload_for_server.len() as u64,
            &payload_for_server[split..],
            false,
        )
        .unwrap();
        resumed_stream.write_all(&resumed_fragment).await.unwrap();
    });

    let source = Ed2kFoundSource {
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
    };
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let first_result = download_file_from_peer_test!(
        test_bind_ip(),
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(first_result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    let partial_manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!partial_manifest.completed);
    assert_eq!(
        partial_manifest.pieces[0].state,
        crate::ed2k_transfer::Ed2kTransferState::Missing
    );
    assert_eq!(partial_manifest.pieces[0].bytes_written, split as u64);

    let resumed_result = download_file_from_peer_test!(
        test_bind_ip(),
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(resumed_result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_resumes_partial_piece_after_obfuscated_reconnect() {
    let root = unique_test_dir("ed2k-obfuscated-small-file-download-resume-reconnect");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6B; 32_768];
    let split = 8_192usize;
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let source_name = "resume-obfuscated-download.epub";
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            source_name.to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_user_hash = [0x52; 16];
    let peer_public_key = test_peer_secure_ident();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (first_stream, _) = listener.accept().await.unwrap();
        let mut first_transport = Ed2kTransport::accept(first_stream, peer_user_hash)
            .await
            .unwrap();
        assert_eq!(first_transport.mode, Ed2kTransportMode::Obfuscated);
        start_obfuscated_download_session(
            &mut first_transport,
            peer_addr,
            peer_user_hash,
            &peer_public_key,
        )
        .await;
        answer_transport_startup_metadata(
            &mut first_transport,
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
        )
        .await;
        let (requested_hash, first_ranges) =
            accept_transport_upload_and_read_parts_request(&mut first_transport, false).await;
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, payload_for_server.len() as u64)]);
        first_transport
            .write_all(
                &encode_sending_part(
                    &file_hash,
                    0,
                    split as u64,
                    &payload_for_server[..split],
                    false,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        drop(first_transport);

        let (resumed_stream, _) = listener.accept().await.unwrap();
        let mut resumed_transport = Ed2kTransport::accept(resumed_stream, peer_user_hash)
            .await
            .unwrap();
        assert_eq!(resumed_transport.mode, Ed2kTransportMode::Obfuscated);
        start_obfuscated_download_session(
            &mut resumed_transport,
            peer_addr,
            peer_user_hash,
            &peer_public_key,
        )
        .await;
        answer_transport_startup_metadata_with_source_exchange(
            &mut resumed_transport,
            &file_hash,
            payload_for_server.len() as u64,
            source_name,
            false,
            false,
        )
        .await;
        let (requested_hash, resumed_ranges) =
            accept_transport_upload_and_read_parts_request(&mut resumed_transport, false).await;
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            resumed_ranges,
            vec![(split as u64, payload_for_server.len() as u64)]
        );
        resumed_transport
            .write_all(
                &encode_sending_part(
                    &file_hash,
                    split as u64,
                    payload_for_server.len() as u64,
                    &payload_for_server[split..],
                    false,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    });

    let source = Ed2kFoundSource {
        file_hash,
        ip: test_bind_ip(),
        tcp_port: peer_addr.port(),
        client_id: u32::from_le_bytes(test_bind_ip().octets()),
        low_id: false,
        obfuscated: true,
        obfuscation_options: Some(super::EMULE_CRYPT_SUPPORTS | super::EMULE_CRYPT_REQUESTS),
        user_hash: Some(peer_user_hash),
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    };
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
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

    let first_result = download_file_from_peer_test!(
        test_bind_ip(),
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(first_result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    let partial_manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!partial_manifest.completed);
    assert_eq!(
        partial_manifest.pieces[0].bytes_written,
        u64::try_from(split).unwrap()
    );

    let resumed_result = download_file_from_peer_test!(
        test_bind_ip(),
        &source,
        hello_identity,
        &secure_ident,
        &transfer_runtime,
        source_name.to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(resumed_result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}
