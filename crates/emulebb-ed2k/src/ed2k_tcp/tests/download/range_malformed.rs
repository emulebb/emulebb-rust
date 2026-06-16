use super::*;

#[tokio::test]
async fn small_file_download_ignores_malformed_range_and_releases_pending_piece() {
    let root = unique_test_dir("ed2k-small-file-malformed-range");
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
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let _hello = read_packet(&mut stream).await;
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
        stream.write_all(&hello_answer).await.unwrap();

        let _secure_ident_probe = read_packet(&mut stream).await;
        stream
            .write_all(&encode_secident_state(
                ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED,
                0x4436_EEAC,
            ))
            .await
            .unwrap();

        let _public_key = read_packet(&mut stream).await;
        let peer_public_key = Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        );
        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let _signature = read_packet(&mut stream).await;
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
            payload_for_server.len() as u64,
            false,
        );
        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();
        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let sending_part = encode_sending_part(
            &file_hash,
            1,
            payload_for_server.len() as u64 + 1,
            &payload_for_server,
            false,
        )
        .unwrap();
        stream.write_all(&sending_part).await.unwrap();
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
    .await;

    assert_eq!(
        result.unwrap(),
        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
    );
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    assert_eq!(
        manifest.pieces[0].state,
        crate::ed2k_transfer::Ed2kTransferState::Missing
    );
    server.await.unwrap();
}
