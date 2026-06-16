use super::*;

#[tokio::test]
async fn small_file_download_accepts_split_compressed_part_frames() {
    let root = unique_test_dir("ed2k-small-file-split-compressedpart");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 8 * 1024];
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
    let peer_public_key = test_peer_secure_ident();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        complete_plain_secure_ident_exchange(&mut stream, peer_addr, &peer_public_key).await;
        answer_startup_metadata(
            &mut stream,
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        )
        .await;
        let (requested_hash, ranges) =
            accept_upload_and_read_parts_request(&mut stream, false).await;
        assert_eq!(requested_hash, file_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&payload_for_server).unwrap();
        let compressed = encoder.finish().unwrap();
        let split_at = (compressed.len() / 2).max(1);

        let first_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[..split_at],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[split_at..],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();
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
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}

#[tokio::test]
async fn small_file_download_accepts_obfuscated_packed_startup_and_compressed_part_frames() {
    let root = unique_test_dir("ed2k-small-file-obfuscated-packed-compressedpart");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 8 * 1024];
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
    let peer_user_hash = [0x42; 16];
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

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        transport.write_all(&peer_challenge).await.unwrap();

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
            payload_for_server.len() as u64,
            false,
        );

        let filename_answer = encode_startup_multipacket_ext2_answer(
            &file_hash,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        );
        transport.write_all(&filename_answer).await.unwrap();

        let start_upload = transport.read_packet().await.unwrap().unwrap();
        assert_eq!(start_upload.protocol, OP_EDONKEYPROT);
        assert_eq!(start_upload.opcode, super::OP_STARTUPLOADREQ);
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

        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&payload_for_server).unwrap();
        let compressed = encoder.finish().unwrap();
        let split_at = (compressed.len() / 2).max(1);

        let first_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[..split_at],
            false,
        )
        .unwrap();
        transport.write_all(&first_fragment).await.unwrap();

        let second_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            0,
            compressed.len(),
            &compressed[split_at..],
            false,
        )
        .unwrap();
        transport.write_all(&second_fragment).await.unwrap();
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
        "captured.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    server.await.unwrap();
}
