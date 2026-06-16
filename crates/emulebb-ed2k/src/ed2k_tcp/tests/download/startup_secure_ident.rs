use super::*;

#[tokio::test]
async fn small_file_download_waits_for_peer_signature_before_start_upload() {
    let root = unique_test_dir("ed2k-small-file-capture");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 2_409_452];
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
    let payload_for_server = payload.clone();
    let peer_public_key_for_server = Arc::clone(&peer_public_key);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);

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

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[0], OP_EMULEPROT);
        assert_eq!(public_key[5], super::OP_PUBLICKEY);

        let peer_public_key_packet = encode_packet(
            OP_EMULEPROT,
            super::OP_PUBLICKEY,
            &peer_public_key_for_server.public_key_payload().unwrap(),
        );
        stream.write_all(&peer_public_key_packet).await.unwrap();

        let signature = read_packet(&mut stream).await;
        assert_eq!(signature[0], OP_EMULEPROT);
        assert_eq!(signature[5], super::OP_SIGNATURE);

        // Oracle-shaped sessions keep file startup traffic behind the full
        // secure-ident roundtrip, so no filename/upload request should
        // arrive before the peer signature closes the exchange.
        assert!(
            tokio::time::timeout(Duration::from_millis(150), read_packet(&mut stream))
                .await
                .is_err(),
            "startup requests must wait for peer OP_SIGNATURE"
        );

        let peer_signature =
            encode_packet(OP_EMULEPROT, super::OP_SIGNATURE, &peer_signature_payload());
        stream.write_all(&peer_signature).await.unwrap();

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
        (180 * 1024) as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    server.await.unwrap();
}
