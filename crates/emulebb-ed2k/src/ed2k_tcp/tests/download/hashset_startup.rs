use super::*;

#[tokio::test]
async fn large_file_download_waits_for_secure_ident_before_hashset_and_upload() {
    let root = unique_test_dir("ed2k-large-file-secure-ident-order");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; (ED2K_PART_SIZE as usize) + 32_768];
    let md4_hashset = payload
        .chunks(ED2K_PART_SIZE as usize)
        .map(|chunk| Md4::digest(chunk).into())
        .collect::<Vec<[u8; 16]>>();
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(
        Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
    );
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let source_root = unique_test_dir("ed2k-large-file-secure-ident-order-source");
    let source_runtime = Ed2kTransferRuntime::load_or_create(&source_root).unwrap();
    source_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    source_runtime
        .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 0, &payload[..ED2K_PART_SIZE as usize])
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 1, &payload[ED2K_PART_SIZE as usize..])
        .await
        .unwrap();
    let source_aich = source_runtime
        .aich_hashset(&file_hash)
        .await
        .unwrap()
        .expect("missing source AICH hashset");
    let source_identifier = super::Ed2kFileIdentifier {
        file_hash,
        file_size: Some(payload.len() as u64),
        aich_root: Some(source_aich.master_hash),
    };

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key_for_server = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let payload_for_server = payload.clone();
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
            true,
        );

        let startup_answer = encode_startup_multipacket_ext2_answer_with_identifier(
            &source_identifier,
            "captured-fallback.iso",
            true,
        );
        stream.write_all(&startup_answer).await.unwrap();

        let hashset_request = read_packet(&mut stream).await;
        assert_eq!(hashset_request[0], OP_EMULEPROT);
        assert_eq!(hashset_request[5], super::OP_HASHSETREQUEST2);
        let (requested_identifier, request_options) =
            super::decode_hashset_request2(&hashset_request[6..]).unwrap();
        assert_eq!(requested_identifier.file_hash, file_hash);
        assert_eq!(
            requested_identifier.file_size,
            Some(payload_for_server.len() as u64)
        );
        assert!(request_options.request_md4);
        assert!(request_options.request_aich);

        let hashset_answer = super::encode_hashset_answer2(
            &source_identifier,
            Some(&md4_hashset),
            Some(&source_aich),
        )
        .unwrap();
        stream.write_all(&hashset_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        assert_eq!(&start_upload[6..22], &file_hash.0);

        let accept = encode_accept_upload_req();
        stream.write_all(&accept).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        let request_uses_i64 = request_parts[5] == super::OP_REQUESTPARTS_I64;
        if request_uses_i64 {
            assert_eq!(request_parts[0], OP_EMULEPROT);
        } else {
            assert_eq!(request_parts[0], OP_EDONKEYPROT);
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        }
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], request_uses_i64).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            ranges,
            vec![(
                0,
                super::ED2K_EMBLOCK_SIZE.min(payload_for_server.len() as u64)
            )]
        );

        let mut expected_start = 0u64;
        for (start, end) in ranges {
            assert_eq!(start, expected_start);
            let start_index = usize::try_from(start).unwrap();
            let end_index = usize::try_from(end).unwrap();
            let sending_part = encode_sending_part(
                &file_hash,
                start,
                end,
                &payload_for_server[start_index..end_index],
                request_uses_i64,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
            expected_start = end;
        }
        while expected_start < payload_for_server.len() as u64 {
            let next_request_parts = read_packet(&mut stream).await;
            let next_request_uses_i64 = next_request_parts[5] == super::OP_REQUESTPARTS_I64;
            if next_request_uses_i64 {
                assert_eq!(next_request_parts[0], OP_EMULEPROT);
            } else {
                assert_eq!(next_request_parts[0], OP_EDONKEYPROT);
                assert_eq!(next_request_parts[5], super::OP_REQUESTPARTS);
            }
            let (next_requested_hash, next_ranges) =
                decode_request_parts_payload(&next_request_parts[6..], next_request_uses_i64)
                    .unwrap();
            assert_eq!(next_requested_hash, file_hash);
            assert!(!next_ranges.is_empty());
            for (start, end) in next_ranges {
                assert_eq!(start, expected_start);
                let start_index = usize::try_from(start).unwrap();
                let end_index = usize::try_from(end).unwrap();
                let sending_part = encode_sending_part(
                    &file_hash,
                    start,
                    end,
                    &payload_for_server[start_index..end_index],
                    next_request_uses_i64,
                )
                .unwrap();
                stream.write_all(&sending_part).await.unwrap();
                expected_start = end;
            }
        }
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
        "captured.iso".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(manifest.aich_hashset.len(), 2);
    server.await.unwrap();
}
