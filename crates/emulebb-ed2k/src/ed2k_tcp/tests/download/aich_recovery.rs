use super::*;

/// A part that fails MD4 verification must trigger an OP_AICHREQUEST to the
/// peer (master `CPartFile::HashSinglePart` failure -> `RequestAICHRecovery`),
/// instead of silently re-downloading the whole part. The peer here delivers a
/// corrupt single part and then asserts it receives an OP_AICHREQUEST for that
/// part carrying the file's trusted AICH master hash.
#[tokio::test]
async fn corrupt_part_triggers_aich_recovery_request() {
    let root = unique_test_dir("ed2k-corrupt-part-aich-request");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // 200 KB single-part file: larger than EMBLOCKSIZE so the master recovery
    // guard (file_size > PARTSIZE * part + EMBLOCKSIZE) admits part 0.
    let payload = vec![0x5A; 200 * 1024];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "corrupt.bin".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    // Seed a trusted AICH master root so recovery can be solicited.
    let trusted_root = [0xABu8; 20];
    transfer_runtime
        .reconcile_aich_root(&file_hash_hex, Some(trusted_root))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = test_peer_secure_ident();
    let payload_len = payload.len() as u64;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        complete_plain_secure_ident_exchange(&mut stream, peer_addr, &peer_public_key).await;
        // Advertise the part as present (complete file status) so the downloader
        // both claims the part and is allowed to ask this peer for recovery.
        answer_startup_metadata(&mut stream, &file_hash, payload_len, "corrupt.bin", true).await;

        // Accept the upload then answer every requested block with corrupt bytes
        // until the whole part is delivered. The 200 KB part spans two blocks,
        // and the request window may fetch them across several frames, so loop
        // until the local MD4 re-check fails and the downloader reacts.
        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], OP_STARTUPLOADREQ);
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request = loop {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EDONKEYPROT, OP_REQUESTPARTS) => {
                    let (requested_hash, ranges) =
                        decode_request_parts_payload(&packet[6..], false).unwrap();
                    assert_eq!(requested_hash, file_hash);
                    for (start, end) in ranges {
                        let corrupt = vec![0x00u8; usize::try_from(end - start).unwrap()];
                        let frame =
                            encode_sending_part(&file_hash, start, end, &corrupt, false).unwrap();
                        stream.write_all(&frame).await.unwrap();
                    }
                }
                (OP_EMULEPROT, OP_AICHREQUEST) => {
                    break decode_aich_recovery_request_payload(&packet[6..]).unwrap();
                }
                (proto, op) => panic!("unexpected packet 0x{proto:02X}/0x{op:02X} during recovery"),
            }
        };
        assert_eq!(request.file_hash, file_hash);
        assert_eq!(request.part, 0);
        assert_eq!(request.master_hash, trusted_root);
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
            user_hash: [0x14; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        },
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
        ),
        &transfer_runtime,
        "corrupt.bin".to_string(),
        payload_len,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    // The peer closes after asserting the request, so the session ends
    // incomplete (no recovery answer was supplied).
    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);

    // The corrupt part was reset for re-download, not left verified.
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    server.await.unwrap();
}
