use super::*;

#[tokio::test]
async fn hash_only_small_file_download_learns_metadata_from_startup_answer() {
    let root = unique_test_dir("ed2k-hash-only-small-file-download");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x41; 180 * 1024];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let placeholder_name = format!("ed2k-{file_hash_hex}.bin");

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = test_peer_secure_ident();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        start_plain_download_session(&mut stream, peer_addr, &peer_public_key).await;
        answer_startup_metadata_with_expected_size(
            &mut stream,
            &file_hash,
            0,
            payload_for_server.len() as u64,
            "captured.epub",
            false,
        )
        .await;
        let source_exchange_answer = encode_answer_sources2(
            &file_hash,
            ED2K_SOURCE_EXCHANGE2_VERSION,
            &[SourceExchangePeer {
                ip: [127, 0, 0, 2],
                tcp_port: 4662,
                server_ip: 0,
                server_port: 0,
                user_hash: Some([0x77; 16]),
                connect_options: 0,
            }],
        )
        .unwrap();
        stream.write_all(&source_exchange_answer).await.unwrap();
        let (requested_hash, ranges) =
            accept_upload_and_read_parts_request(&mut stream, false).await;
        assert_eq!(requested_hash, file_hash);
        let (start, end) = ranges[0];

        let packet = encode_sending_part(
            &file_hash,
            start,
            end,
            &payload_for_server[usize::try_from(start).unwrap()..usize::try_from(end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&packet).await.unwrap();
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
        placeholder_name,
        0,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    assert_eq!(manifest.canonical_name, "captured.epub");
    assert_eq!(manifest.file_size, payload.len() as u64);
    assert!(manifest.sources.contains(&Ed2kSourceHint {
        ip: "127.0.0.2".to_string(),
        tcp_port: 4662,
        user_hash: Some(hex::encode([0x77; 16])),
    }));
    // FIX 3: the download path attributes credit only to a cryptographically
    // verified peer (eMule CClientCredits::AddDownloaded gates IS_IDFAILED/
    // IDNEEDED when crypto is available). This test peer never completes a secure
    // -ident handshake, so no download credit is attributed to its user hash.
    assert_eq!(
        transfer_runtime
            .peer_credit_by_hash([0x42; 16])
            .unwrap()
            .map(|credit| credit.downloaded_bytes),
        None
    );
    assert!(transfer_runtime.download_speed_bytes_per_sec(&file_hash_hex) > 0);
    server.await.unwrap();
}

#[tokio::test]
async fn nofile_answer_for_requested_file_is_file_not_found_not_error() {
    let root = unique_test_dir("ed2k-download-nofile-answer");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x6A; 16]);

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let peer_public_key = test_peer_secure_ident();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        start_plain_download_session(&mut stream, peer_addr, &peer_public_key).await;
        stream
            .write_all(&encode_packet(OP_EDONKEYPROT, OP_CHANGE_SLOT, &[]))
            .await
            .unwrap();
        stream
            .write_all(&encode_packet(OP_EDONKEYPROT, OP_END_OF_DOWNLOAD, &[]))
            .await
            .unwrap();
        stream
            .write_all(&encode_file_req_ans_nofil(&file_hash))
            .await
            .unwrap();
        // Hold the socket open until the downloader has processed the FNF answer
        // and closed its side: dropping immediately can RST away the still
        // buffered packets (the downloader keeps writing startup requests this
        // scripted peer never reads).
        let mut sink = [0u8; 256];
        while !matches!(stream.read(&mut sink).await, Ok(0) | Err(_)) {}
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
            user_hash: [0x12; 16],
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
        "missing.bin".to_string(),
        ED2K_PART_SIZE,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    // OP_FILEREQANSNOFIL is a distinct outcome (oracle ListenSocket.cpp:645-661):
    // the driver dead-lists the (source, file) pair for 45 minutes and drops it.
    assert_eq!(result, Ed2kPeerDownloadOutcome::FileNotFound);
    server.await.unwrap();
}

#[tokio::test]
async fn legacy_peer_without_aich_support_does_not_receive_aich_hash_request() {
    let root = unique_test_dir("ed2k-download-legacy-peer-no-aich");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x6B; 16]);
    let file_size = ED2K_PART_SIZE * 2;

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);
        stream
            .write_all(&legacy_hello_answer_without_aich(peer_addr))
            .await
            .unwrap();

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

        let startup_request = read_packet(&mut stream).await;
        assert_legacy_multipacket_omits_aich_request(&startup_request, &file_hash, file_size);
        stream
            .write_all(&encode_file_req_ans_nofil(&file_hash))
            .await
            .unwrap();
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
            user_hash: [0x13; 16],
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
        "legacy-no-aich.bin".to_string(),
        file_size,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::FileNotFound);
    server.await.unwrap();
}

fn legacy_hello_answer_without_aich(peer_addr: SocketAddr) -> Vec<u8> {
    let mut packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x42; 16],
        client_id: 0x5912_0559,
        tcp_port: peer_addr.port(),
        udp_port: 0,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });
    replace_short_u32_tag(
        &mut packet,
        CT_EMULE_MISCOPTIONS1,
        emule_misc_options1() & !(0x07 << 29),
    );
    replace_short_u32_tag(
        &mut packet,
        CT_EMULE_MISCOPTIONS2,
        emule_misc_options2(emule_connect_options(false), false) & !(1 << 13),
    );
    packet
}

fn replace_short_u32_tag(packet: &mut [u8], tag_name: u8, value: u32) {
    let header = [TAGTYPE_UINT32, 0x01, 0x00, tag_name];
    let offset = packet
        .windows(header.len())
        .position(|window| window == header)
        .expect("short uint32 hello tag is present")
        + header.len();
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn assert_legacy_multipacket_omits_aich_request(
    packet: &[u8],
    file_hash: &Ed2kHash,
    file_size: u64,
) {
    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_MULTIPACKET_EXT);
    let mut remaining = &packet[6..];
    assert_eq!(&remaining[..16], &file_hash.0);
    remaining = &remaining[16..];
    assert_eq!(
        u64::from_le_bytes(remaining[..8].try_into().unwrap()),
        file_size
    );
    remaining = &remaining[8..];

    let mut saw_request_filename = false;
    let mut saw_set_req_file_id = false;
    let mut saw_request_sources2 = false;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            OP_REQUESTFILENAME => {
                remaining = skip_request_filename_ext_info(remaining, file_size).unwrap();
                saw_request_filename = true;
            }
            OP_SETREQFILEID => {
                saw_set_req_file_id = true;
            }
            OP_REQUESTSOURCES2 => {
                assert_eq!(&remaining[..3], &encode_request_sources2_subpayload());
                remaining = &remaining[3..];
                saw_request_sources2 = true;
            }
            OP_AICHFILEHASHREQ => panic!("AICH hash request sent to non-AICH peer"),
            unexpected => panic!("unexpected legacy startup sub-op 0x{unexpected:02X}"),
        }
    }
    assert!(saw_request_filename);
    assert!(saw_set_req_file_id);
    assert!(saw_request_sources2);
}
