use super::*;

#[tokio::test]
async fn listener_upload_startup_tolerates_source_exchange_and_aich_probe() {
    let payload = b"ubuntu linux upload startup handshake".repeat(512);
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    let no_sources_payload = b"ubuntu linux no source exchange peers".repeat(512);
    let no_sources_hash = Ed2kHash::from_bytes(Md4::digest(&no_sources_payload).into());
    let no_sources_hash_hex = no_sources_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-startup");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "startup.txt".to_string(), payload.len() as u64);
    transfer_runtime.ensure_job(&job).await.unwrap();
    let no_sources_job = new_transfer_job(
        no_sources_hash,
        "no-sources.txt".to_string(),
        no_sources_payload.len() as u64,
    );
    transfer_runtime.ensure_job(&no_sources_job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    let aich_root = [0x7B; 20];
    transfer_runtime
        .reconcile_aich_root(&file_hash_hex, Some(aich_root))
        .await
        .unwrap();
    transfer_runtime
        .store_md4_hashset(&no_sources_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
        .await
        .unwrap();
    transfer_runtime
        .remember_source(
            &file_hash_hex,
            Ed2kSourceHint {
                ip: "10.20.30.40".to_string(),
                tcp_port: 4662,
                user_hash: Some(hex::encode([0x61; 16])),
            },
        )
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = test_dht().await;
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = listener_secure_ident();
    let hello_identity = Ed2kHelloIdentity {
        user_hash: [0x31; 16],
        client_id: 0x1357_2468,
        tcp_port: 41011,
        udp_port: 41010,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };

    let server = spawn_single_listener_connection(
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        Arc::clone(&transfer_runtime),
        hello_identity,
    );

    let peer_identity = Ed2kHelloIdentity {
        user_hash: [0x41; 16],
        client_id: 0x2468_1357,
        tcp_port: 4662,
        udp_port: 4672,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    };
    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_identity).await;

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    stream
        .write_all(&super::encode_request_filename(&file_hash, &manifest))
        .await
        .unwrap();
    let filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&filename_answer[6..22], &file_hash.0);

    stream
        .write_all(&super::encode_request_sources2(&file_hash))
        .await
        .unwrap();
    let source_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_ANSWERSOURCES2).await;
    assert_eq!(source_answer[6], super::ED2K_SOURCE_EXCHANGE2_VERSION);
    assert_eq!(&source_answer[7..23], &file_hash.0);
    assert_eq!(
        u16::from_le_bytes([source_answer[23], source_answer[24]]),
        1
    );
    assert_eq!(&source_answer[25..29], &[40, 30, 20, 10]);
    assert_eq!(
        u16::from_le_bytes([source_answer[29], source_answer[30]]),
        4662
    );
    assert_eq!(&source_answer[37..53], &[0x61; 16]);
    assert_eq!(source_answer[53], 0);

    let mut older_source_request = super::encode_request_sources2(&file_hash);
    older_source_request[6] = 2;
    stream.write_all(&older_source_request).await.unwrap();
    let older_source_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_ANSWERSOURCES2).await;
    assert_eq!(older_source_answer[6], 2);
    assert_eq!(&older_source_answer[7..23], &file_hash.0);
    assert_eq!(
        u16::from_le_bytes([older_source_answer[23], older_source_answer[24]]),
        1
    );
    assert_eq!(&older_source_answer[25..29], &[10, 20, 30, 40]);

    let mut invalid_source_request = super::encode_request_sources2(&file_hash);
    invalid_source_request[6] = 0;
    stream.write_all(&invalid_source_request).await.unwrap();

    let no_sources_manifest = transfer_runtime
        .manifest(&no_sources_hash_hex)
        .await
        .unwrap();
    stream
        .write_all(&super::encode_request_sources2(&no_sources_hash))
        .await
        .unwrap();
    let no_sources_hashset_request = super::encode_hashset_request2(
        &super::Ed2kFileIdentifier::from_manifest(&no_sources_manifest).unwrap(),
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: false,
        },
    )
    .unwrap();
    stream.write_all(&no_sources_hashset_request).await.unwrap();
    let no_sources_hashset_answer = read_packet(&mut stream).await;
    assert_eq!(no_sources_hashset_answer[0], OP_EMULEPROT);
    assert_eq!(no_sources_hashset_answer[5], super::OP_HASHSETANSWER2);
    let returned = super::decode_hashset_answer2(&no_sources_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, no_sources_hash);

    let modern_hashset_request = super::encode_hashset_request2(
        &super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap(),
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: false,
        },
    )
    .unwrap();
    stream.write_all(&modern_hashset_request).await.unwrap();
    let modern_hashset_answer = read_packet(&mut stream).await;
    assert_eq!(modern_hashset_answer[0], OP_EMULEPROT);
    assert_eq!(modern_hashset_answer[5], super::OP_HASHSETANSWER2);
    let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, file_hash);
    assert_eq!(
        returned.file_identifier.file_size,
        Some(payload.len() as u64)
    );
    assert!(returned.md4_hashset.is_none());
    assert!(returned.aich_hashset.is_none());

    let request_filename = super::encode_request_filename(&file_hash, &manifest);
    let mut legacy_multipacket_payload = Vec::new();
    legacy_multipacket_payload.extend_from_slice(&file_hash.0);
    legacy_multipacket_payload.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    legacy_multipacket_payload.push(super::OP_REQUESTFILENAME);
    legacy_multipacket_payload.extend_from_slice(&request_filename[22..]);
    legacy_multipacket_payload.push(super::OP_SETREQFILEID);
    legacy_multipacket_payload.push(super::OP_AICHFILEHASHREQ);
    let legacy_multipacket = super::encode_packet(
        OP_EMULEPROT,
        super::OP_MULTIPACKET_EXT,
        &legacy_multipacket_payload,
    );
    stream.write_all(&legacy_multipacket).await.unwrap();
    let legacy_answer = read_packet(&mut stream).await;
    assert_eq!(legacy_answer[0], OP_EMULEPROT);
    assert_eq!(legacy_answer[5], super::OP_MULTIPACKETANSWER);
    assert_eq!(&legacy_answer[6..22], &file_hash.0);
    let mut legacy_remaining = &legacy_answer[22..];
    assert_eq!(legacy_remaining[0], super::OP_REQFILENAMEANSWER);
    let name_len = usize::from(u16::from_le_bytes([
        legacy_remaining[1],
        legacy_remaining[2],
    ]));
    assert_eq!(&legacy_remaining[3..3 + name_len], b"startup.txt");
    legacy_remaining = &legacy_remaining[3 + name_len..];
    assert_eq!(legacy_remaining[0], super::OP_FILESTATUS);
    assert_eq!(&legacy_remaining[1..3], &0u16.to_le_bytes());
    legacy_remaining = &legacy_remaining[3..];
    assert!(
        legacy_remaining.is_empty(),
        "file-identifier peers do not receive deprecated multipacket AICH roots"
    );

    stream
        .write_all(&super::encode_aich_file_hash_request(&file_hash))
        .await
        .unwrap();
    let aich_answer = read_packet(&mut stream).await;
    assert_eq!(aich_answer[0], OP_EMULEPROT);
    assert_eq!(aich_answer[5], super::OP_AICHFILEHASHANS);
    let (returned_hash, returned_aich_root) =
        super::decode_aich_file_hash_answer(&aich_answer[6..]).unwrap();
    assert_eq!(returned_hash, file_hash);
    assert_eq!(returned_aich_root, aich_root);

    let mut aich_recovery_request = Vec::new();
    aich_recovery_request.extend_from_slice(&file_hash.0);
    aich_recovery_request.extend_from_slice(&0u16.to_le_bytes());
    aich_recovery_request.extend_from_slice(&aich_root);
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_AICHREQUEST,
            &aich_recovery_request,
        ))
        .await
        .unwrap();
    let aich_recovery_failure = read_packet(&mut stream).await;
    assert_eq!(aich_recovery_failure[0], OP_EMULEPROT);
    assert_eq!(aich_recovery_failure[5], super::OP_AICHANSWER);
    let aich_recovery_answer =
        super::decode_aich_recovery_answer_payload(&aich_recovery_failure[6..]).unwrap();
    assert_eq!(aich_recovery_answer.file_hash, file_hash);
    assert_eq!(aich_recovery_answer.part, None);

    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_PUBLICIP_REQ, &[]))
        .await
        .unwrap();
    let public_ip_answer = read_packet(&mut stream).await;
    assert_eq!(public_ip_answer[0], OP_EMULEPROT);
    assert_eq!(public_ip_answer[5], OP_PUBLICIP_ANSWER);
    assert_eq!(
        super::decode_public_ip_answer_payload(&public_ip_answer[6..]).unwrap(),
        test_bind_ip()
    );

    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_PORTTEST, &[]))
        .await
        .unwrap();
    let port_test_answer = read_packet(&mut stream).await;
    assert_eq!(port_test_answer[0], OP_EDONKEYPROT);
    assert_eq!(port_test_answer[5], OP_PORTTEST);
    assert_eq!(&port_test_answer[6..], &[0x12]);

    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_KAD_FWTCPCHECK_ACK,
            &[],
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_BUDDYPING, &[]))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_BUDDYPONG, &[]))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(OP_EDONKEYPROT, OP_OUTOFPARTREQS, &[]))
        .await
        .unwrap();
    let mut client_id_change_payload = Vec::new();
    client_id_change_payload.extend_from_slice(&0x1122_3344u32.to_le_bytes());
    client_id_change_payload.extend_from_slice(&0x5566_7788u32.to_le_bytes());
    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_CHANGE_CLIENT_ID,
            &client_id_change_payload,
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_REQUESTPREVIEW,
            &file_hash.0,
        ))
        .await
        .unwrap();
    let mut preview_answer_payload = file_hash.0.to_vec();
    preview_answer_payload.push(1);
    preview_answer_payload.extend_from_slice(&3u32.to_le_bytes());
    preview_answer_payload.extend_from_slice(b"png");
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_PREVIEWANSWER,
            &preview_answer_payload,
        ))
        .await
        .unwrap();
    let mut kad_callback_payload = Vec::new();
    kad_callback_payload.extend_from_slice(&[0x45; 16]);
    kad_callback_payload.extend_from_slice(&file_hash.0);
    kad_callback_payload.extend_from_slice(&u32::from_be_bytes([127, 0, 0, 1]).to_le_bytes());
    kad_callback_payload.extend_from_slice(&4662u16.to_le_bytes());
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_CALLBACK,
            &kad_callback_payload,
        ))
        .await
        .unwrap();
    let mut reask_callback_payload = Vec::new();
    reask_callback_payload.extend_from_slice(&u32::from_be_bytes([127, 0, 0, 1]).to_le_bytes());
    reask_callback_payload.extend_from_slice(&4672u16.to_le_bytes());
    reask_callback_payload.extend_from_slice(&file_hash.0);
    reask_callback_payload.extend_from_slice(&1u16.to_le_bytes());
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_REASKCALLBACKTCP,
            &reask_callback_payload,
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(
            OP_EMULEPROT,
            OP_CHATCAPTCHAREQ,
            &[0, 0x42, 0x4D],
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(OP_EMULEPROT, OP_CHATCAPTCHARES, &[1]))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(OP_EDONKEYPROT, OP_CHANGE_SLOT, &[]))
        .await
        .unwrap();
    let mut message_payload = Vec::new();
    message_payload.extend_from_slice(&5u16.to_le_bytes());
    message_payload.extend_from_slice(b"hello");
    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_MESSAGE,
            &message_payload,
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_ASKSHAREDFILES,
            &[],
        ))
        .await
        .unwrap();
    let shared_files_answer = read_packet(&mut stream).await;
    assert_eq!(shared_files_answer[0], OP_EDONKEYPROT);
    assert_eq!(shared_files_answer[5], OP_ASKSHAREDFILESANSWER);
    let shared_files =
        super::decode_shared_files_answer_payload(&shared_files_answer[6..]).unwrap();
    assert_eq!(shared_files.file_count, 0);
    assert_eq!(shared_files.entry_bytes, 0);

    stream
        .write_all(&super::encode_packet(OP_EDONKEYPROT, OP_ASKSHAREDDIRS, &[]))
        .await
        .unwrap();
    let shared_dirs_denied = read_packet(&mut stream).await;
    assert_eq!(shared_dirs_denied[0], OP_EDONKEYPROT);
    assert_eq!(shared_dirs_denied[5], OP_ASKSHAREDDENIEDANS);

    let mut dir_request = Vec::new();
    dir_request.extend_from_slice(&5u16.to_le_bytes());
    dir_request.extend_from_slice(b"Music");
    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_ASKSHAREDFILESDIR,
            &dir_request,
        ))
        .await
        .unwrap();
    let shared_dir_denied = read_packet(&mut stream).await;
    assert_eq!(shared_dir_denied[0], OP_EDONKEYPROT);
    assert_eq!(shared_dir_denied[5], OP_ASKSHAREDDENIEDANS);

    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_QUEUERANK,
            &123u32.to_le_bytes(),
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_queue_ranking(7))
        .await
        .unwrap();

    stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let accept_upload =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept_upload.len(), 6);

    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_END_OF_DOWNLOAD,
            &[],
        ))
        .await
        .unwrap();
    stream
        .write_all(&super::encode_packet(
            OP_EDONKEYPROT,
            OP_END_OF_DOWNLOAD,
            &file_hash.0,
        ))
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
}
