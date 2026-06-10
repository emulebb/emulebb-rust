use super::*;

#[tokio::test]
async fn listener_hashset_request2_returns_aich_when_available() {
    let mut payload = vec![0x5A; ED2K_PART_SIZE as usize];
    payload.extend_from_slice(&vec![0x37; 32_768]);
    let md4_hashset = payload
        .chunks(ED2K_PART_SIZE as usize)
        .map(|chunk| Md4::digest(chunk).into())
        .collect::<Vec<[u8; 16]>>();
    let file_hash = Ed2kHash::from_bytes(
        Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
    );
    let file_hash_hex = file_hash.to_string();
    let root = unique_test_dir("ed2k-upload-listener-modern-aich");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(
        file_hash,
        "listener-aich.iso".to_string(),
        payload.len() as u64,
    );
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload[..ED2K_PART_SIZE as usize])
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 1, &payload[ED2K_PART_SIZE as usize..])
        .await
        .unwrap();
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.aich_hashset_acquired);
    let requested_identifier = super::Ed2kFileIdentifier::from_manifest(&manifest).unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = DhtNode::new(DhtConfig {
        bind_addr: Some(test_bind_addr()),
        node_id: NodeId::from_bytes([0x5D; 16]),
        udp_key: 0x5566_7788,
        ..DhtConfig::default()
    })
    .await
    .unwrap();
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
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

    let server = tokio::spawn({
        let transfer_runtime = Arc::clone(&transfer_runtime);
        let server_state = Arc::clone(&server_state);
        let kad_firewall = Arc::clone(&kad_firewall);
        let secure_ident = Arc::clone(&secure_ident);
        async move {
            let (stream, remote_addr) = listener.accept().await.unwrap();
            handle_connection_test!(
                stream,
                remote_addr,
                &dht,
                &server_state,
                &kad_firewall,
                &secure_ident,
                &transfer_runtime,
                hello_identity,
            )
            .await
            .unwrap();
        }
    });

    let mut stream = TcpStream::connect(peer_addr).await.unwrap();
    stream
        .write_all(&encode_hello_request(Ed2kHelloIdentity {
            user_hash: [0x41; 16],
            client_id: 0x2468_1357,
            tcp_port: 4662,
            udp_port: 4672,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();
    let _ = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

    let modern_hashset_request = super::encode_hashset_request2(
        &requested_identifier,
        super::Ed2kHashsetRequestOptions {
            request_md4: true,
            request_aich: true,
        },
    )
    .unwrap();
    stream.write_all(&modern_hashset_request).await.unwrap();
    let modern_hashset_answer =
        read_until_opcode(&mut stream, OP_EMULEPROT, super::OP_HASHSETANSWER2).await;
    let returned = super::decode_hashset_answer2(&modern_hashset_answer[6..]).unwrap();
    assert_eq!(returned.file_identifier.file_hash, file_hash);
    assert_eq!(
        returned.file_identifier.aich_root,
        requested_identifier.aich_root
    );
    assert_eq!(returned.md4_hashset.unwrap().len(), 2);
    let returned_aich = returned
        .aich_hashset
        .expect("missing returned AICH hashset");
    assert_eq!(
        returned_aich.master_hash,
        requested_identifier.aich_root.unwrap()
    );
    assert_eq!(returned_aich.part_hashes.len(), 2);

    drop(stream);
    server.await.unwrap();
}
