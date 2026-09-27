use super::*;

const PEER_HASH: [u8; 16] = [0x42; 16];

async fn serve_download_startup(
    listener: &TcpListener,
    peer_addr: SocketAddr,
    file_hash: Ed2kHash,
    file_size: u64,
    file_name: &str,
    expect_source_exchange: bool,
) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let hello = read_packet(&mut stream).await;
    assert_eq!(hello[5], OP_HELLO);
    stream
        .write_all(&encode_hello_answer(Ed2kHelloIdentity {
            user_hash: PEER_HASH,
            client_id: 0x5912_0559,
            tcp_port: peer_addr.port(),
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }))
        .await
        .unwrap();

    let secure_ident_probe = read_packet(&mut stream).await;
    assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);
    let startup_request = read_packet(&mut stream).await;
    assert_startup_multipacket_ext2_with_source_exchange(
        startup_request[0],
        startup_request[5],
        &startup_request[6..],
        &file_hash,
        file_size,
        false,
        expect_source_exchange,
    );
    stream
        .write_all(&encode_startup_multipacket_ext2_answer(
            &file_hash, file_size, file_name, false,
        ))
        .await
        .unwrap();
    let start_upload = read_packet(&mut stream).await;
    assert_eq!(start_upload[5], OP_STARTUPLOADREQ);
    stream
}

fn source(file_hash: Ed2kHash, peer_addr: SocketAddr) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash,
        ip: test_bind_ip(),
        tcp_port: peer_addr.port(),
        client_id: u32::from_le_bytes(test_bind_ip().octets()),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: Some(PEER_HASH),
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

fn local_identity() -> Ed2kHelloIdentity {
    Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    }
}

async fn run_download(
    transfer_runtime: &Ed2kTransferRuntime,
    peer: &Ed2kFoundSource,
    secure_ident: &Arc<Ed2kSecureIdent>,
    file_size: u64,
) -> anyhow::Result<Ed2kPeerDownloadOutcome> {
    download_file_from_peer_test!(
        test_bind_ip(),
        peer,
        local_identity(),
        secure_ident,
        transfer_runtime,
        "anti-abuse.bin".to_string(),
        file_size,
        Duration::from_secs(3),
    )
    .await
}

#[tokio::test]
async fn unsolicited_queue_rank_bursts_disconnect_then_ban() {
    let root = unique_test_dir("ed2k-download-queue-rank-flood");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0xA5; 32_768];
    let file_size = payload.len() as u64;
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "anti-abuse.bin".to_string(),
            file_size,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for attempt in 0..2 {
            let mut stream = serve_download_startup(
                &listener,
                peer_addr,
                file_hash,
                file_size,
                "anti-abuse.bin",
                attempt == 0,
            )
            .await;
            // One solicited response consumes m_fQueueRankPending; the next
            // three ranks form the flood burst.
            for rank in [7, 8, 9, 10] {
                stream.write_all(&encode_queue_ranking(rank)).await.unwrap();
            }
            let mut eof = [0u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), stream.read(&mut eof))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    });

    let peer = source(file_hash, peer_addr);
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    let first_error = run_download(&transfer_runtime, &peer, &secure_ident, file_size)
        .await
        .unwrap_err();
    assert!(first_error.to_string().contains("QR flood"));
    assert!(!transfer_runtime.is_client_banned(Some(test_bind_ip()), Some(&PEER_HASH)));

    let second_error = run_download(&transfer_runtime, &peer, &secure_ident, file_size)
        .await
        .unwrap_err();
    assert!(second_error.to_string().contains("QR flood"));
    assert!(transfer_runtime.is_client_banned(Some(test_bind_ip()), Some(&PEER_HASH)));
    server.await.unwrap();
}

#[tokio::test]
async fn repeated_out_of_part_requests_suppress_later_accept_with_cancel() {
    let root = unique_test_dir("ed2k-download-out-of-part-guard");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6C; 32_768];
    let file_size = payload.len() as u64;
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "anti-abuse.bin".to_string(),
            file_size,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for attempt in 0..3 {
            let mut stream = serve_download_startup(
                &listener,
                peer_addr,
                file_hash,
                file_size,
                "anti-abuse.bin",
                attempt == 0,
            )
            .await;
            stream.write_all(&encode_accept_upload_req()).await.unwrap();
            let request = read_packet(&mut stream).await;
            assert_eq!(request[5], OP_REQUESTPARTS);
            stream
                .write_all(&encode_packet(OP_EDONKEYPROT, OP_OUTOFPARTREQS, &[]))
                .await
                .unwrap();
        }

        let mut guarded = serve_download_startup(
            &listener,
            peer_addr,
            file_hash,
            file_size,
            "anti-abuse.bin",
            false,
        )
        .await;
        guarded
            .write_all(&encode_accept_upload_req())
            .await
            .unwrap();
        let cancel = read_packet(&mut guarded).await;
        assert_eq!(cancel[0], OP_EDONKEYPROT);
        assert_eq!(cancel[5], OP_CANCELTRANSFER);
    });

    let peer = source(file_hash, peer_addr);
    let secure_ident = Arc::new(
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap(),
    );
    for _ in 0..3 {
        assert_eq!(
            run_download(&transfer_runtime, &peer, &secure_ident, file_size)
                .await
                .unwrap(),
            Ed2kPeerDownloadOutcome::NoNeededParts
        );
    }
    assert_eq!(
        run_download(&transfer_runtime, &peer, &secure_ident, file_size)
            .await
            .unwrap(),
        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
    );
    server.await.unwrap();
}
