use super::*;

#[tokio::test]
async fn outbound_download_connection_serves_and_cancels_upload_without_closing() {
    let root = unique_test_dir("ed2k-outbound-duplex-upload");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let download_payload = vec![0x5A; 32_768];
    let download_hash = Ed2kHash::from_bytes(Md4::digest(&download_payload).into());
    let download_hash_hex = download_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            download_hash,
            "download.epub".to_string(),
            download_payload.len() as u64,
        ))
        .await
        .unwrap();

    let upload_payload = vec![0x71; 4096];
    let upload_hash = Ed2kHash::from_bytes(Md4::digest(&upload_payload).into());
    let upload_hash_hex = upload_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            upload_hash,
            "upload.txt".to_string(),
            upload_payload.len() as u64,
        ))
        .await
        .unwrap();
    transfer_runtime
        .store_md4_hashset(&upload_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&upload_hash_hex, 0, &upload_payload)
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = download_payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!((hello[0], hello[5]), (OP_EDONKEYPROT, OP_HELLO));
        stream
            .write_all(&encode_hello_answer(Ed2kHelloIdentity {
                user_hash: [0x42; 16],
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
        assert_eq!(
            (secure_ident_probe[0], secure_ident_probe[5]),
            (OP_EMULEPROT, OP_SECIDENTSTATE)
        );
        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &download_hash,
            payload_for_server.len() as u64,
            false,
        );
        stream
            .write_all(&encode_startup_multipacket_ext2_answer(
                &download_hash,
                payload_for_server.len() as u64,
                "download.epub",
                false,
            ))
            .await
            .unwrap();
        stream
            .write_all(&encode_start_upload_req(&upload_hash))
            .await
            .unwrap();

        let mut saw_upload_accept = false;
        let mut saw_download_start = false;
        while !saw_upload_accept || !saw_download_start {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ) => {
                    saw_upload_accept = true;
                }
                (OP_EDONKEYPROT, super::OP_STARTUPLOADREQ) => {
                    assert_eq!(&packet[6..22], &download_hash.0);
                    saw_download_start = true;
                }
                pair => panic!("unexpected duplex startup packet {pair:?}"),
            }
        }

        stream
            .write_all(&encode_packet(OP_EDONKEYPROT, OP_CANCELTRANSFER, &[]))
            .await
            .unwrap();
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(
            (request_parts[0], request_parts[5]),
            (OP_EDONKEYPROT, super::OP_REQUESTPARTS)
        );
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, download_hash);
        assert_eq!(ranges, vec![(0, payload_for_server.len() as u64)]);
        stream
            .write_all(
                &encode_sending_part(
                    &download_hash,
                    0,
                    payload_for_server.len() as u64,
                    &payload_for_server,
                    false,
                )
                .unwrap(),
            )
            .await
            .unwrap();
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &Ed2kFoundSource {
            file_hash: download_hash,
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
        "download.epub".to_string(),
        download_payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);
    assert!(
        transfer_runtime
            .manifest(&download_hash_hex)
            .await
            .unwrap()
            .completed
    );
    server.await.unwrap();
}
