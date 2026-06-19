use super::*;

#[tokio::test]
async fn small_file_download_completes_after_out_of_order_multi_range_compressed_response() {
    let root = unique_test_dir("ed2k-small-file-out-of-order-window-compressed");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x37; (super::ED2K_EMBLOCK_SIZE as usize) * 4];
    let first_end = super::ED2K_EMBLOCK_SIZE;
    let second_end = super::ED2K_EMBLOCK_SIZE * 2;
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "window-complete-compressed.epub".to_string(),
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
            "window-complete-compressed.epub",
            false,
        );
        stream.write_all(&filename_answer).await.unwrap();

        let _start_upload = read_packet(&mut stream).await;
        stream.write_all(&encode_accept_upload_req()).await.unwrap();

        let first_request_parts = read_packet(&mut stream).await;
        let (requested_hash, first_ranges) =
            decode_request_parts_payload(&first_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(first_ranges, vec![(0, first_end)]);
        let first_fragment = encode_sending_part(
            &file_hash,
            0,
            first_end,
            &payload_for_server[..usize::try_from(first_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&first_fragment).await.unwrap();

        let second_request_parts = read_packet(&mut stream).await;
        let (requested_hash, second_ranges) =
            decode_request_parts_payload(&second_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(second_ranges, vec![(first_end, second_end)]);
        let second_fragment = encode_sending_part(
            &file_hash,
            first_end,
            second_end,
            &payload_for_server
                [usize::try_from(first_end).unwrap()..usize::try_from(second_end).unwrap()],
            false,
        )
        .unwrap();
        stream.write_all(&second_fragment).await.unwrap();

        let third_request_parts = read_packet(&mut stream).await;
        let (requested_hash, third_ranges) =
            decode_request_parts_payload(&third_request_parts[6..], false).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            third_ranges,
            vec![
                (second_end, second_end + super::ED2K_EMBLOCK_SIZE),
                (
                    second_end + super::ED2K_EMBLOCK_SIZE,
                    payload_for_server.len() as u64,
                ),
            ]
        );

        let (early_start, early_end) = third_ranges[0];
        let (late_start, late_end) = third_ranges[1];

        let mut late_encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        late_encoder
            .write_all(
                &payload_for_server
                    [usize::try_from(late_start).unwrap()..usize::try_from(late_end).unwrap()],
            )
            .unwrap();
        let late_compressed = late_encoder.finish().unwrap();
        let late_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            late_start,
            late_compressed.len(),
            &late_compressed,
            false,
        )
        .unwrap();
        stream.write_all(&late_fragment).await.unwrap();

        let mut early_encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        early_encoder
            .write_all(
                &payload_for_server
                    [usize::try_from(early_start).unwrap()..usize::try_from(early_end).unwrap()],
            )
            .unwrap();
        let early_compressed = early_encoder.finish().unwrap();
        let early_fragment = super::encode_compressed_part_fragment(
            &file_hash,
            early_start,
            early_compressed.len(),
            &early_compressed,
            false,
        )
        .unwrap();
        stream.write_all(&early_fragment).await.unwrap();
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
        "window-complete-compressed.epub".to_string(),
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
