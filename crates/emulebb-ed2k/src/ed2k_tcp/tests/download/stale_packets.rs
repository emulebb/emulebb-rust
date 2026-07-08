//! Stale / duplicate / corrupt block-packet tolerance (RUST-PAR-017 DL-4).
//!
//! The oracle drops a block payload that matches no pending request instead of
//! killing the session (DownloadClient.cpp:1531-1553), consumes duplicate
//! payload gracefully (:1421-1487), survives zlib stream errors (:1300-1308,
//! :1394-1411), and only cancels after 32 stale packets inside 15 s
//! (:2690-2712).

use super::*;

async fn serve_download_startup(
    stream: &mut tokio::net::TcpStream,
    file_hash: &emulebb_kad_proto::Ed2kHash,
    file_size: u64,
    file_name: &str,
    peer_port: u16,
) {
    let _hello = read_packet(stream).await;
    let hello_answer = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x42; 16],
        client_id: 0x5912_0559,
        tcp_port: peer_port,
        udp_port: 0,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });
    stream.write_all(&hello_answer).await.unwrap();

    let _secure_ident_probe = read_packet(stream).await;
    let startup_request = read_packet(stream).await;
    assert_startup_multipacket_ext2(
        startup_request[0],
        startup_request[5],
        &startup_request[6..],
        file_hash,
        file_size,
        false,
    );
    let filename_answer =
        encode_startup_multipacket_ext2_answer(file_hash, file_size, file_name, false);
    stream.write_all(&filename_answer).await.unwrap();
    let _start_upload = read_packet(stream).await;
    stream.write_all(&encode_accept_upload_req()).await.unwrap();
}

fn stale_test_source(file_hash: emulebb_kad_proto::Ed2kHash, peer_port: u16) -> Ed2kFoundSource {
    Ed2kFoundSource {
        file_hash,
        ip: test_bind_ip(),
        tcp_port: peer_port,
        client_id: u32::from_le_bytes(test_bind_ip().octets()),
        low_id: false,
        obfuscated: false,
        obfuscation_options: None,
        user_hash: None,
        source_server: None,
        buddy_id: None,
        buddy_endpoint: None,
        source_udp_port: None,
    }
}

fn stale_test_identity() -> Ed2kHelloIdentity {
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

/// One stale OP_SENDINGPART is dropped (oracle :1531-1553) and the session
/// keeps downloading to completion.
#[tokio::test]
async fn stale_block_packet_dropped_without_ending_session() {
    let root = unique_test_dir("ed2k-stale-block-packet-dropped");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "stale-drop.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_download_startup(
            &mut stream,
            &file_hash,
            payload_for_server.len() as u64,
            "stale-drop.epub",
            peer_addr.port(),
        )
        .await;

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        // A payload range we never requested from this offset: dropped, not fatal.
        let stale =
            encode_sending_part(&file_hash, 8, 16, &payload_for_server[8..16], false).unwrap();
        stream.write_all(&stale).await.unwrap();
        // The real block still lands and completes the file.
        let valid = encode_sending_part(
            &file_hash,
            0,
            payload_for_server.len() as u64,
            &payload_for_server,
            false,
        )
        .unwrap();
        stream.write_all(&valid).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &stale_test_source(file_hash, peer_addr.port()),
        stale_test_identity(),
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "stale-drop.epub".to_string(),
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

/// The 32nd stale packet inside 15 s trips the oracle's guard (:2690-2712,
/// constants :70-71): the client sends OP_CANCELTRANSFER and requeues the
/// source; none of the dropped bytes are attributed in the corruption blackbox.
#[tokio::test]
async fn sustained_stale_block_packets_cancel_transfer() {
    let root = unique_test_dir("ed2k-stale-block-packet-cancel");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5A; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "stale-cancel.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_download_startup(
            &mut stream,
            &file_hash,
            payload_for_server.len() as u64,
            "stale-cancel.epub",
            peer_addr.port(),
        )
        .await;

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let stale =
            encode_sending_part(&file_hash, 8, 16, &payload_for_server[8..16], false).unwrap();
        // 31 stale packets are tolerated; the 32nd cancels.
        for _ in 0..32 {
            stream.write_all(&stale).await.unwrap();
        }
        let cancel = read_packet(&mut stream).await;
        assert_eq!(cancel[5], OP_CANCELTRANSFER);
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &stale_test_source(file_hash, peer_addr.port()),
        stale_test_identity(),
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "stale-cancel.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    // Dropped stale payload must never be attributed as received data.
    assert_eq!(
        transfer_runtime.cbb_recorded_bytes_for_test(&file_hash_hex, test_bind_ip()),
        0
    );
    server.await.unwrap();
}

/// Duplicate payload overlapping already-received bytes is consumed gracefully
/// (oracle :1421-1487): a full duplicate is dropped without error and a
/// partial duplicate advances the pending block with only its new tail.
#[tokio::test]
async fn duplicate_block_payload_consumed_without_error() {
    let root = unique_test_dir("ed2k-duplicate-block-consumed");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6B; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "duplicate.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_download_startup(
            &mut stream,
            &file_hash,
            payload_for_server.len() as u64,
            "duplicate.epub",
            peer_addr.port(),
        )
        .await;

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        let first_half =
            encode_sending_part(&file_hash, 0, 16_384, &payload_for_server[..16_384], false)
                .unwrap();
        stream.write_all(&first_half).await.unwrap();
        // Full duplicate of the received prefix: dropped, not fatal.
        stream.write_all(&first_half).await.unwrap();
        // Overlapping resend that extends past the received prefix: only the
        // new tail is consumed and the block completes.
        let overlap = encode_sending_part(
            &file_hash,
            8_192,
            payload_for_server.len() as u64,
            &payload_for_server[8_192..],
            false,
        )
        .unwrap();
        stream.write_all(&overlap).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &stale_test_source(file_hash, peer_addr.port()),
        stale_test_identity(),
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "duplicate.epub".to_string(),
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

/// A zlib error on a compressed stream ignores the remainder of that stream
/// but keeps the connection (oracle :1300-1308, :1394-1411): the session ends
/// via the peer closing, not via a hard error, and no stale bytes are
/// attributed in the corruption blackbox.
#[tokio::test]
async fn inflate_error_skips_stream_but_session_continues() {
    let root = unique_test_dir("ed2k-inflate-error-continues");
    let transfer_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x7C; 32_768];
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "zstream-error.epub".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        serve_download_startup(
            &mut stream,
            &file_hash,
            payload_for_server.len() as u64,
            "zstream-error.epub",
            peer_addr.port(),
        )
        .await;

        let request_parts = read_packet(&mut stream).await;
        assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        // Not a zlib stream: the inflater errors on the first fragment.
        let garbage = vec![0xEE; 300];
        let corrupt =
            super::encode_compressed_part_fragment(&file_hash, 0, garbage.len(), &garbage, false)
                .unwrap();
        stream.write_all(&corrupt).await.unwrap();
        // Further payload for the errored stream is swallowed, not fatal.
        stream.write_all(&corrupt).await.unwrap();
    });

    let result = download_file_from_peer_test!(
        test_bind_ip(),
        &stale_test_source(file_hash, peer_addr.port()),
        stale_test_identity(),
        &Arc::new(
            Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap())
                .unwrap(),
        ),
        &transfer_runtime,
        "zstream-error.epub".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    // The zlib error is NOT a session error: the attempt ends as a normal
    // incomplete session when the peer goes away.
    assert_eq!(result, Ed2kPeerDownloadOutcome::AcceptedButIncomplete);
    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(!manifest.completed);
    assert_eq!(manifest.pieces[0].bytes_written, 0);
    assert_eq!(
        transfer_runtime.cbb_recorded_bytes_for_test(&file_hash_hex, test_bind_ip()),
        0
    );
    server.await.unwrap();
}
