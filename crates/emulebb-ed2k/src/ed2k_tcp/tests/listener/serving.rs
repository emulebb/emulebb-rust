use super::*;

#[test]
fn upload_part_packets_split_large_uncompressed_ranges() {
    let file_hash = Ed2kHash::from_bytes([0x5A; 16]);
    let mut lcg = 0x1234_5678u32;
    let payload = (0..32_768)
        .map(|_| {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (lcg >> 24) as u8
        })
        .collect::<Vec<_>>();

    let packets = super::build_upload_part_packets(
        &file_hash,
        "upload.bin",
        0,
        payload.len() as u64,
        &payload,
        false,
    )
    .unwrap();

    assert!(packets.len() > 1);
    let mut reconstructed = Vec::new();
    let mut expected_start = 0u64;
    for packet in packets {
        assert_eq!(packet.phase, "sending_part");
        let (decoded_hash, start, end, bytes) =
            super::decode_sending_part_payload(&packet.packet[6..], false).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(start, expected_start);
        expected_start = end;
        reconstructed.extend_from_slice(&bytes);
    }

    assert_eq!(reconstructed, payload);
}

#[tokio::test]
async fn listener_upload_session_serves_verified_file_via_compressed_parts() {
    let mut payload = Vec::new();
    for index in 0..12_000u32 {
        writeln!(
            &mut payload,
            "ubuntu linux upload parity line {:05} repeated request surface",
            index % 1024
        )
        .unwrap();
    }
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let file_hash_hex = file_hash.to_string();

    let root = unique_test_dir("ed2k-upload-listener-compressed");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "upload.txt".to_string(), payload.len() as u64);
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &payload)
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = test_dht().await;
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = listener_secure_ident();
    let hello_identity = listener_hello_identity();

    let server = spawn_single_listener_connection(
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        Arc::clone(&transfer_runtime),
        hello_identity,
    );

    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_hello_identity()).await;
    // RSA-verify our identity to the listener so it credits our user hash
    // (B2: credits are attributed only to a verified secure-ident peer).
    let peer_secure_ident = test_peer_secure_ident();
    complete_peer_secure_ident_with_listener(&mut stream, &peer_secure_ident).await;

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    stream
        .write_all(&super::encode_request_filename(&file_hash, &manifest))
        .await
        .unwrap();
    let request_filename_answer =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_REQFILENAMEANSWER).await;
    assert_eq!(&request_filename_answer[6..22], &file_hash.0);

    stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let accept_upload =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept_upload.len(), 6);

    stream
        .write_all(
            &super::encode_request_parts_batch(&file_hash, &[(0, payload.len() as u64)]).unwrap(),
        )
        .await
        .unwrap();

    let mut reconstructed = Vec::new();
    let mut saw_compressed = false;
    let mut pending = None;
    while reconstructed.len() < payload.len() {
        let packet = read_packet(&mut stream).await;
        match (packet[0], packet[5]) {
            (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                saw_compressed = true;
                let (decoded_hash, start, advertised_len, fragment) =
                    super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                assert_eq!(decoded_hash, file_hash);
                // The serve walks the requested range in EMBLOCKSIZE blocks, each
                // its own complete zlib stream that may span several wire
                // fragments (all sharing the same `start`). A new block opens
                // (pending == None) at the next contiguous offset.
                if pending.is_none() {
                    assert_eq!(start, reconstructed.len() as u64);
                }
                let block_end = (start + ED2K_EMBLOCK_SIZE).min(payload.len() as u64);
                let pending_stream = pending.get_or_insert_with(|| super::PendingCompressedPart {
                    piece_index: 0,
                    start,
                    end: block_end,
                    advertised_compressed_len: advertised_len,
                    compressed_received: 0,
                    uncompressed_written: 0,
                    inflater: Decompress::new(true),
                });
                let (bytes, finished) =
                    super::inflate_compressed_part_fragment(pending_stream, fragment).unwrap();
                reconstructed.extend_from_slice(&bytes);
                if finished {
                    pending = None;
                }
            }
            (OP_EDONKEYPROT, super::OP_SENDINGPART) => {
                let (_, _, _, bytes) =
                    super::decode_sending_part_payload(&packet[6..], false).unwrap();
                reconstructed.extend_from_slice(&bytes);
            }
            _ => {}
        }
    }

    assert!(saw_compressed);
    assert_eq!(reconstructed, payload);
    let upload_snapshot = transfer_runtime.upload_queue_snapshot().await;
    assert_eq!(upload_snapshot.len(), 1);
    assert_eq!(upload_snapshot[0].uploaded_bytes, payload.len() as u64);
    assert!(upload_snapshot[0].upload_speed_bytes_per_sec > 0);
    drop(stream);
    server.await.unwrap();
    assert_eq!(
        transfer_runtime
            .peer_credit_by_hash(peer_hello_identity().user_hash)
            .unwrap()
            .map(|credit| credit.uploaded_bytes),
        Some(payload.len() as u64)
    );
}

/// FIX (memory-amplification DoS): an oversized OP_REQUESTPARTS range must be
/// served block-by-block from bounded reads, not via one whole-range read.
///
/// The seeded file has two parts but only part 0 is verified. The peer requests
/// the whole verified part 0 as a single oversized range (`0..ED2K_PART_SIZE`,
/// ~9.7 MB >> EMBLOCKSIZE) plus a range fully inside the unverified part 1.
/// The pre-fix path allocated `vec![0u8; end - start]` and read the entire range
/// in one shot; the chunked path walks the requested span in EMBLOCKSIZE reads,
/// so the resident allocation per read is bounded to one block regardless of the
/// peer-controlled range size. The whole verified part still serves exactly
/// (every byte, contiguous, every wire fragment <= EMBLOCKSIZE) while the
/// unverified range yields nothing (master serves only complete parts).
#[tokio::test]
async fn listener_serves_oversized_range_block_by_block_without_whole_range_read() {
    // A two-ED2K-part file (PARTSIZE first part + a short trailing part), with
    // only part 0 stored/verified. Incompressible random bytes so the serve
    // takes the uncompressed OP_SENDINGPART path and fragment sizes are
    // observable on the wire.
    let last_part_len = ED2K_EMBLOCK_SIZE * 2;
    let file_size = ED2K_PART_SIZE + last_part_len;
    let mut lcg = 0x9E37_79B9u32;
    let mut next_byte = || {
        lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (lcg >> 24) as u8
    };
    let first_piece = (0..ED2K_PART_SIZE).map(|_| next_byte()).collect::<Vec<_>>();
    let last_piece = (0..last_part_len).map(|_| next_byte()).collect::<Vec<_>>();
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let file_hash_hex = file_hash.to_string();

    let root = unique_test_dir("ed2k-upload-listener-oversized-range");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = new_transfer_job(file_hash, "oversized.bin".to_string(), file_size);
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(&file_hash_hex, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();
    transfer_runtime
        .mark_piece_requested(&file_hash_hex, 0)
        .await
        .unwrap();
    // Only part 0 is verified; part 1 stays missing.
    transfer_runtime
        .store_piece_data(&file_hash_hex, 0, &first_piece)
        .await
        .unwrap();

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let dht = test_dht().await;
    let server_state = Arc::new(RwLock::new(Ed2kServerState::default()));
    let kad_firewall = Arc::new(Mutex::new(KadFirewallState::default()));
    let secure_ident = listener_secure_ident();
    let hello_identity = listener_hello_identity();

    let server = spawn_single_listener_connection(
        listener,
        dht,
        server_state,
        kad_firewall,
        secure_ident,
        Arc::clone(&transfer_runtime),
        hello_identity,
    );

    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_hello_identity()).await;
    stream
        .write_all(&super::encode_start_upload_req(&file_hash))
        .await
        .unwrap();
    let accept_upload =
        read_until_opcode(&mut stream, OP_EDONKEYPROT, super::OP_ACCEPTUPLOADREQ).await;
    assert_eq!(accept_upload.len(), 6);

    // One batch with the whole verified part 0 (oversized, served exactly) plus
    // a range fully inside the unverified part 1 (must serve nothing). The
    // verified range ends exactly at the part boundary so every EMBLOCKSIZE walk
    // step stays inside the verified region.
    stream
        .write_all(
            &super::encode_request_parts_batch(
                &file_hash,
                &[
                    (0, ED2K_PART_SIZE),
                    (ED2K_PART_SIZE, ED2K_PART_SIZE + ED2K_EMBLOCK_SIZE),
                ],
            )
            .unwrap(),
        )
        .await
        .unwrap();

    // Collect SENDINGPART fragments for the verified part 0. The serve must
    // deliver every byte of part 0 contiguously; the unverified part-1 range
    // contributes nothing (the loop completes once part 0 is whole). A bounded
    // read per fragment is reflected by every wire fragment being <= EMBLOCKSIZE.
    let mut served_end = 0u64;
    let mut max_fragment_len = 0u64;
    while served_end < ED2K_PART_SIZE {
        let packet = read_packet(&mut stream).await;
        if (packet[0], packet[5]) == (OP_EDONKEYPROT, super::OP_SENDINGPART) {
            let (decoded_hash, start, end, bytes) =
                super::decode_sending_part_payload(&packet[6..], false).unwrap();
            assert_eq!(decoded_hash, file_hash);
            assert_eq!(start, served_end, "fragments must be contiguous");
            assert_eq!(end - start, bytes.len() as u64);
            assert!(end <= ED2K_PART_SIZE, "serve overran into the unverified part");
            max_fragment_len = max_fragment_len.max(end - start);
            served_end = end;
        }
    }

    // The whole verified part 0 was served, contiguously, and never overran into
    // the unverified region.
    assert_eq!(served_end, ED2K_PART_SIZE);
    // No wire fragment exceeded one EMBLOCKSIZE — the per-read allocation is
    // bounded to a single block (the DoS cap is enforced).
    assert!(
        max_fragment_len <= ED2K_EMBLOCK_SIZE,
        "fragment {max_fragment_len} exceeded EMBLOCKSIZE {ED2K_EMBLOCK_SIZE}"
    );

    // Exactly the verified bytes were accounted, nothing for part 1.
    let upload_snapshot = transfer_runtime.upload_queue_snapshot().await;
    assert_eq!(upload_snapshot.len(), 1);
    assert_eq!(upload_snapshot[0].uploaded_bytes, ED2K_PART_SIZE);

    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_obfuscated_upload_session_serves_verified_file_via_compressed_parts() {
    let mut payload = Vec::new();
    for index in 0..12_000u32 {
        writeln!(
            &mut payload,
            "ubuntu linux obfuscated upload parity line {:05} repeated request surface",
            index % 1024
        )
        .unwrap();
    }
    let listener_identity = Ed2kHelloIdentity {
        connect_options: emule_connect_options(true),
        ..listener_hello_identity()
    };
    let listener_user_hash = listener_identity.user_hash;
    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-obfuscated-compressed",
        listener_identity,
        [0x7E; 16],
        0xAA55_9900,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("upload-obfuscated.txt", payload)
        .await;
    let server = runtime.spawn_listener_connections(1);

    let mut transport = connect_obfuscated_peer_and_exchange_hello(
        runtime.peer_addr,
        listener_user_hash,
        Ed2kHelloIdentity {
            connect_options: emule_connect_options(true),
            ..peer_hello_identity()
        },
    )
    .await;
    // RSA-verify our identity so the listener credits our user hash (B2).
    let peer_secure_ident = test_peer_secure_ident();
    complete_peer_secure_ident_with_listener_transport(&mut transport, &peer_secure_ident).await;

    transport
        .write_all(&encode_start_upload_req(&file.file_hash))
        .await
        .unwrap();
    wait_for_transport_upload_accept(&mut transport).await;

    request_transport_upload_parts(
        &mut transport,
        &file.file_hash,
        &[(0, file.payload.len() as u64)],
    )
    .await;
    let (reconstructed, saw_compressed) = read_transport_upload_bytes(
        &mut transport,
        &file.file_hash,
        0,
        file.payload.len() as u64,
    )
    .await;

    assert!(saw_compressed);
    assert_eq!(reconstructed, file.payload);
    let upload_snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
    assert_eq!(upload_snapshot.len(), 1);
    assert_eq!(upload_snapshot[0].uploaded_bytes, file.payload.len() as u64);
    assert!(upload_snapshot[0].upload_speed_bytes_per_sec > 0);
    drop(transport);
    server.await.unwrap();
    assert_eq!(
        runtime
            .transfer_runtime
            .peer_credit_by_hash(peer_hello_identity().user_hash)
            .unwrap()
            .map(|credit| credit.uploaded_bytes),
        Some(file.payload.len() as u64)
    );
}
