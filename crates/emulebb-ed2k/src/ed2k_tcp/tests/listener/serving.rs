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
        reconstructed.extend_from_slice(bytes);
    }

    assert_eq!(reconstructed, payload);
}

// RUST-PAR-022 (UploadDiskIOThread.cpp:705 `if (endpos > _UI32_MAX)`): the
// standard SENDINGPART reply opcode is chosen PER PACKET from the fragment's
// exclusive end offset, not once from the request opcode. For a >4GB range a
// fragment ending at or below 4GiB emits the 32-bit OP_SENDINGPART (4-byte
// offsets) while a fragment ending above 4GiB emits OP_SENDINGPART_I64 (8-byte
// offsets). A packet straddling the 4GiB boundary uses I64 (its end > u32::MAX).
#[test]
fn upload_part_packets_select_sending_opcode_per_fragment() {
    const BOUNDARY: u64 = u32::MAX as u64;
    let file_hash = Ed2kHash::from_bytes([0x5A; 16]);
    // Start below 4GiB so the range crosses the boundary; three fragments result:
    // [start, start+10240) entirely below, [+10240, +20480) straddling, and
    // [+20480, +25000) entirely above.
    let start = BOUNDARY - 12_000;
    let range_len = 25_000usize;
    let end = start + range_len as u64;
    let mut lcg = 0x0BAD_F00Du32;
    let payload = (0..range_len)
        .map(|_| {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (lcg >> 24) as u8
        })
        .collect::<Vec<_>>();

    // ".mp4" is in the incompressible exclusion set, so the standard path is used
    // deterministically (no compression attempt).
    let packets = super::build_upload_part_packets(&file_hash, "movie.mp4", start, end, &payload)
        .unwrap();
    assert_eq!(packets.len(), 3, "25000 bytes split into 10240+10240+4520");

    let expected_i64 = [false, true, true];
    let mut reconstructed = Vec::new();
    let mut expected_start = start;
    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(packet.phase, "sending_part");
        let want_i64 = expected_i64[index];
        if want_i64 {
            assert_eq!(packet.packet[0], OP_EMULEPROT);
            assert_eq!(packet.packet[5], OP_SENDINGPART_I64);
        } else {
            assert_eq!(packet.packet[0], OP_EDONKEYPROT);
            assert_eq!(packet.packet[5], OP_SENDINGPART);
        }
        let (decoded_hash, frag_start, frag_end, bytes) =
            super::decode_sending_part_payload(&packet.packet[6..], want_i64).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(frag_start, expected_start);
        // Confirm the on-wire offset field WIDTH matches the chosen opcode:
        // header = proto(1)+len(4)+opcode(1) + hash(16) + 2 offsets (8 or 16).
        let offset_field_bytes = if want_i64 { 16 } else { 8 };
        assert_eq!(packet.packet.len(), 6 + 16 + offset_field_bytes + bytes.len());
        // The boundary-straddling fragment must be the I64 one.
        assert_eq!(frag_end > BOUNDARY, want_i64);
        expected_start = frag_end;
        reconstructed.extend_from_slice(bytes);
    }
    assert_eq!(expected_start, end);
    assert_eq!(reconstructed, payload);
}

// RUST-PAR-022 (UploadDiskIOThread.cpp:770 `if (uEndOffset > UINT32_MAX)`): the
// COMPRESSEDPART reply opcode is chosen PER BLOCK from the whole range's end
// offset (all fragments share it, since the header advertises the block start +
// total compressed size). A block ending above 4GiB uses OP_COMPRESSEDPART_I64;
// a block entirely at or below 4GiB uses the 32-bit OP_COMPRESSEDPART.
#[test]
fn upload_part_packets_select_compressed_opcode_per_block() {
    const BOUNDARY: u64 = u32::MAX as u64;
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);
    // Highly repetitive payload so compression fires (compressed < original).
    let mut payload = Vec::new();
    for _ in 0..5_000 {
        payload.extend_from_slice(b"parity");
    }

    // Block ending above 4GiB -> every fragment is OP_COMPRESSEDPART_I64.
    let start_hi = BOUNDARY - 5_000;
    let end_hi = start_hi + payload.len() as u64;
    let hi = super::build_upload_part_packets(&file_hash, "notes.txt", start_hi, end_hi, &payload)
        .unwrap();
    assert!(!hi.is_empty());
    for packet in &hi {
        assert_eq!(packet.phase, "compressed_part");
        assert_eq!(packet.packet[0], OP_EMULEPROT);
        assert_eq!(packet.packet[5], OP_COMPRESSEDPART_I64);
        let (decoded_hash, block_start, _len, _frag) =
            super::decode_compressed_part_fragment(&packet.packet[6..], true).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(block_start, start_hi);
    }

    // Block entirely below 4GiB -> every fragment is the 32-bit OP_COMPRESSEDPART.
    let start_lo = 1_000u64;
    let end_lo = start_lo + payload.len() as u64;
    let lo = super::build_upload_part_packets(&file_hash, "notes.txt", start_lo, end_lo, &payload)
        .unwrap();
    assert!(!lo.is_empty());
    for packet in &lo {
        assert_eq!(packet.phase, "compressed_part");
        assert_eq!(packet.packet[0], OP_EMULEPROT);
        assert_eq!(packet.packet[5], OP_COMPRESSEDPART);
        let (decoded_hash, block_start, _len, _frag) =
            super::decode_compressed_part_fragment(&packet.packet[6..], false).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(block_start, start_lo);
    }
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

    let mut reconstructed = Vec::new();
    let mut saw_compressed = false;
    let mut request_start = 0u64;
    while reconstructed.len() < payload.len() {
        let request_end = request_start
            .saturating_add(ED2K_EMBLOCK_SIZE * 3)
            .min(payload.len() as u64);
        stream
            .write_all(
                &super::encode_request_parts_batch(&file_hash, &[(request_start, request_end)])
                    .unwrap(),
            )
            .await
            .unwrap();

        let mut pending = None;
        while reconstructed.len() < request_end as usize {
            let packet = read_packet(&mut stream).await;
            match (packet[0], packet[5]) {
                (OP_EMULEPROT, super::OP_COMPRESSEDPART) => {
                    saw_compressed = true;
                    let (decoded_hash, start, advertised_len, fragment) =
                        super::decode_compressed_part_fragment(&packet[6..], false).unwrap();
                    assert_eq!(decoded_hash, file_hash);
                    // The serve walks the requested range in EMBLOCKSIZE blocks,
                    // each its own complete zlib stream that may span several
                    // wire fragments (all sharing the same `start`). A new block
                    // opens (pending == None) at the next contiguous offset.
                    if pending.is_none() {
                        assert_eq!(start, reconstructed.len() as u64);
                    }
                    let block_end = (start + ED2K_EMBLOCK_SIZE).min(request_end);
                    let pending_stream =
                        pending.get_or_insert_with(|| super::PendingCompressedPart {
                            piece_index: 0,
                            start,
                            end: block_end,
                            advertised_compressed_len: advertised_len,
                            compressed_received: 0,
                            uncompressed_written: 0,
                            inflater: Decompress::new(true),
                            zstream_error: false,
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
                    reconstructed.extend_from_slice(bytes);
                }
                _ => {}
            }
        }
        request_start = request_end;
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

/// MFC parity: an oversized OP_REQUESTPARTS range is rejected before queuing.
///
/// The seeded file has two parts but only part 0 is verified. The peer requests
/// one range just above MFC's `3 * EMBLOCKSIZE` cap plus one valid block. The
/// oversized range must contribute no bytes, while the valid range still serves.
#[tokio::test]
async fn listener_rejects_oversized_range_and_serves_valid_range() {
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

    // One oversized range (must be skipped) plus one valid block (must serve).
    stream
        .write_all(
            &super::encode_request_parts_batch(
                &file_hash,
                &[(0, ED2K_EMBLOCK_SIZE * 3 + 1), (0, ED2K_EMBLOCK_SIZE)],
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let mut served_end = 0u64;
    while served_end < ED2K_EMBLOCK_SIZE {
        let packet = read_packet(&mut stream).await;
        assert_eq!(
            (packet[0], packet[5]),
            (OP_EDONKEYPROT, super::OP_SENDINGPART)
        );
        let (decoded_hash, start, end, bytes) =
            super::decode_sending_part_payload(&packet[6..], false).unwrap();
        assert_eq!(decoded_hash, file_hash);
        assert_eq!(start, served_end);
        assert_eq!(end - start, bytes.len() as u64);
        assert!(end <= ED2K_EMBLOCK_SIZE);
        served_end = end;
    }
    assert_eq!(served_end, ED2K_EMBLOCK_SIZE);

    // Only the valid block was accounted. The oversized range contributed no
    // payload, matching MFC's reject-too-large admission.
    let upload_snapshot = transfer_runtime.upload_queue_snapshot().await;
    assert_eq!(upload_snapshot.len(), 1);
    assert_eq!(upload_snapshot[0].uploaded_bytes, ED2K_EMBLOCK_SIZE);

    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_skips_duplicate_range_within_single_upload_request() {
    let mut lcg = 0xA5A5_1234u32;
    let payload = (0..ED2K_EMBLOCK_SIZE)
        .map(|_| {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (lcg >> 24) as u8
        })
        .collect::<Vec<_>>();

    let mut runtime = ListenerTestRuntime::new(
        "ed2k-upload-listener-duplicate-range",
        listener_hello_identity(),
        [0x42; 16],
        0xCC33_2211,
    )
    .await;
    let file = runtime
        .seed_verified_upload_file("duplicate-range.bin", payload)
        .await;
    let server = runtime.spawn_listener_connections(1);

    let mut stream =
        connect_peer_and_exchange_hello(runtime.peer_addr, peer_hello_identity()).await;
    request_upload_file(&mut stream, &file.file_hash).await;
    wait_for_upload_accept(&mut stream).await;

    request_upload_parts(
        &mut stream,
        &file.file_hash,
        &[(0, ED2K_EMBLOCK_SIZE), (0, ED2K_EMBLOCK_SIZE)],
    )
    .await;
    let uploaded = read_upload_bytes(&mut stream, &file.file_hash, 0, ED2K_EMBLOCK_SIZE).await;
    assert_eq!(uploaded, file.payload);
    let duplicate_payload =
        tokio::time::timeout(Duration::from_millis(250), read_packet(&mut stream)).await;
    assert!(duplicate_payload.is_err());

    let upload_snapshot = runtime.transfer_runtime.upload_queue_snapshot().await;
    assert_eq!(upload_snapshot.len(), 1);
    assert_eq!(upload_snapshot[0].uploaded_bytes, ED2K_EMBLOCK_SIZE);

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

    let mut reconstructed = Vec::new();
    let mut saw_compressed = false;
    let mut request_start = 0u64;
    while reconstructed.len() < file.payload.len() {
        let request_end = request_start
            .saturating_add(ED2K_EMBLOCK_SIZE * 3)
            .min(file.payload.len() as u64);
        request_transport_upload_parts(
            &mut transport,
            &file.file_hash,
            &[(request_start, request_end)],
        )
        .await;
        let (bytes, compressed) = read_transport_upload_bytes(
            &mut transport,
            &file.file_hash,
            request_start,
            request_end,
        )
        .await;
        reconstructed.extend_from_slice(&bytes);
        saw_compressed |= compressed;
        request_start = request_end;
    }

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
