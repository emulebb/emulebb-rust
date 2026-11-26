use super::*;
use crate::ed2k_transfer::Ed2kTransferState;

const LARGE_BROWSE_FILES: usize = 100_000;
const BROWSE_FIXTURE_FILE_SIZE: u64 = 32;

async fn large_browse_publisher(root: &std::path::Path) -> Arc<Ed2kTransferRuntime> {
    use emulebb_metadata::{MetadataSharedDirectoryRoot, MetadataStore, NativePath};
    use rusqlite::params;

    let database = root.join("large-browse.sqlite");
    let metadata = MetadataStore::open(&database).unwrap();
    let runtime =
        Ed2kTransferRuntime::load_or_create_with_metadata(root, metadata.clone()).unwrap();
    let library = root.join("private-browse-root");
    std::fs::create_dir(&library).unwrap();
    let template = root.join("unshared-evidence.bin");
    std::fs::write(&template, [0x62; BROWSE_FIXTURE_FILE_SIZE as usize]).unwrap();
    runtime
        .ingest_local_file(&template, "unshared-evidence.bin")
        .await
        .unwrap();
    let fingerprint = metadata
        .local_file_instance(&crate::long_path::long_path(&template))
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    metadata
        .clone()
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: library.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();

    // Seed persisted rows in one transaction. Session visibility is still
    // granted by the production membership admission on the runtime's own
    // connection. Only the browse projection is under test, so the 100,000
    // synthetic paths need no payload files.
    let mut writer = rusqlite::Connection::open(&database).unwrap();
    writer.pragma_update(None, "foreign_keys", "ON").unwrap();
    let tx = writer.transaction().unwrap();
    let (native_identity, secondary_identity, stored_fingerprint): (Vec<u8>, Option<Vec<u8>>, Vec<u8>) = tx
        .query_row(
            "SELECT native_identity,secondary_identity,verified_fingerprint FROM local_file_instances",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    {
        let mut known = tx.prepare(
            "INSERT INTO known_files(ed2k_hash,size_bytes,display_name,first_seen_at_s,last_seen_at_s,updated_at_s)
             VALUES(?1,?2,?3,0,0,0) RETURNING id",
        ).unwrap();
        let mut path = tx.prepare(
            "INSERT INTO local_paths(display_path,native_path,search_key,platform,sort_key,file_name_search_key)
             VALUES(?1,?2,?3,?4,?3,?5) RETURNING id",
        ).unwrap();
        let mut instance = tx.prepare(
            "INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,secondary_identity,verified_fingerprint,verified_at_s)
             VALUES(?1,?2,?3,?4,?5,?6,0)",
        ).unwrap();
        let mut verified = tx.prepare(
            "INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
             VALUES(?1,?2,?3,0)",
        ).unwrap();
        for index in 1..=LARGE_BROWSE_FILES {
            let name = format!("browse-{index:06}.bin");
            let hash = format!("{index:016}");
            let id: i64 = known
                .query_row(
                    params![hash.as_bytes(), BROWSE_FIXTURE_FILE_SIZE as i64, name],
                    |row| row.get(0),
                )
                .unwrap();
            let native = NativePath::from(library.join(&name));
            let display = native.display_path();
            let path_id: i64 = path
                .query_row(
                    params![
                        display,
                        native.storage_bytes(),
                        display.to_lowercase(),
                        NativePath::platform(),
                        name
                    ],
                    |row| row.get(0),
                )
                .unwrap();
            instance
                .execute(params![
                    path_id,
                    id,
                    BROWSE_FIXTURE_FILE_SIZE as i64,
                    native_identity,
                    secondary_identity,
                    stored_fingerprint
                ])
                .unwrap();
            verified
                .execute(params![id, name, ED2K_PART_SIZE as i64])
                .unwrap();
        }
    }
    tx.commit().unwrap();

    let watermark = metadata.shared_root_scan_watermark(&library).unwrap();
    metadata
        .replace_root_memberships(
            &library,
            &watermark,
            (1..=LARGE_BROWSE_FILES).map(|index| {
                let relative = std::path::PathBuf::from(format!("browse-{index:06}.bin"));
                (library.join(&relative), relative, fingerprint.clone())
            }),
        )
        .unwrap();
    assert_eq!(
        metadata.verified_local_share_count().unwrap(),
        LARGE_BROWSE_FILES
    );
    Arc::new(runtime)
}

#[tokio::test]
async fn listener_and_requester_browse_one_hundred_thousand_files_over_tcp() {
    use crate::ed2k_tcp::{
        OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILESDIRANS,
        browse::{BrowsePeer, requests::PeerBrowseStatus},
        codec::shared_browse::BROWSE_MAX_PAYLOAD,
    };

    let root = tempfile::tempdir_in(unique_test_dir("ed2k-large-browse-tcp")).unwrap();
    let publisher = large_browse_publisher(root.path()).await;
    let requester = Ed2kTransferRuntime::load_or_create(&root.path().join("requester")).unwrap();
    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let identity = listener_hello_identity();
    let task = spawn_single_listener_connection(
        listener,
        test_dht().await,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        Arc::new(Mutex::new(KadFirewallState::default())),
        listener_secure_ident(),
        publisher,
        identity,
    );
    let mut socket = TcpStream::connect(endpoint).await.unwrap();
    socket
        .write_all(&encode_hello_request(peer_hello_identity()))
        .await
        .unwrap();
    let hello = read_until_opcode(&mut socket, OP_EDONKEYPROT, OP_HELLOANSWER).await;
    let hello = decode_hello_answer_profile(&hello[6..]).unwrap();
    let mut session = None;
    BrowsePeer::from_hello(&hello).bind(
        &requester,
        hello.identity.user_hash,
        endpoint,
        &mut session,
    );
    let mut session = session.unwrap();

    socket
        .write_all(&encode_packet(OP_EDONKEYPROT, OP_ASKSHAREDFILES, &[]))
        .await
        .unwrap();
    let flat = tokio::time::timeout(
        Duration::from_secs(30),
        read_until_opcode(&mut socket, OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS),
    )
    .await
    .unwrap();
    assert!(flat[6..].is_empty());

    let registry = requester.peer_browse_registry();
    let peer_endpoint = SocketAddr::new(endpoint.ip(), identity.tcp_port);
    let browse = registry
        .start(Some(identity.user_hash), peer_endpoint)
        .unwrap();
    let mut directory_replies = 0;
    tokio::time::timeout(Duration::from_secs(90), async {
        let mut request = session.recv().await;
        while let Some(frame) = request {
            let expected = match frame[5] {
                OP_ASKSHAREDDIRS => OP_ASKSHAREDDIRSANS,
                OP_ASKSHAREDFILESDIR => OP_ASKSHAREDFILESDIRANS,
                opcode => panic!("unexpected browse request {opcode:#x}"),
            };
            socket.write_all(&frame).await.unwrap();
            let reply = read_next_edonkey_packet(&mut socket).await;
            assert_eq!(reply[5], expected);
            assert!(reply.len() - 6 <= BROWSE_MAX_PAYLOAD);
            request = session
                .handle_reply_async(expected, reply[6..].to_vec())
                .await;
            directory_replies += usize::from(expected == OP_ASKSHAREDFILESDIRANS);
        }
    })
    .await
    .unwrap();
    assert_eq!(directory_replies, LARGE_BROWSE_FILES.div_ceil(512));

    for offset in (0..LARGE_BROWSE_FILES).step_by(512) {
        let page = registry.page(browse.search_id, offset, 512).unwrap();
        assert_eq!(page.status, PeerBrowseStatus::Complete);
        assert_eq!(page.total, LARGE_BROWSE_FILES);
        assert_eq!(page.files.len(), (LARGE_BROWSE_FILES - offset).min(512));
        let directory = format!("Shared {:04}", offset / 512 + 1);
        for (index, entry) in (offset + 1..).zip(page.files) {
            assert_eq!(entry.directory.as_deref(), Some(directory.as_str()));
            assert_eq!(
                entry.file.file_hash.0.as_slice(),
                format!("{index:016}").as_bytes()
            );
            assert_eq!(entry.file.display_name, format!("browse-{index:06}.bin"));
            assert_eq!(entry.file.file_size, BROWSE_FIXTURE_FILE_SIZE);
        }
    }
    drop(socket);
    task.await.unwrap();
}

#[tokio::test]
async fn listener_disconnects_browse_on_oversized_directory_answer() {
    use crate::ed2k_string::Ed2kStringEncoding;
    use crate::ed2k_tcp::{
        OP_ASKSHAREDDIRSANS, OP_ASKSHAREDFILESDIRANS, PeerBrowseStatus,
        codec::shared_browse::{
            PeerBrowseEncoding, PeerBrowseFile, encode_browse_dirs, encode_browse_files,
            split_browse_directory,
        },
    };

    let mut runtime = ListenerTestRuntime::new(
        "ed2k-oversized-browse-answer",
        listener_hello_identity(),
        [0x69; 16],
        0x1122_3344,
    )
    .await;
    let connection = runtime.spawn_listener_results(1);
    let peer = peer_hello_identity();
    let mut stream = connect_peer_and_exchange_hello(runtime.peer_addr, peer).await;
    let registry = runtime.transfer_runtime.peer_browse_registry();
    let endpoint = SocketAddr::new(runtime.peer_addr.ip(), peer.tcp_port);
    let browse = registry.start(Some(peer.user_hash), endpoint).unwrap();

    let valid_dir = b"Music".to_vec();
    let oversized_dir = b"Videos".to_vec();
    let file = PeerBrowseFile {
        file_hash: Ed2kHash::from_bytes([0x71; 16]),
        display_name: "valid.bin".into(),
        file_size: 42,
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_ASKSHAREDDIRS).await;
        let directories = encode_browse_dirs(&[valid_dir.clone(), oversized_dir.clone()]).unwrap();
        assert_eq!(directories[5], OP_ASKSHAREDDIRSANS);
        stream.write_all(&directories).await.unwrap();

        let request = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR).await;
        assert_eq!(split_browse_directory(&request[6..]).unwrap().0, valid_dir);
        let answer = encode_browse_files(
            std::slice::from_ref(&file),
            Some(&valid_dir),
            PeerBrowseEncoding {
                strings: Ed2kStringEncoding::Utf8,
                compact_tags: true,
                emule_family: true,
                supports_large_files: true,
                local_endpoint: None,
            },
        )
        .unwrap();
        stream.write_all(&answer).await.unwrap();

        let request = read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_ASKSHAREDFILESDIR).await;
        assert_eq!(
            split_browse_directory(&request[6..]).unwrap().0,
            oversized_dir
        );
        let interim = registry.page(browse.search_id, 0, 8).unwrap();
        assert_eq!(interim.status, PeerBrowseStatus::Pending);
        assert_eq!(interim.total, 1);

        // The length field includes the opcode. Keep the socket open and omit
        // the body so waiting for an oversized payload fails the deadline.
        let payload_len = 2_000_001_u32;
        let mut header = [OP_EDONKEYPROT, 0, 0, 0, 0, OP_ASKSHAREDFILESDIRANS];
        header[1..5].copy_from_slice(&(payload_len + 1).to_le_bytes());
        stream.write_all(&header).await.unwrap();

        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining).await.unwrap();
        let results = connection.await.unwrap();
        let error = results.into_iter().next().unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("oversized eD2k peer packet length 2000001"));
    })
    .await
    .expect("browse connection did not reject the oversized directory header");

    let page = registry.page(browse.search_id, 0, 8).unwrap();
    assert_eq!(page.status, PeerBrowseStatus::Disconnected);
    assert_eq!(page.total, 1);
    assert_eq!(page.files.len(), 1);
    assert_eq!(page.files[0].directory.as_deref(), Some("Music"));
    assert_eq!(page.files[0].file, file);
}

async fn read_next_edonkey_packet(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let packet = read_packet(stream).await;
            if packet[0] == OP_EDONKEYPROT {
                break packet;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn listener_file_status_respects_stock_large_file_capability() {
    use crate::ed2k_transfer::ED2K_LEGACY_FILE_SIZE_MAX;

    let root = unique_test_dir("ed2k-large-file-capability");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let boundary = Ed2kHash::from_bytes([0x71; 16]);
    let large = Ed2kHash::from_bytes([0x72; 16]);
    for (hash, size) in [
        (boundary, ED2K_LEGACY_FILE_SIZE_MAX),
        (large, ED2K_LEGACY_FILE_SIZE_MAX + 1),
    ] {
        let job = crate::ed2k_transfer::test_support::admit_download_job(
            &runtime,
            hash,
            "sample.bin".to_string(),
            size,
        );
        runtime.ensure_job(&job).await.unwrap();
    }

    for supports_large_files in [false, true] {
        let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
        let peer_addr = listener.local_addr().unwrap();
        let server = spawn_single_listener_connection(
            listener,
            test_dht().await,
            Arc::new(RwLock::new(Ed2kServerState::default())),
            Arc::new(Mutex::new(KadFirewallState::default())),
            listener_secure_ident(),
            Arc::clone(&runtime),
            listener_hello_identity(),
        );
        let mut hello = encode_hello_request(peer_hello_identity());
        let misc_header = [TAGTYPE_UINT32, 1, 0, CT_EMULE_MISCOPTIONS2];
        let tag_value = hello
            .windows(4)
            .position(|part| part == misc_header)
            .unwrap()
            + 4;
        assert_ne!(hello[tag_value] & 0x10, 0);
        if !supports_large_files {
            hello[tag_value] &= !0x10;
        }
        let mut stream = TcpStream::connect(peer_addr).await.unwrap();
        stream.write_all(&hello).await.unwrap();
        read_until_opcode(&mut stream, OP_EDONKEYPROT, OP_HELLOANSWER).await;

        for (hash, opcode) in [
            (boundary, OP_FILESTATUS),
            (
                large,
                if supports_large_files {
                    OP_FILESTATUS
                } else {
                    OP_FILEREQANSNOFIL
                },
            ),
        ] {
            stream
                .write_all(&encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &hash.0))
                .await
                .unwrap();
            let packet = read_next_edonkey_packet(&mut stream).await;
            assert_eq!(packet[5], opcode);
            assert_eq!(&packet[6..22], &hash.0);
        }
        drop(stream);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn listener_distinguishes_unknown_filename_and_empty_partial_status() {
    let root = unique_test_dir("ed2k-standalone-file-status");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let partial = Ed2kHash::from_bytes([0x41; 16]);
    let exact = Ed2kHash::from_bytes([0x42; 16]);
    let single = Ed2kHash::from_bytes([0x43; 16]);
    let unknown = Ed2kHash::from_bytes([0x44; 16]);
    for (hash, size) in [
        (partial, ED2K_PART_SIZE + 1),
        (exact, 2 * ED2K_PART_SIZE),
        (single, ED2K_PART_SIZE),
    ] {
        let job = crate::ed2k_transfer::test_support::admit_download_job(
            &runtime,
            hash,
            "partial.bin".to_string(),
            size,
        );
        runtime.ensure_job(&job).await.unwrap();
    }
    assert!(
        runtime
            .local_servable_entry(&exact)
            .await
            .unwrap()
            .is_none()
    );

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = spawn_single_listener_connection(
        listener,
        test_dht().await,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        Arc::new(Mutex::new(KadFirewallState::default())),
        listener_secure_ident(),
        runtime,
        listener_hello_identity(),
    );
    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_hello_identity()).await;

    stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            OP_REQUESTFILENAME,
            &unknown.0,
        ))
        .await
        .unwrap();
    for (hash, opcode, body) in [
        (partial, OP_FILESTATUS, &[2, 0, 0][..]),
        (exact, OP_FILESTATUS, &[3, 0, 0b100][..]),
        (single, OP_FILEREQANSNOFIL, &[][..]),
        (unknown, OP_FILEREQANSNOFIL, &[][..]),
    ] {
        stream
            .write_all(&encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &hash.0))
            .await
            .unwrap();
        let reply = read_next_edonkey_packet(&mut stream).await;
        assert_eq!(reply[5], opcode);
        assert_eq!(&reply[6..22], &hash.0);
        assert_eq!(&reply[22..], body);
    }

    // A rejected multipacket must not make the rejected hash the active file.
    // A subsequent end notification for that hash must leave the session live.
    let mut rejected_request = unknown.0.to_vec();
    rejected_request.push(OP_SETREQFILEID);
    stream
        .write_all(&encode_packet(
            OP_EMULEPROT,
            OP_MULTIPACKET,
            &rejected_request,
        ))
        .await
        .unwrap();
    let rejected = read_next_edonkey_packet(&mut stream).await;
    assert_eq!(rejected[5], OP_FILEREQANSNOFIL);
    assert_eq!(&rejected[6..], &unknown.0);
    stream
        .write_all(&encode_packet(
            OP_EDONKEYPROT,
            OP_END_OF_DOWNLOAD,
            &unknown.0,
        ))
        .await
        .unwrap();
    stream
        .write_all(&encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &exact.0))
        .await
        .unwrap();
    assert_eq!(
        read_next_edonkey_packet(&mut stream).await[5],
        OP_FILESTATUS
    );
    drop(stream);
    server.await.unwrap();
}

#[tokio::test]
async fn listener_admits_scattered_part_progress_for_metadata_only() {
    let root = unique_test_dir("ed2k-scattered-file-metadata");
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let hash = Ed2kHash::from_bytes([0x57; 16]);
    let last_full_block_end = ED2K_PART_SIZE - ED2K_PART_SIZE % ED2K_EMBLOCK_SIZE;
    let first_part_present = last_full_block_end - ED2K_EMBLOCK_SIZE;
    let second_part_prefix = ED2K_PART_SIZE - first_part_present;
    let size = ED2K_PART_SIZE + second_part_prefix + 1;
    let name = "scattered.bin";
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &runtime,
        hash,
        name.to_string(),
        size,
    );
    runtime.ensure_job(&job).await.unwrap();
    let bytes = vec![0x21; second_part_prefix as usize];
    let mut start = ED2K_EMBLOCK_SIZE;
    while start < last_full_block_end {
        let end = start + ED2K_EMBLOCK_SIZE;
        runtime
            .append_piece_block(
                job.token,
                0,
                start,
                end,
                &bytes[..ED2K_EMBLOCK_SIZE as usize],
            )
            .await
            .unwrap();
        start = end;
    }
    let threshold_byte = ED2K_PART_SIZE + second_part_prefix - 1;
    runtime
        .append_piece_block(
            job.token,
            1,
            ED2K_PART_SIZE,
            threshold_byte,
            &bytes[..(second_part_prefix - 1) as usize],
        )
        .await
        .unwrap();
    let manifest = runtime.manifest(job.token).await.unwrap();
    assert_eq!(manifest.pieces[1].bytes_written, second_part_prefix - 1);
    let identifier = Ed2kFileIdentifier::from_manifest(&manifest).unwrap();
    drop(manifest);

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let server = spawn_single_listener_connection(
        listener,
        test_dht().await,
        Arc::new(RwLock::new(Ed2kServerState::default())),
        Arc::new(Mutex::new(KadFirewallState::default())),
        listener_secure_ident(),
        Arc::clone(&runtime),
        listener_hello_identity(),
    );
    let mut stream = connect_peer_and_exchange_hello(peer_addr, peer_hello_identity()).await;
    let filename =
        encode_request_filename(&hash, size, FILENAME_EXTENSION_V2, [false; 2].into_iter());
    let status = encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &hash.0);

    for at_threshold in [false, true] {
        if at_threshold {
            runtime
                .append_piece_block(
                    job.token,
                    1,
                    threshold_byte,
                    threshold_byte + 1,
                    &bytes[..1],
                )
                .await
                .unwrap();
            let manifest = runtime.manifest(job.token).await.unwrap();
            assert_eq!(manifest.pieces[1].bytes_written, second_part_prefix);
            assert!(manifest.durable_present_bytes() < ED2K_PART_SIZE);
            assert!(manifest.verified_ranges.is_empty());
        }
        assert!(runtime.local_servable_entry(&hash).await.unwrap().is_none());
        stream.write_all(&filename).await.unwrap();
        if at_threshold {
            let reply = read_next_edonkey_packet(&mut stream).await;
            assert_eq!(reply[5], OP_REQFILENAMEANSWER);
            assert_eq!(&reply[6..22], &hash.0);
            assert_eq!(&reply[24..], name.as_bytes());
            stream
                .write_all(&encode_start_upload_req(&hash))
                .await
                .unwrap();
        }
        // Use the following status as a marker for filename silence below
        // threshold and upload-request silence at the threshold.
        stream.write_all(&status).await.unwrap();
        let reply = read_next_edonkey_packet(&mut stream).await;
        assert_eq!(reply[5], OP_FILESTATUS);
        assert_eq!(&reply[6..22], &hash.0);
        assert_eq!(&reply[22..], &[2, 0, 0]);

        for opcode in [OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2] {
            let mut request = Vec::new();
            if opcode == OP_MULTIPACKET_EXT2 {
                identifier.encode_into(&mut request);
            } else {
                request.extend_from_slice(&hash.0);
                if opcode == OP_MULTIPACKET_EXT {
                    request.extend_from_slice(&size.to_le_bytes());
                }
            }
            request.push(OP_SETREQFILEID);
            stream
                .write_all(&encode_packet(OP_EMULEPROT, opcode, &request))
                .await
                .unwrap();
            if !at_threshold {
                let reply = read_next_edonkey_packet(&mut stream).await;
                assert_eq!(reply[5], OP_FILEREQANSNOFIL);
                assert_eq!(&reply[6..], &hash.0);
            } else if opcode == OP_MULTIPACKET_EXT2 {
                let reply =
                    read_until_opcode(&mut stream, OP_EMULEPROT, OP_MULTIPACKETANSWER_EXT2).await;
                let (returned, remaining) = Ed2kFileIdentifier::decode(&reply[6..]).unwrap();
                assert_eq!(returned.file_hash, hash);
                assert_eq!(remaining, &[OP_FILESTATUS, 2, 0, 0]);
            } else {
                let reply =
                    read_until_opcode(&mut stream, OP_EMULEPROT, OP_MULTIPACKETANSWER).await;
                assert_eq!(&reply[6..22], &hash.0);
                assert_eq!(&reply[22..], &[OP_FILESTATUS, 2, 0, 0]);
            }
        }
    }
    drop(stream);
    server.await.unwrap();
}

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
    let packets =
        super::build_upload_part_packets(&file_hash, "movie.mp4", start, end, &payload).unwrap();
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
        assert_eq!(
            packet.packet.len(),
            6 + 16 + offset_field_bytes + bytes.len()
        );
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

    let root = unique_test_dir("ed2k-upload-listener-compressed");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &transfer_runtime,
        file_hash,
        "upload.txt".to_string(),
        payload.len() as u64,
    );
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    transfer_runtime
        .store_piece_data(job.token, 0, &payload)
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

    let manifest = transfer_runtime.manifest(job.token).await.unwrap();
    stream
        .write_all(&super::encode_request_filename(
            &file_hash,
            manifest.file_size,
            FILENAME_EXTENSION_V2,
            manifest
                .pieces
                .iter()
                .map(|piece| piece.state == Ed2kTransferState::Verified),
        ))
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

    let root = unique_test_dir("ed2k-upload-listener-oversized-range");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let job = crate::ed2k_transfer::test_support::admit_download_job(
        &transfer_runtime,
        file_hash,
        "oversized.bin".to_string(),
        file_size,
    );
    transfer_runtime.ensure_job(&job).await.unwrap();
    transfer_runtime
        .store_md4_hashset(job.token, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();
    // Only part 0 is verified; part 1 stays missing.
    transfer_runtime
        .store_piece_data(job.token, 0, &first_piece)
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
