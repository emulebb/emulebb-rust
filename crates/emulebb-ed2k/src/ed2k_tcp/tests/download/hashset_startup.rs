use super::*;

#[tokio::test]
async fn large_file_download_starts_hashset_flow_before_peer_secure_ident_key_arrives() {
    run_hashset_startup_case(StartupAichCase::Advertised).await;
}

#[tokio::test]
async fn consistent_unrelated_peer_aich_tree_cannot_become_download_identity() {
    run_hashset_startup_case(StartupAichCase::Unrelated).await;
}

#[tokio::test]
async fn trusted_operator_master_allows_a_matching_modern_part_set() {
    run_hashset_startup_case(StartupAichCase::Operator).await;
}

#[tokio::test]
async fn trusted_master_allows_aich_only_acquisition_after_md4_is_known() {
    run_hashset_startup_case(StartupAichCase::OperatorWithMd4).await;
}

#[tokio::test]
async fn current_consensus_master_allows_a_matching_modern_part_set() {
    run_hashset_startup_case(StartupAichCase::NetworkConsensus).await;
}

#[tokio::test]
async fn late_modern_aich_answer_cannot_cross_a_consensus_aba_generation() {
    run_hashset_startup_case(StartupAichCase::ConsensusAba).await;
}

enum StartupAichCase {
    Advertised,
    Unrelated,
    Operator,
    OperatorWithMd4,
    NetworkConsensus,
    ConsensusAba,
}

async fn run_hashset_startup_case(case: StartupAichCase) {
    let unrelated_aich_tree = matches!(case, StartupAichCase::Unrelated);
    let operator_root = matches!(
        case,
        StartupAichCase::Operator | StartupAichCase::OperatorWithMd4
    );
    let consensus_root = matches!(
        case,
        StartupAichCase::NetworkConsensus | StartupAichCase::ConsensusAba
    );
    let late_aich_answer = matches!(case, StartupAichCase::ConsensusAba);
    let trusted_root = operator_root || consensus_root;
    let md4_preseeded = matches!(case, StartupAichCase::OperatorWithMd4);
    let root = unique_test_dir("ed2k-large-file-secure-ident-order");
    let transfer_runtime = Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let payload = vec![0x5A; (ED2K_PART_SIZE as usize) + 32_768];
    let md4_hashset = payload
        .chunks(ED2K_PART_SIZE as usize)
        .map(|chunk| Md4::digest(chunk).into())
        .collect::<Vec<[u8; 16]>>();
    let file_hash = emulebb_kad_proto::Ed2kHash::from_bytes(
        Md4::digest(md4_hashset.iter().flatten().copied().collect::<Vec<u8>>()).into(),
    );
    let file_hash_hex = file_hash.to_string();
    transfer_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    let source_root = unique_test_dir("ed2k-large-file-secure-ident-order-source");
    let source_runtime = Ed2kTransferRuntime::load_or_create(&source_root).unwrap();
    source_runtime
        .ensure_job(&new_transfer_job(
            file_hash,
            "captured.iso".to_string(),
            payload.len() as u64,
        ))
        .await
        .unwrap();
    source_runtime
        .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 0, &payload[..ED2K_PART_SIZE as usize])
        .await
        .unwrap();
    source_runtime
        .store_piece_data(&file_hash_hex, 1, &payload[ED2K_PART_SIZE as usize..])
        .await
        .unwrap();
    let mut source_aich = source_runtime
        .aich_hashset(&file_hash)
        .await
        .unwrap()
        .expect("missing source AICH hashset");
    if unrelated_aich_tree {
        // A mathematically valid two-part tree unrelated to the MD4-identified
        // payload. It must not authorize salvage or survive local completion.
        source_aich.part_hashes = vec![[0x21; 20], [0x43; 20]];
        source_aich.master_hash = sha1::Sha1::digest(
            source_aich
                .part_hashes
                .iter()
                .flatten()
                .copied()
                .collect::<Vec<_>>(),
        )
        .into();
    }
    let advertised_root = source_aich.master_hash;
    if operator_root {
        transfer_runtime
            .reconcile_aich_root(&file_hash_hex, Some(advertised_root))
            .await
            .unwrap();
    } else if consensus_root {
        let observations = (0..10)
            .map(|signer| {
                (
                    advertised_root,
                    IpAddr::V4(std::net::Ipv4Addr::new(203, signer, 0, 1)),
                )
            })
            .collect::<Vec<_>>();
        transfer_runtime
            .record_network_aich_observations(&file_hash_hex, &observations)
            .await
            .unwrap();
    }
    if md4_preseeded {
        transfer_runtime
            .store_md4_hashset(&file_hash_hex, md4_hashset.clone())
            .await
            .unwrap();
    }
    let source_identifier = super::Ed2kFileIdentifier {
        file_hash,
        file_size: Some(payload.len() as u64),
        aich_root: Some(source_aich.master_hash),
    };

    let listener = TcpListener::bind((test_bind_ip(), 0)).await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let payload_for_server = payload.clone();
    let observed_runtime = Arc::clone(&transfer_runtime);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let hello = read_packet(&mut stream).await;
        assert_eq!(hello[0], OP_EDONKEYPROT);
        assert_eq!(hello[5], OP_HELLO);

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

        let secure_ident_probe = read_packet(&mut stream).await;
        assert_eq!(secure_ident_probe[0], OP_EMULEPROT);
        assert_eq!(secure_ident_probe[5], OP_SECIDENTSTATE);

        let peer_challenge =
            encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436_EEAC);
        stream.write_all(&peer_challenge).await.unwrap();

        let startup_request = read_packet(&mut stream).await;
        assert_startup_multipacket_ext2(
            startup_request[0],
            startup_request[5],
            &startup_request[6..],
            &file_hash,
            payload_for_server.len() as u64,
            true,
        );

        let startup_answer = encode_startup_multipacket_ext2_answer_with_identifier(
            &source_identifier,
            "captured-fallback.iso",
            true,
        );
        stream.write_all(&startup_answer).await.unwrap();

        let public_key = read_packet(&mut stream).await;
        assert_eq!(public_key[0], OP_EMULEPROT);
        assert_eq!(public_key[5], super::OP_PUBLICKEY);

        let hashset_request = read_packet(&mut stream).await;
        assert_eq!(hashset_request[0], OP_EMULEPROT);
        assert_eq!(hashset_request[5], super::OP_HASHSETREQUEST2);
        let (requested_identifier, request_options) =
            super::decode_hashset_request2(&hashset_request[6..]).unwrap();
        assert_eq!(requested_identifier.file_hash, file_hash);
        assert_eq!(
            requested_identifier.file_size,
            Some(payload_for_server.len() as u64)
        );
        assert_eq!(request_options.request_md4, !md4_preseeded);
        assert_eq!(request_options.request_aich, trusted_root);

        let mut expected_generation = None;
        if consensus_root {
            let requested = observed_runtime
                .manifest(&file_hash.to_string())
                .await
                .unwrap();
            assert_eq!(requested.aich_root, Some(hex::encode(advertised_root)));
            assert_eq!(
                requested.aich_root_origin,
                Some(crate::ed2k_transfer::Ed2kAichRootOrigin::NetworkConsensus)
            );
            expected_generation = Some(requested.aich_trust_generation);
            if late_aich_answer {
                // WHY: receiving the real request is the causal barrier. Retire
                // its generation before sending its otherwise matching answer;
                // returning to the same master prevents a root mismatch from
                // accidentally testing the wrong response-admission boundary.
                let mut dissenting_root = advertised_root;
                dissenting_root[0] ^= 0x80;
                let demoted = observed_runtime
                    .record_network_aich_root(
                        &file_hash.to_string(),
                        Some(dissenting_root),
                        IpAddr::V4(std::net::Ipv4Addr::new(198, 0, 0, 1)),
                    )
                    .await
                    .unwrap();
                assert!(demoted.aich_root.is_none());
                assert!(demoted.aich_trust_generation > requested.aich_trust_generation);
                let renewed = observed_runtime
                    .record_network_aich_observations(
                        &file_hash.to_string(),
                        &[10, 11].map(|signer| {
                            (
                                advertised_root,
                                IpAddr::V4(std::net::Ipv4Addr::new(203, signer, 0, 1)),
                            )
                        }),
                    )
                    .await
                    .unwrap();
                assert_eq!(renewed.aich_root, requested.aich_root);
                assert_eq!(renewed.aich_root_origin, requested.aich_root_origin);
                assert!(renewed.aich_trust_generation > demoted.aich_trust_generation);
                assert!(!renewed.aich_hashset_acquired);
                expected_generation = Some(renewed.aich_trust_generation);
            }
        }

        let hashset_answer = super::encode_hashset_answer2(
            &source_identifier,
            (!md4_preseeded).then_some(md4_hashset.as_slice()),
            Some(&source_aich),
        )
        .unwrap();
        stream.write_all(&hashset_answer).await.unwrap();

        let start_upload = read_packet(&mut stream).await;
        assert_eq!(start_upload[0], OP_EDONKEYPROT);
        assert_eq!(start_upload[5], super::OP_STARTUPLOADREQ);
        assert_eq!(&start_upload[6..22], &file_hash.0);

        // Observe before supplying any payload: a later local completion pass
        // must not hide the single-peer acquisition bypass.
        let before_payload = observed_runtime
            .manifest(&file_hash.to_string())
            .await
            .unwrap();
        assert!(before_payload.md4_hashset_acquired);
        if trusted_root {
            assert_eq!(before_payload.aich_root, Some(hex::encode(advertised_root)));
            assert_eq!(before_payload.aich_hashset_acquired, !late_aich_answer);
            assert_eq!(before_payload.aich_hashset.is_empty(), late_aich_answer);
            if let Some(generation) = expected_generation {
                assert_eq!(before_payload.aich_trust_generation, generation);
                assert_eq!(
                    before_payload.aich_root_origin,
                    Some(crate::ed2k_transfer::Ed2kAichRootOrigin::NetworkConsensus)
                );
            }
        } else {
            assert!(before_payload.aich_root.is_none());
            assert!(!before_payload.aich_hashset_acquired);
            assert!(before_payload.aich_hashset.is_empty());
        }

        let accept = encode_accept_upload_req();
        stream.write_all(&accept).await.unwrap();

        let request_parts = read_packet(&mut stream).await;
        let request_uses_i64 = request_parts[5] == super::OP_REQUESTPARTS_I64;
        if request_uses_i64 {
            assert_eq!(request_parts[0], OP_EMULEPROT);
        } else {
            assert_eq!(request_parts[0], OP_EDONKEYPROT);
            assert_eq!(request_parts[5], super::OP_REQUESTPARTS);
        }
        let (requested_hash, ranges) =
            decode_request_parts_payload(&request_parts[6..], request_uses_i64).unwrap();
        assert_eq!(requested_hash, file_hash);
        assert_eq!(
            ranges,
            vec![(
                0,
                super::ED2K_EMBLOCK_SIZE.min(payload_for_server.len() as u64)
            )]
        );

        let mut expected_start = 0u64;
        for (start, end) in ranges {
            assert_eq!(start, expected_start);
            let start_index = usize::try_from(start).unwrap();
            let end_index = usize::try_from(end).unwrap();
            let sending_part = encode_sending_part(
                &file_hash,
                start,
                end,
                &payload_for_server[start_index..end_index],
                request_uses_i64,
            )
            .unwrap();
            stream.write_all(&sending_part).await.unwrap();
            expected_start = end;
        }
        while expected_start < payload_for_server.len() as u64 {
            let next_request_parts = read_packet(&mut stream).await;
            let next_request_uses_i64 = next_request_parts[5] == super::OP_REQUESTPARTS_I64;
            if next_request_uses_i64 {
                assert_eq!(next_request_parts[0], OP_EMULEPROT);
            } else {
                assert_eq!(next_request_parts[0], OP_EDONKEYPROT);
                assert_eq!(next_request_parts[5], super::OP_REQUESTPARTS);
            }
            let (next_requested_hash, next_ranges) =
                decode_request_parts_payload(&next_request_parts[6..], next_request_uses_i64)
                    .unwrap();
            assert_eq!(next_requested_hash, file_hash);
            assert!(!next_ranges.is_empty());
            for (start, end) in next_ranges {
                assert_eq!(start, expected_start);
                let start_index = usize::try_from(start).unwrap();
                let end_index = usize::try_from(end).unwrap();
                let sending_part = encode_sending_part(
                    &file_hash,
                    start,
                    end,
                    &payload_for_server[start_index..end_index],
                    next_request_uses_i64,
                )
                .unwrap();
                stream.write_all(&sending_part).await.unwrap();
                expected_start = end;
            }
        }
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
        "captured.iso".to_string(),
        payload.len() as u64,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    assert_eq!(result, Ed2kPeerDownloadOutcome::Completed);

    let manifest = transfer_runtime.manifest(&file_hash_hex).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(
        manifest.aich_root_origin,
        Some(crate::ed2k_transfer::Ed2kAichRootOrigin::LocalComputed)
    );
    assert_eq!(manifest.aich_hashset.len(), 2);
    if unrelated_aich_tree {
        assert_ne!(manifest.aich_root, Some(hex::encode(advertised_root)));
    }
    server.await.unwrap();
}
