use super::*;

#[test]
fn server_udp_endpoint_uses_obfuscation_port_when_keyed() {
    let server = test_udp_obfuscated_server();
    assert_eq!(server_udp_endpoint(&server).port(), 4675);

    let plain_server = test_server(0, SERVER_UDP_FLAG_EXT_GETSOURCES2);
    assert_eq!(server_udp_endpoint(&plain_server).port(), 4665);
}

#[test]
fn udp_keyword_search_request_uses_legacy_opcode_without_extensions() {
    let server = test_server(0, 0);
    let (opcode, payload) = encode_udp_search_request(&server, b"abc");

    assert_eq!(opcode, OP_GLOBSEARCHREQ);
    assert_eq!(payload, b"abc");
}

#[test]
fn udp_keyword_search_request_uses_ext_opcode_when_supported() {
    let server = test_server(0, SERVER_UDP_FLAG_EXT_GETFILES);
    let (opcode, payload) = encode_udp_search_request(&server, b"abc");

    assert_eq!(opcode, OP_GLOBSEARCHREQ2);
    assert_eq!(payload, b"abc");
}

#[test]
fn udp_keyword_search_request_adds_large_file_flags_when_supported() {
    let server = test_server(0, SERVER_UDP_FLAG_EXT_GETFILES | SERVER_UDP_FLAG_LARGEFILES);
    let (opcode, payload) = encode_udp_search_request(&server, b"abc");

    assert_eq!(opcode, OP_GLOBSEARCHREQ3);
    assert_eq!(&payload[..4], &1u32.to_le_bytes());
    assert!(payload.ends_with(b"abc"));
}

#[test]
fn udp_source_request_batch_encodes_legacy_hashes() {
    let server = test_server(0, SERVER_UDP_FLAG_EXT_GETSOURCES);
    let targets = [
        Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([0x11; 16]),
            file_size: 1234,
        },
        Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([0x22; 16]),
            file_size: 5678,
        },
        Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([0x33; 16]),
            file_size: 0,
        },
    ];

    let encoded = encode_udp_source_request_batch(&server, &targets).expect("encode source batch");

    assert_eq!(encoded.opcode, OP_GLOBGETSOURCES);
    assert_eq!(encoded.included_files, 3);
    assert_eq!(encoded.included_large_files, 0);
    assert_eq!(encoded.payload.len(), 48);
    assert_eq!(&encoded.payload[0..16], &[0x11; 16]);
    assert_eq!(&encoded.payload[16..32], &[0x22; 16]);
    assert_eq!(&encoded.payload[32..48], &[0x33; 16]);
}

#[test]
fn udp_source_request_batch_encodes_getsources2_sizes() {
    let server = test_server(
        0,
        SERVER_UDP_FLAG_EXT_GETSOURCES2 | SERVER_UDP_FLAG_LARGEFILES,
    );
    let large_size = u64::from(u32::MAX) + 1;
    let targets = [
        Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([0x44; 16]),
            file_size: 1234,
        },
        Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([0x55; 16]),
            file_size: large_size,
        },
    ];

    let encoded = encode_udp_source_request_batch(&server, &targets).expect("encode source batch");

    assert_eq!(encoded.opcode, OP_GLOBGETSOURCES2);
    assert_eq!(encoded.included_files, 2);
    assert_eq!(encoded.included_large_files, 1);
    assert_eq!(encoded.payload.len(), 48);
    assert_eq!(&encoded.payload[0..16], &[0x44; 16]);
    assert_eq!(
        u32::from_le_bytes(encoded.payload[16..20].try_into().unwrap()),
        1234
    );
    assert_eq!(&encoded.payload[20..36], &[0x55; 16]);
    assert_eq!(
        u32::from_le_bytes(encoded.payload[36..40].try_into().unwrap()),
        0
    );
    assert_eq!(
        u64::from_le_bytes(encoded.payload[40..48].try_into().unwrap()),
        large_size
    );
}

#[test]
fn udp_source_request_batch_matches_mfc_packet_fill_limit() {
    let server = test_server(0, SERVER_UDP_FLAG_EXT_GETSOURCES);
    let targets = (0..40)
        .map(|index| Ed2kUdpSourceRequestTarget {
            file_hash: Ed2kHash::from_bytes([index; 16]),
            file_size: 1024,
        })
        .collect::<Vec<_>>();

    let encoded = encode_udp_source_request_batch(&server, &targets).expect("encode source batch");

    assert_eq!(encoded.opcode, OP_GLOBGETSOURCES);
    assert_eq!(encoded.included_files, 32);
    assert_eq!(encoded.payload.len(), 512);
    assert_eq!(&encoded.payload[0..16], &[0; 16]);
    assert_eq!(&encoded.payload[496..512], &[31; 16]);
}

#[test]
fn server_udp_obfuscation_round_trips_plain_payload() {
    let server = test_udp_obfuscated_server();
    let (endpoint, packet) = encode_server_udp_datagram(&server, OP_GLOBGETSOURCES2, b"abc");

    assert_eq!(endpoint.port(), 4675);
    assert_ne!(packet[0], OP_EDONKEYPROT);

    let random_key_part = 0x7788u16;
    let mut response = vec![0x01];
    response.extend_from_slice(&random_key_part.to_le_bytes());
    response.extend_from_slice(&EMULE_UDP_CRYPT_MAGIC_SYNC_SERVER.to_le_bytes());
    response.push(0);
    response.extend_from_slice(&[OP_EDONKEYPROT, OP_GLOBGETSOURCES2, b'a', b'b', b'c']);
    let mut cipher = derive_server_udp_cipher(
        server.entry.udp_key,
        random_key_part,
        EMULE_UDP_CRYPT_MAGIC_SERVER_CLIENT,
    );
    cipher.apply(&mut response[3..]);

    let decoded = decode_server_udp_datagram(&server, &response).expect("decrypt packet");
    assert_eq!(
        decoded,
        [OP_EDONKEYPROT, OP_GLOBGETSOURCES2, b'a', b'b', b'c']
    );
}

#[test]
fn login_request_matches_oracle_tag_shape() {
    let payload = encode_login_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let nickname_tag_header = [
        ed2k_string_tag_type(HELLO_NICKNAME.len()),
        0x01,
        0x00,
        CT_NAME,
    ];
    let version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
    let server_flags_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_SERVER_FLAGS];
    let emule_version_tag_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

    assert_eq!(&payload[..16], &[0x11; 16]);
    assert_eq!(u16::from_le_bytes([payload[20], payload[21]]), 41001);
    assert_eq!(
        u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]),
        4
    );
    assert!(
        payload
            .windows(nickname_tag_header.len())
            .any(|window| window == nickname_tag_header)
    );
    assert!(
        payload
            .windows(version_tag_header.len())
            .any(|window| window == version_tag_header)
    );
    assert!(
        payload
            .windows(server_flags_tag_header.len())
            .any(|window| window == server_flags_tag_header)
    );
    assert!(
        payload
            .windows(emule_version_tag_header.len())
            .any(|window| window == emule_version_tag_header)
    );
    assert!(
        payload
            .windows(HELLO_NICKNAME.len())
            .any(|window| window == HELLO_NICKNAME.as_bytes())
    );
    assert!(
        payload
            .windows(4)
            .any(|window| window == EDONKEY_VERSION.to_le_bytes())
    );
    assert!(
        payload
            .windows(4)
            .any(|window| window == server_capabilities(emule_connect_options(true)).to_le_bytes())
    );
    let version =
        (EMULE_VERSION_MAJOR << 17) | (EMULE_VERSION_MINOR << 10) | (EMULE_VERSION_UPDATE << 7);
    assert!(
        payload
            .windows(4)
            .any(|window| window == version.to_le_bytes())
    );
}

#[test]
fn login_request_omits_crypt_flags_when_obfuscation_is_off() {
    let payload = encode_login_request(Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });

    assert!(payload.windows(4).any(
            |window| window == server_capabilities(emule_connect_options(false)).to_le_bytes()
        ));
    assert_eq!(
        server_capabilities(emule_connect_options(false)) & 0x0E00,
        0
    );
}

#[test]
fn login_request_matches_stock_072a_plaintext_sample() {
    let packet = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(Ed2kHelloIdentity {
            user_hash: [
                0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
                0x6F, 0x83,
            ],
            client_id: 0,
            tcp_port: 46671,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(false),
            direct_udp_callback: false,
        }),
        false,
    )
    .unwrap();

    let expected = decode(
            "e33c0000000173bec566140e7e6083c450c9af026f83000000004fb60400000015010001654d756c65030100113c0000000301002019010000030100fb00200100",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn login_request_matches_stock_072a_obfuscated_preference_sample() {
    let packet = encode_packet(
        OP_LOGINREQUEST,
        &encode_login_request(Ed2kHelloIdentity {
            user_hash: [
                0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
                0x6F, 0x83,
            ],
            client_id: 0,
            tcp_port: 46671,
            udp_port: 0,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        }),
        false,
    )
    .unwrap();

    let expected = decode(
            "e33c0000000173bec566140e7e6083c450c9af026f83000000004fb60400000015010001654d756c65030100113c0000000301002019070000030100fb00200100",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn metadata_poor_server_tries_obfuscation_when_client_supports_crypt() {
    assert!(should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(0, 0)
    ));
}

#[test]
fn metadata_known_plain_server_uses_plaintext() {
    assert!(!should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(0, SERVER_UDP_FLAG_EXT_GETSOURCES2)
    ));
}

#[test]
fn obfuscated_server_transport_suppresses_request_and_require_flags() {
    let identity = Ed2kHelloIdentity {
        user_hash: [0x33; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: 0x07,
        direct_udp_callback: false,
    };

    let login_identity = login_identity_for_server_transport(identity, true);

    assert_eq!(login_identity.connect_options, 0x01);
    assert_eq!(
        server_capabilities(login_identity.connect_options) & 0x0E00,
        0x0200
    );
}

#[test]
fn plaintext_server_transport_preserves_request_flags() {
    let identity = Ed2kHelloIdentity {
        user_hash: [0x44; 16],
        client_id: 0,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: 0,
        server_port: 0,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    };

    let login_identity = login_identity_for_server_transport(identity, false);

    assert_eq!(login_identity.connect_options, emule_connect_options(true));
}

#[test]
fn metadata_known_obfuscation_server_uses_obfuscated_transport() {
    assert!(should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(4661, SERVER_UDP_FLAG_UDPOBFUSCATION)
    ));
}

#[test]
fn obfuscation_disabled_uses_plaintext_even_with_positive_server_metadata() {
    assert!(!should_use_server_obfuscation(
        emule_connect_options(false),
        &test_server(4661, SERVER_UDP_FLAG_UDPOBFUSCATION)
    ));
}

#[test]
fn metadata_with_tcp_obfuscation_flag_uses_obfuscated_transport() {
    assert!(should_use_server_obfuscation(
        emule_connect_options(true),
        &test_server(4661, SERVER_UDP_FLAG_TCPOBFUSCATION)
    ));
}

#[test]
fn packet_encoder_uses_ed2k_framing() {
    let packet = encode_packet(OP_GETSERVERLIST, &[], false).unwrap();
    assert_eq!(packet[0], 0xE3);
    assert_eq!(
        u32::from_le_bytes([packet[1], packet[2], packet[3], packet[4]]),
        1
    );
    assert_eq!(packet[5], OP_GETSERVERLIST);
}

#[test]
fn server_state_reports_low_id_as_firewalled() {
    let mut state = Ed2kServerState::default();
    assert_eq!(state.tcp_firewalled(), None);
    state.client_id = Some(0x0000_1234);
    assert_eq!(state.tcp_firewalled(), Some(true));
    state.client_id = Some(0x7F00_0001);
    assert_eq!(state.tcp_firewalled(), Some(false));
}

#[test]
fn packed_server_payload_is_inflated() {
    let plain_payload = b"oracle-server-payload";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain_payload).unwrap();
    let packed_payload = encoder.finish().unwrap();

    let decoded = decode_server_payload(OP_PACKEDPROT, packed_payload).unwrap();

    assert_eq!(decoded, plain_payload);
}

#[test]
fn packet_encoder_uses_packed_framing_when_requested() {
    let packet = encode_packet(OP_GETSERVERLIST, &[], true).unwrap();
    assert_eq!(packet[0], OP_PACKEDPROT);
    let decoded = decode_server_payload(OP_PACKEDPROT, packet[6..].to_vec()).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(packet[5], OP_GETSERVERLIST);
}

#[test]
fn server_flag_formatter_lists_known_capabilities() {
    let text = format_server_flags(SERVER_TCP_FLAG_COMPRESSION | SERVER_TCP_FLAG_LARGEFILES);
    assert!(text.contains("compression"));
    assert!(text.contains("large_files"));
}

#[test]
fn search_probe_encoding_matches_prefix_and_shape() {
    let payload = encode_search_request("ubuntu linux").unwrap();

    assert_eq!(payload[0], 1);
    assert_eq!(u16::from_le_bytes([payload[1], payload[2]]), 12);
    assert_eq!(&payload[3..15], b"ubuntu linux");
}

#[test]
fn search_probe_encoding_preserves_boolean_query_tree_shape() {
    let payload = encode_search_request("ubuntu OR linux").unwrap();

    assert_eq!(payload[0], 0);
    assert_eq!(payload[1], 0x01);
    assert_eq!(payload[2], 1);
    assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), 6);
    assert_eq!(&payload[5..11], b"ubuntu");
    assert_eq!(payload[11], 1);
    assert_eq!(u16::from_le_bytes([payload[12], payload[13]]), 5);
    assert_eq!(&payload[14..19], b"linux");
}

#[test]
fn plaintext_server_sessions_preserve_crypt_capability_bits() {
    let identity = login_identity_for_server_transport(
        Ed2kHelloIdentity {
            user_hash: [0x33; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        false,
    );

    assert_eq!(identity.connect_options, emule_connect_options(true));
}

#[test]
fn offer_files_payload_matches_oracle_search_session_sample() {
    let shared_catalog = vec![Ed2kSharedEntry {
        file_hash: hex::encode(OFFER_FILE_SAMPLE_HASH),
        canonical_name: OFFER_FILE_SAMPLE_NAME.to_string(),
        file_size: u64::from(OFFER_FILE_SAMPLE_SIZE),
        verified_complete: false,
        verified_ranges: Vec::new(),
        compatibility_hint: true,
        source_count_hint: Some(12),
        aich_root: None,
        complete_parts: Vec::new(),
    }];
    let packet = encode_packet(
        OP_OFFERFILES,
        &encode_offer_files_payload(
            &shared_catalog,
            Some(0x521B_5895),
            Ipv4Addr::LOCALHOST,
            46671,
            Some(SERVER_TCP_FLAG_COMPRESSION),
        ),
        false,
    )
    .unwrap();

    let expected = decode(
            "e34a00000015010000009f3c23db7651efbac9a837a8a0ae3ed9fbfbfbfbfbfb0300000082011e007562756e74752d6c696e75782d6f7261636c652d73616d706c652e69736f830200002000890304",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn offer_files_payload_advertises_large_file_size_truthfully() {
    let large_size = (5u64 << 32) + 12_345;
    let shared_catalog = vec![Ed2kSharedEntry {
        file_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        canonical_name: "large-shared-file.iso".to_string(),
        file_size: large_size,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        complete_parts: Vec::new(),
    }];
    let payload = encode_offer_files_payload(
        &shared_catalog,
        Some(0x521B_5895),
        Ipv4Addr::LOCALHOST,
        46671,
        Some(SERVER_TCP_FLAG_LARGEFILES),
    );

    assert_eq!(u32::from_le_bytes(payload[0..4].try_into().unwrap()), 1);
    let tag_count_offset = 4 + 16 + 4 + 2;
    assert_eq!(
        u32::from_le_bytes(
            payload[tag_count_offset..tag_count_offset + 4]
                .try_into()
                .unwrap()
        ),
        4
    );
    assert_eq!(
        short_u32_tag_value(&payload, FT_FILESIZE),
        Some(large_size as u32)
    );
    assert_eq!(
        short_u32_tag_value(&payload, FT_FILESIZE_HI),
        Some((large_size >> 32) as u32)
    );
    assert_ne!(
        short_u32_tag_value(&payload, FT_FILESIZE),
        Some(u32::MAX),
        "large-file offers must not saturate the low size tag"
    );
}

#[test]
fn offer_files_fingerprint_changes_when_shared_catalog_changes() {
    let base_catalog = vec![Ed2kSharedEntry {
        file_hash: hex::encode(OFFER_FILE_SAMPLE_HASH),
        canonical_name: OFFER_FILE_SAMPLE_NAME.to_string(),
        file_size: u64::from(OFFER_FILE_SAMPLE_SIZE),
        verified_complete: false,
        verified_ranges: Vec::new(),
        compatibility_hint: true,
        source_count_hint: Some(12),
        aich_root: None,
        complete_parts: Vec::new(),
    }];
    let mut expanded_catalog = base_catalog.clone();
    expanded_catalog.push(Ed2kSharedEntry {
        file_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        canonical_name: "new-shared-file.bin".to_string(),
        file_size: 42_000,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        complete_parts: Vec::new(),
    });

    assert_ne!(
        offer_files_catalog_fingerprint(&base_catalog),
        offer_files_catalog_fingerprint(&expanded_catalog)
    );
}

fn short_u32_tag_value(payload: &[u8], tag_name: u8) -> Option<u32> {
    let header = [TAG_SHORT_NAME_MASK | TAGTYPE_UINT32, tag_name];
    let offset = payload
        .windows(header.len())
        .position(|window| window == header)?;
    let value = payload.get(offset + header.len()..offset + header.len() + 4)?;
    Some(u32::from_le_bytes(value.try_into().unwrap()))
}

#[test]
fn source_request_encoding_includes_u32_size_for_small_files() {
    let payload = encode_source_request(Ed2kHash([0xAB; 16]), 734_003_200);

    assert_eq!(&payload[..16], &[0xAB; 16]);
    assert_eq!(
        u32::from_le_bytes(payload[16..20].try_into().unwrap()),
        734_003_200
    );
    assert_eq!(payload.len(), 20);
}

#[test]
fn source_request_encoding_uses_hash_only_shape_when_size_is_unknown() {
    let payload = encode_source_request(Ed2kHash([0xEF; 16]), 0);

    assert_eq!(payload, vec![0xEF; 16]);
}

#[test]
fn source_request_encoding_uses_large_file_sentinel() {
    let payload = encode_source_request(Ed2kHash([0xCD; 16]), 4_294_967_301);

    assert_eq!(&payload[..16], &[0xCD; 16]);
    assert_eq!(u32::from_le_bytes(payload[16..20].try_into().unwrap()), 0);
    assert_eq!(
        u64::from_le_bytes(payload[20..28].try_into().unwrap()),
        4_294_967_301
    );
}

#[test]
fn source_request_opcode_uses_obfuscated_variant_when_supported() {
    assert_eq!(
        source_request_opcode(0x01, Some(SERVER_TCP_FLAG_TCPOBFUSCATION)),
        OP_GETSOURCES_OBFU
    );
    assert_eq!(
        source_request_opcode(0x00, Some(SERVER_TCP_FLAG_TCPOBFUSCATION)),
        OP_GETSOURCES
    );
    assert_eq!(source_request_opcode(0x01, Some(0)), OP_GETSOURCES);
}
