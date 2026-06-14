use super::*;

#[test]
fn hello_request_encoding_matches_ed2k_framing() {
    let packet = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLO);
    assert_eq!(packet[6], 16);
    assert_eq!(&packet[7..23], &[0x11; 16]);
    assert_eq!(u16::from_le_bytes([packet[27], packet[28]]), 41001);
    assert!(u32::from_le_bytes([packet[29], packet[30], packet[31], packet[32]]) >= 6);
    assert!(
        packet
            .windows(4)
            .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
    );
}

#[test]
fn hello_answer_advertises_emule_style_tags() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });
    let expected_name_header = [
        ed2k_string_tag_type(HELLO_NICKNAME.len()),
        0x01,
        0x00,
        CT_NAME,
    ];
    let expected_u32_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_VERSION];
    let expected_udp_ports_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_UDPPORTS];
    let expected_misc1_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS1];
    let expected_misc2_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_MISCOPTIONS2];
    let expected_emule_version_header = [TAGTYPE_UINT32, 0x01, 0x00, CT_EMULE_VERSION];

    assert_eq!(packet[0], OP_EDONKEYPROT);
    assert_eq!(packet[5], OP_HELLOANSWER);
    assert_eq!(&packet[6..22], &[0x22; 16]);
    assert_eq!(
        u32::from_le_bytes([packet[22], packet[23], packet[24], packet[25]]),
        0x521B_5895
    );
    assert_eq!(
        u32::from_le_bytes([packet[28], packet[29], packet[30], packet[31]]),
        6
    );
    assert!(
        packet
            .windows(expected_name_header.len())
            .any(|window| window == expected_name_header)
    );
    assert!(
        packet
            .windows(expected_u32_version_header.len())
            .any(|window| window == expected_u32_version_header)
    );
    assert!(
        packet
            .windows(expected_udp_ports_header.len())
            .any(|window| window == expected_udp_ports_header)
    );
    assert!(
        packet
            .windows(expected_misc1_header.len())
            .any(|window| window == expected_misc1_header)
    );
    assert!(
        packet
            .windows(expected_misc2_header.len())
            .any(|window| window == expected_misc2_header)
    );
    assert!(
        packet
            .windows(expected_emule_version_header.len())
            .any(|window| window == expected_emule_version_header)
    );
    assert!(
        packet
            .windows(HELLO_NICKNAME.len())
            .any(|window| window == HELLO_NICKNAME.as_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == EDONKEY_VERSION.to_le_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == ((41000u32 << 16) | 41000u32).to_le_bytes())
    );
    assert!(
        packet
            .windows(4)
            .any(|window| window == emule_misc_options1().to_le_bytes())
    );
    assert!(packet.windows(4).any(|window| {
        window == emule_misc_options2(emule_connect_options(true), false).to_le_bytes()
    }));
    assert!(
        packet
            .windows(4)
            .any(|window| window == emule_version_tag().to_le_bytes())
    );
    assert_eq!(
        u32::from_le_bytes([
            packet[packet.len() - 6],
            packet[packet.len() - 5],
            packet[packet.len() - 4],
            packet[packet.len() - 3]
        ]),
        u32::from_le_bytes([176, 123, 2, 239])
    );
    assert_eq!(
        u16::from_le_bytes([packet[packet.len() - 2], packet[packet.len() - 1]]),
        4232
    );
}

#[test]
fn hello_decode_preserves_multipacket_capabilities() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x22; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });

    let profile = decode_hello_profile(&packet[6..]).unwrap();

    assert!(profile.supports_aich);
    assert!(profile.supports_secure_ident);
    assert!(profile.supports_multipacket);
    assert!(profile.supports_ext_multipacket);
    assert_eq!(profile.source_exchange_version, 4);
    assert!(profile.supports_source_exchange);
    assert!(profile.supports_source_exchange2);
    assert!(profile.supports_file_identifiers);
    // The peer's eD2k UDP port is recovered from CT_EMULE_UDPPORTS (low 16 bits)
    // for (ip, udp_port) reask correlation.
    assert_eq!(profile.identity.udp_port, 41000);
}

#[test]
fn hello_answer_decode_keeps_user_hash_leading_type_byte() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [0x10; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });

    let profile = decode_hello_answer_profile(&packet[6..]).unwrap();

    assert_eq!(profile.identity.user_hash, [0x10; 16]);
    assert!(profile.supports_secure_ident);
}

#[test]
fn hello_misc_options2_does_not_advertise_unsupported_chat_captcha() {
    let misc_options2 = emule_misc_options2(emule_connect_options(false), false);

    assert_eq!(
        (misc_options2 >> 13) & 1,
        1,
        "file identifiers are implemented"
    );
    assert_eq!(
        (misc_options2 >> 11) & 1,
        0,
        "chat/captcha is not implemented"
    );
    assert_eq!(
        (misc_options2 >> 10) & 1,
        1,
        "source exchange 2 is implemented"
    );
}

#[test]
fn hello_misc_options1_advertises_stock_comments_but_not_preview() {
    let misc_options1 = emule_misc_options1();

    assert_eq!((misc_options1 >> 29) & 0x7, 1, "AICH is implemented");
    assert_eq!(
        (misc_options1 >> 12) & 0x0F,
        4,
        "source exchange is implemented"
    );
    assert_eq!(
        (misc_options1 >> 4) & 0x0F,
        1,
        "stock comment/rating acceptance is advertised"
    );
    assert_eq!(
        (misc_options1 >> 3) & 1,
        0,
        "defunct PeerCache is not advertised"
    );
    assert_eq!(
        (misc_options1 >> 2) & 1,
        1,
        "shared-file browsing is disabled"
    );
    assert_eq!(misc_options1 & 1, 0, "preview is not implemented");
}

#[test]
fn hello_answer_matches_truthful_plaintext_profile() {
    let packet = encode_hello_answer(Ed2kHelloIdentity {
        user_hash: [
            0x73, 0xBE, 0xC5, 0x66, 0x14, 0x0E, 0x7E, 0x60, 0x83, 0xC4, 0x50, 0xC9, 0xAF, 0x02,
            0x6F, 0x83,
        ],
        client_id: 0x521B_5895,
        tcp_port: 46671,
        udp_port: 46673,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(false),
        direct_udp_callback: false,
    });

    let expected = decode(
            "e3520000004c73bec566140e7e6083c450c9af026f8395581b524fb60600000015010001654d756c65030100113c000000030100f951b651b6030100fa16421334030100fe3a240000030100fb00200100b07b02ef8810",
        )
        .unwrap();

    assert_eq!(packet, expected);
}

#[test]
fn emule_info_request_uses_expected_protocol_and_tag_count() {
    let packet = encode_emule_info_request(41000);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_EMULEINFO);
    assert_eq!(packet[6], EMULE_VERSION_SHORT);
    assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
    assert_eq!(
        u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
        7
    );
}

#[test]
fn emule_info_advertises_stock_comments_but_not_preview() {
    let packet = encode_emule_info_answer(41000);

    assert_eq!(emule_info_u32_tag(&packet, ET_COMMENTS), Some(1));
    assert_eq!(
        emule_info_u32_tag(&packet, ET_FEATURES),
        Some(EMULE_INFO_FEATURES)
    );
    assert_eq!(
        EMULE_INFO_FEATURES & 0x03,
        0x03,
        "secure ident is implemented"
    );
    assert_eq!(
        (EMULE_INFO_FEATURES >> 7) & 1,
        0,
        "preview is not implemented"
    );
}

#[test]
fn emule_info_decode_preserves_stock_capability_tags() {
    let packet = encode_emule_info_request(41000);
    let profile = decode_emule_info_profile(&packet[6..]).unwrap();

    assert_eq!(profile.data_compression_version, 1);
    assert_eq!(profile.udp_version, 4);
    assert_eq!(profile.udp_port, 41000);
    assert_eq!(profile.source_exchange_version, 3);
    assert!(profile.supports_source_exchange);
    assert_eq!(profile.extended_requests_version, 2);
    assert!(profile.accepts_comments);
    assert!(profile.supports_secure_ident);
    assert!(!profile.supports_preview);
}

#[test]
fn emule_info_answer_uses_expected_protocol_and_tag_count() {
    let packet = encode_emule_info_answer(41000);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_EMULEINFOANSWER);
    assert_eq!(packet[6], EMULE_VERSION_SHORT);
    assert_eq!(packet[7], EMULE_PROTOCOL_VERSION);
    assert_eq!(
        u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]),
        7
    );
}

fn emule_info_u32_tag(packet: &[u8], name: u8) -> Option<u32> {
    let header = [TAGTYPE_UINT32, 0x01, 0x00, name];
    let offset = packet
        .windows(header.len())
        .position(|window| window == header)?;
    let value = packet.get(offset + header.len()..offset + header.len() + 4)?;
    Some(u32::from_le_bytes(value.try_into().unwrap()))
}

#[test]
fn encoded_hello_request_is_detected_as_mule_hello() {
    let packet = encode_hello_request(Ed2kHelloIdentity {
        user_hash: [0x11; 16],
        client_id: 0x521B_5895,
        tcp_port: 41001,
        udp_port: 41000,
        server_ip: u32::from_le_bytes([176, 123, 2, 239]),
        server_port: 4232,
        connect_options: emule_connect_options(true),
        direct_udp_callback: false,
    });

    assert!(is_mule_hello(&packet[6..]).unwrap());
}

#[test]
fn oracle_server_callback_hello_is_detected_as_non_mule() {
    let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();

    assert!(!is_mule_hello(&payload).unwrap());
}

#[test]
fn non_mule_hello_replies_with_emule_info_then_helloanswer() {
    let payload = decode(
            "105d0e3efaf60e650d1f6f873e19326f635e67bc8236120200000097016553657276657289113c000000000000",
        )
        .unwrap();
    let replies = build_hello_responses(
        &payload,
        Ed2kHelloIdentity {
            user_hash: [0x22; 16],
            client_id: 0x521B_5895,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: u32::from_le_bytes([176, 123, 2, 239]),
            server_port: 4232,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
    )
    .unwrap();

    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0][0], OP_EMULEPROT);
    assert_eq!(replies[0][5], OP_EMULEINFO);
    assert_eq!(replies[1][0], OP_EDONKEYPROT);
    assert_eq!(replies[1][5], OP_HELLOANSWER);
}

#[test]
fn connect_options_request_and_support_crypt_layer() {
    assert_eq!(
        emule_connect_options(true),
        EMULE_CRYPT_SUPPORTS | EMULE_CRYPT_REQUESTS
    );
}

#[test]
fn connect_options_disable_crypt_layer_when_obfuscation_is_off() {
    assert_eq!(emule_connect_options(false), 0);
}

#[tokio::test]
async fn enrich_hello_identity_sets_direct_udp_callback_for_low_id_with_verified_udp() {
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
        client_id: Some(0x0000_1234),
        ..Ed2kServerState::default()
    }));
    let mut firewall = KadFirewallState::default();
    firewall.udp_open = true;
    firewall.udp_verified = true;
    let kad_firewall = Arc::new(Mutex::new(firewall));

    let identity = enrich_hello_identity(
        Ed2kHelloIdentity {
            user_hash: [0xAB; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        &server_state,
        &kad_firewall,
    )
    .await;

    assert!(identity.direct_udp_callback);
    assert_eq!(identity.client_id, 0x0000_1234);
    assert_eq!(identity.server_ip, u32::from_le_bytes([185, 237, 185, 226]));
    assert_eq!(identity.server_port, 31031);
}

#[tokio::test]
async fn enrich_hello_identity_keeps_direct_udp_callback_off_for_high_id() {
    let server_state = Arc::new(RwLock::new(Ed2kServerState {
        endpoint: Some(SocketAddr::from((Ipv4Addr::new(185, 237, 185, 226), 31031))),
        client_id: Some(0x521B_5895),
        ..Ed2kServerState::default()
    }));
    let mut firewall = KadFirewallState::default();
    firewall.udp_open = true;
    firewall.udp_verified = true;
    let kad_firewall = Arc::new(Mutex::new(firewall));

    let identity = enrich_hello_identity(
        Ed2kHelloIdentity {
            user_hash: [0xCD; 16],
            client_id: 0,
            tcp_port: 41001,
            udp_port: 41000,
            server_ip: 0,
            server_port: 0,
            connect_options: emule_connect_options(true),
            direct_udp_callback: false,
        },
        &server_state,
        &kad_firewall,
    )
    .await;

    assert!(!identity.direct_udp_callback);
    assert_eq!(identity.client_id, 0x521B_5895);
}
