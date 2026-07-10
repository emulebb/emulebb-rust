use super::*;

#[test]
fn source_type_switches_to_large_file_variant_at_old_max_emule_file_size() {
    // Oracle IsLargeFile(): strictly greater than OLD_MAX_EMULE_FILE_SIZE
    // (4290048000), not the raw u32 ceiling.
    assert_eq!(emule_high_id_source_type(4_290_048_000), 1);
    assert_eq!(emule_high_id_source_type(4_290_048_001), 4);
}

#[test]
fn source_publish_tags_match_oracle_open_shape() {
    // Oracle non-firewalled STOREFILE branch (Search.cpp:732-743):
    // SOURCETYPE, SOURCEPORT, SOURCEUPORT, FILESIZE, ENCRYPTION — and no
    // SOURCEIP tag (indexers take the IP from the datagram sender).
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
        SourcePublishReachability::Open,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_set_obfuscated_encryption_bits() {
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
        SourcePublishReachability::Open,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)))
    );
}

#[test]
fn source_publish_tags_match_oracle_buddy_relay_shape() {
    // Oracle firewalled-with-buddy STOREFILE branch (Search.cpp:717-730):
    // SOURCETYPE 3 (uint8), SERVERIP = buddy in_addr DWORD, SERVERPORT =
    // buddy Kad UDP port, BUDDYHASH = uppercase hex of ~KadID in wire
    // order, then the common tail.
    let own_id = NodeId::from_bytes([0xF0; 16]);
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        2_097_152,
        SourcePublishReachability::BuddyRelay {
            buddy_ip: "198.51.100.136".parse().unwrap(),
            buddy_kad_port: 4672,
        },
        own_id,
    );

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(3)),
            Tag::new_short(tag_name::SERVERIP, TagValue::UInt(0x8864_33C6)),
            Tag::new_short(tag_name::SERVERPORT, TagValue::UInt(4672)),
            Tag::new_short(
                tag_name::BUDDYHASH,
                TagValue::String("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F".to_string()),
            ),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41001)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::filesize(2_097_152),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0)),
        ]
    );
}

#[test]
fn source_publish_tags_buddy_relay_uses_large_file_type_5() {
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: false,
        },
        EMULE_LARGE_FILE_SIZE_THRESHOLD + 1,
        SourcePublishReachability::BuddyRelay {
            buddy_ip: "198.51.100.136".parse().unwrap(),
            buddy_kad_port: 4672,
        },
        NodeId::from_bytes([0xF0; 16]),
    );

    assert_eq!(
        tags.first(),
        Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::U8(5)))
    );
}

#[test]
fn source_publish_tags_direct_callback_sets_type_6_and_callback_bit() {
    // Oracle direct-callback STOREFILE branch (Search.cpp:708-715) +
    // GetMyConnectOptions(true, true): type 6 with connect options bit 3.
    let tags = build_source_publish_tags(
        41000,
        SourcePublishSettings {
            tcp_port: 41001,
            obfuscation_enabled: true,
        },
        2_097_152,
        SourcePublishReachability::DirectUdpCallback,
        NodeId::from_bytes([0x11; 16]),
    );

    assert_eq!(
        tags.first(),
        Some(&Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(6)))
    );
    assert_eq!(
        tags.last(),
        Some(&Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(0x0B)))
    );
}

#[test]
fn kad_hello_request_tags_advertise_source_udp_port_when_verified_open() {
    let tags = build_kad_hello_request_tags(41000, true, false, false, false, KAD_VERSION);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
}

#[test]
fn kad_hello_request_tags_emit_source_port_and_misc_bits_additively() {
    // Oracle SendMyDetails writes SOURCEUPORT (intern port) AND KADMISCOPTIONS
    // (firewalled/ack) together, not one or the other.
    let tags = build_kad_hello_request_tags(41000, true, true, false, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05)),
        ]
    );
}

#[test]
fn kad_hello_tags_omit_misc_options_toward_pre_v8_contacts() {
    // Oracle SendMyDetails only writes (and counts) TAG_KADMISCOPTIONS when
    // byKadVersion >= KADEMLIA_VERSION8_49b. A v7 (or older) contact that
    // would otherwise get the ACK/firewall bits receives SOURCEUPORT only;
    // it is IP-verified via a PING / legacy challenge instead.
    for build in [
        build_kad_hello_request_tags as fn(u16, bool, bool, bool, bool, u8) -> Vec<Tag>,
        build_kad_hello_response_tags,
    ] {
        assert_eq!(
            build(41000, true, true, true, true, 7),
            vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))],
            "pre-v8 contact must not receive KADMISCOPTIONS"
        );
        // v8 exactly is the first version that receives it.
        assert!(
            build(41000, true, true, true, true, 8)
                .iter()
                .any(|tag| tag.name == emulebb_kad_proto::TagName::Short(tag_name::KADMISCOPTIONS))
        );
    }
}

#[test]
fn kad_publish_tolerance_gate_matches_oracle_distance_and_lan_exemption() {
    use std::net::Ipv4Addr;
    let own = NodeId::ZERO;

    // Close target (chunk0 distance well under SEARCHTOLERANCE) -> accepted.
    let close = NodeId::from_be_bytes([0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(kad_publish_within_tolerance(
        own,
        close,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));

    // Far target (chunk0 distance > SEARCHTOLERANCE) from a public IP -> dropped.
    let far = NodeId::from_be_bytes([0x7F, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert!(!kad_publish_within_tolerance(
        own,
        far,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
    ));

    // The same far target from a LAN IP is exempt -> accepted.
    assert!(kad_publish_within_tolerance(
        own,
        far,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))
    ));
}

#[test]
fn kad_req_masks_type_to_low_five_bits_and_rejects_zero() {
    // Oracle: byType &= 0x1F; throw on 0.
    assert_eq!(kad_req_masked_count(0x00), None);
    assert_eq!(kad_req_masked_count(0x20), None); // high bits only -> 0
    assert_eq!(kad_req_masked_count(0x02), Some(2));
    assert_eq!(kad_req_masked_count(0xE2), Some(2)); // high bits masked off
    assert_eq!(kad_req_masked_count(0x1F), Some(0x1F));
}

#[test]
fn hello_res_ack_requested_only_when_added_and_key_unverified() {
    // Oracle: SendMyDetails(..., bAddedOrUpdated && !bValidReceiverKey).
    assert!(should_request_hello_res_ack(true, false));
    assert!(!should_request_hello_res_ack(true, true));
    assert!(!should_request_hello_res_ack(false, false));
    assert!(!should_request_hello_res_ack(false, true));
}

#[test]
fn kad_hello_request_tags_emit_only_misc_bits_when_on_extern_port() {
    // When we advertise our extern Kad port (GetUseExternKadPort), the oracle
    // omits SOURCEUPORT but still emits KADMISCOPTIONS while firewalled.
    let tags = build_kad_hello_request_tags(41000, false, true, false, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
    );
}

#[test]
fn kad_hello_response_tags_include_source_udp_port_and_misc_bits() {
    let tags = build_kad_hello_response_tags(41000, true, true, true, true, KAD_VERSION);

    assert_eq!(
        tags,
        vec![
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000)),
            Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x07)),
        ]
    );
}

#[test]
fn kad_hello_response_tags_gate_both_tags_like_request_and_oracle() {
    // Oracle SendMyDetails gates HELLO_RES tags as HELLO_REQ: SOURCEUPORT
    // only when advertising the intern port; KADMISCOPTIONS only on ACK/fw.
    assert!(
        build_kad_hello_response_tags(41000, false, false, false, false, KAD_VERSION).is_empty()
    );
    assert_eq!(
        build_kad_hello_response_tags(41000, true, false, false, false, KAD_VERSION),
        vec![Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41000))]
    );
    assert_eq!(
        build_kad_hello_response_tags(41000, false, true, false, true, KAD_VERSION),
        vec![Tag::new_short(tag_name::KADMISCOPTIONS, TagValue::U8(0x05))]
    );
}

#[test]
fn source_publish_identity_uses_emule_kad_chunk_order() {
    let user_hash = [
        0xB4, 0x22, 0xCF, 0x1A, 0x44, 0x0E, 0x71, 0x6B, 0xD2, 0xE1, 0xDD, 0x6E, 0x77, 0x21, 0x6F,
        0xE4,
    ];

    let publisher_id = source_publish_client_hash(user_hash);

    assert_eq!(
        publisher_id.0,
        [
            0x1A, 0xCF, 0x22, 0xB4, 0x6B, 0x71, 0x0E, 0x44, 0x6E, 0xDD, 0xE1, 0xD2, 0xE4, 0x6F,
            0x21, 0x77,
        ]
    );
    assert_eq!(publisher_id.to_be_bytes(), user_hash);
}
