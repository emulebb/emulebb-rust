use super::{
    KEYWORD_PUBLISH_MAX_ENTRIES_PER_PACKET, KeywordPublishEntry, PUBLISH_KEYWORD_LOOKUP_TIMEOUT,
    PUBLISH_NOTES_LOOKUP_TIMEOUT, PUBLISH_SOURCE_LOOKUP_TIMEOUT, PublishAttempt,
    PublishAttemptStats, build_keyword_publish_packet, build_keyword_publish_packets,
    build_notes_publish_packet, build_source_publish_packet, keyword_publish_chunk_count,
    publish_target_is_within_tolerance, record_keyword_publish_results, select_publish_contacts,
};
use crate::traversal::TraversalContact;
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag, TagName, TagValue,
    constants::{
        STORE_KEYWORD_TIMEOUT_SECS, STORE_NOTES_TIMEOUT_SECS, STORE_SOURCE_TIMEOUT_SECS,
        STORE_STOP_GRACE_SECS,
    },
    packet::{PublishKeyReq, PublishRes},
    tag_name,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn close_publish_contact(distance_low_byte: u8, host: u8) -> TraversalContact {
    let mut id = [0u8; 16];
    id[0] = distance_low_byte;
    TraversalContact {
        id: NodeId::from_bytes(id),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, host)), 4_600),
        tcp_port: 0,
        version: 9,
    }
}

#[test]
fn publish_lookup_leaves_mfc_stop_grace_for_store_fanout() {
    assert_eq!(STORE_STOP_GRACE_SECS, 20);
    assert_eq!(
        PUBLISH_KEYWORD_LOOKUP_TIMEOUT,
        Duration::from_secs(STORE_KEYWORD_TIMEOUT_SECS - STORE_STOP_GRACE_SECS)
    );
    assert_eq!(
        PUBLISH_SOURCE_LOOKUP_TIMEOUT,
        Duration::from_secs(STORE_SOURCE_TIMEOUT_SECS - STORE_STOP_GRACE_SECS)
    );
    assert_eq!(
        PUBLISH_NOTES_LOOKUP_TIMEOUT,
        Duration::from_secs(STORE_NOTES_TIMEOUT_SECS - STORE_STOP_GRACE_SECS)
    );
}

#[test]
fn select_publish_contacts_respects_requested_fanout() {
    let target = NodeId::ZERO;
    let contacts = vec![
        close_publish_contact(1, 2),
        close_publish_contact(2, 3),
        close_publish_contact(3, 4),
        close_publish_contact(4, 5),
        close_publish_contact(5, 6),
    ];

    let selected = select_publish_contacts(target, &contacts, 3);

    assert_eq!(selected.len(), 3);
    assert_eq!(selected[0].id, contacts[0].id);
    assert_eq!(selected[2].id, contacts[2].id);
}

#[test]
fn select_publish_contacts_clamps_zero_to_one() {
    let target = NodeId::ZERO;
    let contacts = vec![close_publish_contact(1, 2), close_publish_contact(2, 3)];

    let selected = select_publish_contacts(target, &contacts, 0);

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id, contacts[0].id);
}

#[test]
fn select_publish_contacts_filters_far_contacts_before_fanout() {
    let target = NodeId::ZERO;
    let close = close_publish_contact(1, 2);
    let far = TraversalContact {
        id: NodeId::from_bytes([0xFF; 16]),
        addr: "8.8.8.8:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    let selected = select_publish_contacts(target, &[close.clone(), far], 4);

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id, close.id);
}

#[test]
fn select_publish_contacts_can_filter_every_far_public_contact() {
    let target = NodeId::ZERO;
    let far = TraversalContact {
        id: NodeId::from_bytes([0xFF; 16]),
        addr: "8.8.8.8:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    let selected = select_publish_contacts(target, &[far], 4);

    assert!(selected.is_empty());
}

#[test]
fn publish_tolerance_accepts_loopback_contacts_even_when_far() {
    let target = NodeId::ZERO;
    let far_loopback = TraversalContact {
        id: NodeId::from_bytes([0xFF; 16]),
        addr: "127.0.0.10:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    assert!(publish_target_is_within_tolerance(target, &far_loopback));
}

#[test]
fn publish_tolerance_accepts_exact_harness_keyword_target() {
    let target = NodeId::from_be_bytes([
        0x2a, 0x85, 0xd7, 0xa5, 0x6b, 0x40, 0x4d, 0x26, 0x4a, 0x2a, 0x68, 0x2d, 0xd1, 0xb6, 0x8f,
        0xa8,
    ]);
    let exact_contact = TraversalContact {
        id: NodeId::from_bytes([
            0xa5, 0xd7, 0x85, 0x2a, 0x26, 0x4d, 0x40, 0x6b, 0x2d, 0x68, 0x2a, 0x4a, 0xa8, 0x8f,
            0xb6, 0xd1,
        ]),
        addr: "127.0.0.2:4672".parse().unwrap(),
        tcp_port: 0,
        version: 9,
    };

    assert!(publish_target_is_within_tolerance(target, &exact_contact));
}

#[test]
fn build_keyword_publish_packet_skips_aich_for_v8_contacts() {
    let packet = build_keyword_publish_packet(
        NodeId::from_bytes([1; 16]),
        &[KeywordPublishEntry {
            file_hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![Tag::filename("ubuntu.iso")],
            aich_hash: Some([3; 20]),
        }],
        8,
    );

    let KadPacket::PublishKeyReq(request) = packet else {
        panic!("expected publish key packet");
    };
    assert_eq!(request.entries[0].tags.len(), 1);
}

/// A full high-ID (non-firewalled) source-publish tag set in the exact order
/// `build_source_publish_tags` emits it (Search.cpp:731-745 open branch):
/// SOURCETYPE, SOURCEPORT, SOURCEUPORT, FILESIZE, ENCRYPTION.
fn full_source_publish_tags() -> Vec<Tag> {
    vec![
        Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
        Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41_001)),
        Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41_000)),
        Tag::filesize(2_097_152),
        Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)),
    ]
}

/// A Kad1 contact (version < `KADEMLIA_VERSION2_47a` = 2) must not receive the
/// FILESIZE tag; every other tag keeps its value and relative order so the wire
/// stays byte-exact to the oracle (Search.cpp:741 gates only FILESIZE).
#[test]
fn build_source_publish_packet_skips_filesize_for_pre_47a_contacts() {
    let packet = build_source_publish_packet(
        NodeId::from_bytes([1; 16]),
        NodeId::from_bytes([2; 16]),
        &full_source_publish_tags(),
        1,
    );

    let KadPacket::PublishSourceReq(request) = packet else {
        panic!("expected publish source packet");
    };
    // Identical to the full set with only the FILESIZE tag removed in place.
    assert_eq!(
        request.tags,
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(41_001)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(41_000)),
            Tag::new_short(tag_name::ENCRYPTION, TagValue::U8(3)),
        ]
    );
}

/// A `KADEMLIA_VERSION2_47a`+ contact (version >= 2) receives the whole tag set
/// unchanged, FILESIZE included in its original position.
#[test]
fn build_source_publish_packet_keeps_filesize_for_47a_contacts() {
    let packet = build_source_publish_packet(
        NodeId::from_bytes([1; 16]),
        NodeId::from_bytes([2; 16]),
        &full_source_publish_tags(),
        2,
    );

    let KadPacket::PublishSourceReq(request) = packet else {
        panic!("expected publish source packet");
    };
    assert_eq!(request.tags, full_source_publish_tags());
}

/// A full notes tag set in the order `CSearch::StorePacket` STORENOTES emits it
/// (Search.cpp:834-840): FILENAME, FILERATING, DESCRIPTION, FILESIZE.
fn full_notes_publish_tags() -> Vec<Tag> {
    vec![
        Tag::filename("ubuntu.iso"),
        Tag::new_short(tag_name::FILERATING, TagValue::UInt(3)),
        Tag::new_short(tag_name::DESCRIPTION, TagValue::String("great".to_string())),
        Tag::filesize(2_097_152),
    ]
}

/// A pre-`KADEMLIA_VERSION2_47a` contact (version < 2) must not receive the
/// notes FILESIZE tag, matching the source publish gating (Search.cpp:839).
#[test]
fn build_notes_publish_packet_skips_filesize_for_pre_47a_contacts() {
    let packet = build_notes_publish_packet(
        NodeId::from_bytes([1; 16]),
        NodeId::from_bytes([2; 16]),
        &full_notes_publish_tags(),
        1,
    );

    let KadPacket::PublishNotesReq(request) = packet else {
        panic!("expected publish notes packet");
    };
    assert_eq!(
        request.tags,
        vec![
            Tag::filename("ubuntu.iso"),
            Tag::new_short(tag_name::FILERATING, TagValue::UInt(3)),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("great".to_string())),
        ]
    );
}

/// A `KADEMLIA_VERSION2_47a`+ contact (version >= 2) receives the whole notes
/// tag set unchanged, FILESIZE included in its original position.
#[test]
fn build_notes_publish_packet_keeps_filesize_for_47a_contacts() {
    let packet = build_notes_publish_packet(
        NodeId::from_bytes([1; 16]),
        NodeId::from_bytes([2; 16]),
        &full_notes_publish_tags(),
        2,
    );

    let KadPacket::PublishNotesReq(request) = packet else {
        panic!("expected publish notes packet");
    };
    assert_eq!(request.tags, full_notes_publish_tags());
}

#[test]
fn build_keyword_publish_packet_adds_aich_bsob_for_v9_contacts() {
    let packet = build_keyword_publish_packet(
        NodeId::from_bytes([1; 16]),
        &[KeywordPublishEntry {
            file_hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![Tag::filename("ubuntu.iso")],
            aich_hash: Some([3; 20]),
        }],
        9,
    );

    let KadPacket::PublishKeyReq(request) = packet else {
        panic!("expected publish key packet");
    };
    let aich_tag = request.entries[0]
        .tags
        .iter()
        .find(|tag| tag.name == TagName::Short(tag_name::KADAICHHASHPUB))
        .expect("missing aich tag");
    assert_eq!(aich_tag.value, TagValue::SmallBlob(vec![3; 20]));
}

#[test]
fn build_keyword_publish_packet_preserves_multi_file_entries() {
    let packet = build_keyword_publish_packet(
        NodeId::from_bytes([1; 16]),
        &[
            KeywordPublishEntry {
                file_hash: Ed2kHash::from_bytes([2; 16]),
                tags: vec![Tag::filename("ubuntu.iso")],
                aich_hash: Some([3; 20]),
            },
            KeywordPublishEntry {
                file_hash: Ed2kHash::from_bytes([4; 16]),
                tags: vec![Tag::filename("python.iso")],
                aich_hash: Some([5; 20]),
            },
        ],
        9,
    );

    let KadPacket::PublishKeyReq(request) = packet else {
        panic!("expected publish key packet");
    };
    assert_eq!(request.entries.len(), 2);
    assert_eq!(request.entries[0].hash, Ed2kHash::from_bytes([2; 16]));
    assert_eq!(request.entries[1].hash, Ed2kHash::from_bytes([4; 16]));
    assert!(
        request.entries[0]
            .tags
            .iter()
            .any(|tag| tag.value == TagValue::SmallBlob(vec![3; 20]))
    );
    assert!(
        request.entries[1]
            .tags
            .iter()
            .any(|tag| tag.value == TagValue::SmallBlob(vec![5; 20]))
    );
}

fn keyword_entry(seed: u8) -> KeywordPublishEntry {
    KeywordPublishEntry {
        file_hash: Ed2kHash::from_bytes([seed; 16]),
        tags: vec![Tag::filename("ubuntu.iso")],
        aich_hash: Some([seed; 20]),
    }
}

fn keyword_entries(count: usize) -> Vec<KeywordPublishEntry> {
    (0..count)
        .map(|index| keyword_entry((index % 251) as u8))
        .collect()
}

fn unpack_key_req(packet: &KadPacket) -> &PublishKeyReq {
    let KadPacket::PublishKeyReq(request) = packet else {
        panic!("expected publish key packet");
    };
    request
}

/// Oracle Search.cpp:766-776: chunk divisor mirrors `(files + 49) / 50`.
#[test]
fn keyword_publish_chunk_count_matches_oracle_divisor() {
    assert_eq!(KEYWORD_PUBLISH_MAX_ENTRIES_PER_PACKET, 50);
    assert_eq!(keyword_publish_chunk_count(0), 1);
    assert_eq!(keyword_publish_chunk_count(1), 1);
    assert_eq!(keyword_publish_chunk_count(50), 1);
    assert_eq!(keyword_publish_chunk_count(51), 2);
    assert_eq!(keyword_publish_chunk_count(100), 2);
    assert_eq!(keyword_publish_chunk_count(101), 3);
    assert_eq!(keyword_publish_chunk_count(150), 3);
}

#[test]
fn build_keyword_publish_packets_keeps_fifty_entries_in_one_packet() {
    let target = NodeId::from_bytes([1; 16]);
    let packets = build_keyword_publish_packets(target, &keyword_entries(50), 9);

    assert_eq!(packets.len(), 1);
    let request = unpack_key_req(&packets[0]);
    assert_eq!(request.target, target);
    assert_eq!(request.entries.len(), 50);
}

#[test]
fn build_keyword_publish_packets_splits_fifty_one_entries_into_two_packets() {
    let target = NodeId::from_bytes([1; 16]);
    let entries = keyword_entries(51);
    let packets = build_keyword_publish_packets(target, &entries, 9);

    assert_eq!(packets.len(), 2);
    let first = unpack_key_req(&packets[0]);
    let second = unpack_key_req(&packets[1]);
    // Every chunk re-emits the target + count header (oracle Search.cpp:774-791).
    assert_eq!(first.target, target);
    assert_eq!(second.target, target);
    assert_eq!(first.entries.len(), 50);
    assert_eq!(second.entries.len(), 1);
    // Entry order is preserved across the chunk boundary.
    assert_eq!(first.entries[0].hash, entries[0].file_hash);
    assert_eq!(first.entries[49].hash, entries[49].file_hash);
    assert_eq!(second.entries[0].hash, entries[50].file_hash);
}

#[test]
fn build_keyword_publish_packets_splits_cap_into_three_full_packets() {
    let target = NodeId::from_bytes([1; 16]);
    let entries = keyword_entries(150);
    let packets = build_keyword_publish_packets(target, &entries, 9);

    assert_eq!(packets.len(), 3);
    for (chunk_index, packet) in packets.iter().enumerate() {
        let request = unpack_key_req(packet);
        assert_eq!(request.target, target);
        assert_eq!(request.entries.len(), 50);
        assert_eq!(request.entries[0].hash, entries[chunk_index * 50].file_hash);
        assert_eq!(
            request.entries[49].hash,
            entries[chunk_index * 50 + 49].file_hash
        );
    }
}

#[test]
fn build_keyword_publish_packets_applies_aich_gating_per_chunk() {
    let target = NodeId::from_bytes([1; 16]);
    let entries = keyword_entries(51);

    for packet in build_keyword_publish_packets(target, &entries, 8) {
        for entry in &unpack_key_req(&packet).entries {
            assert!(
                !entry
                    .tags
                    .iter()
                    .any(|tag| tag.name == TagName::Short(tag_name::KADAICHHASHPUB))
            );
        }
    }
    for packet in build_keyword_publish_packets(target, &entries, 9) {
        for entry in &unpack_key_req(&packet).entries {
            assert!(
                entry
                    .tags
                    .iter()
                    .any(|tag| tag.name == TagName::Short(tag_name::KADAICHHASHPUB))
            );
        }
    }
}

fn chunk_attempt(rank: u32, total: u32) -> PublishAttempt {
    PublishAttempt {
        rank,
        total,
        contact: close_publish_contact(rank as u8, rank as u8 + 1),
    }
}

fn publish_res(load: u8) -> KadPacket {
    KadPacket::PublishRes(PublishRes {
        target: NodeId::from_bytes([9; 16]),
        load,
        options: None,
    })
}

fn timeout_error(secs: u64) -> emulebb_kad_net::NetError {
    emulebb_kad_net::NetError::Timeout {
        addr: "127.0.0.9:4672".parse().unwrap(),
        secs,
    }
}

/// SearchManager.cpp:422-445 + Search.cpp:1570-1576: every RES counts one load
/// sample, but the answer count is normalized by the packets-per-contact chunk
/// count so a 3-packet train from one contact yields one effective answer.
#[test]
fn record_keyword_publish_results_normalizes_acks_by_chunk_count() {
    let mut stats = PublishAttemptStats {
        attempted_contacts: 2,
        ..PublishAttemptStats::default()
    };

    let results = vec![
        (
            chunk_attempt(1, 2),
            vec![
                Ok(publish_res(10)),
                Ok(publish_res(20)),
                Ok(publish_res(30)),
            ],
        ),
        (
            chunk_attempt(2, 2),
            vec![
                Ok(publish_res(40)),
                Ok(publish_res(50)),
                Ok(publish_res(60)),
            ],
        ),
    ];
    record_keyword_publish_results(&mut stats, 3, results);

    // 6 raw RES / 3 chunks per contact = 2 effective contact answers.
    assert_eq!(stats.acked_contacts, 2);
    // Load stays per-RES (oracle UpdateNodeLoad runs once per RES).
    assert_eq!(stats.load_responses, 6);
    assert_eq!(stats.total_load, 210);
    assert_eq!(stats.node_load(), 35);
    assert_eq!(stats.timed_out_contacts, 0);
}

#[test]
fn record_keyword_publish_results_floors_partial_chunk_answers() {
    let mut stats = PublishAttemptStats {
        attempted_contacts: 1,
        ..PublishAttemptStats::default()
    };

    let results = vec![(
        chunk_attempt(1, 1),
        vec![
            Ok(publish_res(10)),
            Err(timeout_error(5)),
            Err(timeout_error(5)),
        ],
    )];
    record_keyword_publish_results(&mut stats, 3, results);

    // 1 raw RES / 3 chunks floors to 0 (oracle GetAnswers integer division);
    // the contact answered one chunk, so it is not counted as timed out.
    assert_eq!(stats.acked_contacts, 0);
    assert_eq!(stats.load_responses, 1);
    assert_eq!(stats.timed_out_contacts, 0);
}

#[test]
fn record_keyword_publish_results_counts_contact_timeout_only_when_whole_train_expires() {
    let mut stats = PublishAttemptStats {
        attempted_contacts: 2,
        ..PublishAttemptStats::default()
    };

    let results = vec![
        (
            chunk_attempt(1, 2),
            vec![
                Err(timeout_error(5)),
                Err(timeout_error(5)),
                Err(timeout_error(5)),
            ],
        ),
        (
            chunk_attempt(2, 2),
            vec![Ok(publish_res(4)), Ok(publish_res(6)), Ok(publish_res(8))],
        ),
    ];
    record_keyword_publish_results(&mut stats, 3, results);

    assert_eq!(stats.timed_out_contacts, 1);
    assert_eq!(stats.acked_contacts, 1);
    assert_eq!(stats.failed_contacts(), 1);
}

#[test]
fn record_keyword_publish_results_single_packet_matches_unchunked_counting() {
    let mut stats = PublishAttemptStats {
        attempted_contacts: 2,
        ..PublishAttemptStats::default()
    };

    let results = vec![
        (chunk_attempt(1, 2), vec![Ok(publish_res(12))]),
        (chunk_attempt(2, 2), vec![Err(timeout_error(5))]),
    ];
    record_keyword_publish_results(&mut stats, 1, results);

    assert_eq!(stats.acked_contacts, 1);
    assert_eq!(stats.load_responses, 1);
    assert_eq!(stats.total_load, 12);
    assert_eq!(stats.timed_out_contacts, 1);
}
