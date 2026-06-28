use super::{
    KeywordPublishEntry, PUBLISH_KEYWORD_LOOKUP_TIMEOUT, PUBLISH_NOTES_LOOKUP_TIMEOUT,
    PUBLISH_SOURCE_LOOKUP_TIMEOUT, build_keyword_publish_packet,
    publish_target_is_within_tolerance, select_publish_contacts,
};
use crate::traversal::TraversalContact;
use emulebb_kad_proto::{
    Ed2kHash, KadPacket, NodeId, Tag, TagName, TagValue,
    constants::{
        STORE_KEYWORD_TIMEOUT_SECS, STORE_NOTES_TIMEOUT_SECS, STORE_SOURCE_TIMEOUT_SECS,
        STORE_STOP_GRACE_SECS,
    },
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
