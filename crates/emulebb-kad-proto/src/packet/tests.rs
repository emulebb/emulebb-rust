use super::*;
use crate::TagValue;
use crate::tag::Tag;

fn roundtrip(pkt: &KadPacket) -> KadPacket {
    let bytes = pkt.encode().expect("encode failed");
    KadPacket::decode(&bytes).expect("decode failed")
}

#[test]
fn test_ping_roundtrip() {
    let pkt = KadPacket::Ping;
    let bytes = pkt.encode().unwrap();
    assert_eq!(bytes, vec![0xE4, 0x60]);
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    assert!(matches!(pkt2, KadPacket::Ping));
}

#[test]
fn test_pong_roundtrip() {
    let pkt = KadPacket::Pong(Pong { udp_port: 4672 });
    let bytes = pkt.encode().unwrap();
    assert_eq!(bytes, vec![0xE4, 0x61, 0x40, 0x12]);
    let pkt2 = roundtrip(&pkt);
    assert!(matches!(pkt2, KadPacket::Pong(Pong { udp_port: 4672 })));
}

#[test]
fn test_bootstrap_res_roundtrip() {
    let contacts = vec![
        ContactEntry {
            node_id: NodeId::from_bytes([1u8; 16]),
            ip: 0x0102_0304,
            udp_port: 4672,
            tcp_port: 4662,
            version: 9,
        },
        ContactEntry {
            node_id: NodeId::from_bytes([2u8; 16]),
            ip: 0x0506_0708,
            udp_port: 4673,
            tcp_port: 4663,
            version: 8,
        },
    ];
    let pkt = KadPacket::BootstrapRes(BootstrapRes {
        sender_id: NodeId::from_bytes([0xAA; 16]),
        sender_tcp_port: 4662,
        sender_version: 9,
        contacts: contacts.clone(),
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::BootstrapRes(res) = pkt2 {
        assert_eq!(res.contacts.len(), 2);
        assert_eq!(res.contacts[0].node_id, contacts[0].node_id);
        assert_eq!(res.contacts[1].udp_port, 4673);
        assert_eq!(res.sender_version, 9);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
fn test_packed_packet_decode() {
    // Build a plain Ping, then zlib-compress it to simulate 0xE5 packet
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    // Body of a Ping is empty; encode as 0xE4 0x60, body = []
    // For 0xE5 format: compress just the body (buf[2..] of the plain packet)
    let plain = KadPacket::Ping.encode().unwrap();
    let body = &plain[2..]; // empty for Ping

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut packed = vec![OP_KADEMLIAPACKEDPROT, plain[1]]; // 0xE5 + opcode
    packed.extend_from_slice(&compressed);

    let decoded = KadPacket::decode(&packed).unwrap();
    assert!(matches!(decoded, KadPacket::Ping));
}

#[test]
fn test_packed_packet_decompression_bomb_rejected() {
    // A crafted 0xE5 packet whose zlib body inflates far past the Kad cap must be
    // rejected as DecompressError without performing the unbounded allocation.
    use flate2::{Compression, write::ZlibEncoder};
    use std::io::Write;

    // Highly compressible payload that inflates well beyond
    // MAX_DECOMPRESSED_KAD_PACKET_LEN (64 KB). 1 MiB of zeros compresses to a
    // tiny body, so the compressed input stays small while the inflated output
    // would be huge.
    let bomb = vec![0u8; 1024 * 1024];
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&bomb).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(
        compressed.len() < MAX_DECOMPRESSED_KAD_PACKET_LEN,
        "compressed bomb input should be small"
    );

    let mut packed = vec![OP_KADEMLIAPACKEDPROT, opcode::PING];
    packed.extend_from_slice(&compressed);

    let err = KadPacket::decode(&packed).unwrap_err();
    assert!(
        matches!(err, ProtoError::DecompressError),
        "expected DecompressError, got {err:?}"
    );
}

#[test]
fn test_hello_req_v10_with_tags_roundtrip() {
    let pkt = KadPacket::HelloReq(HelloReq {
        node_id: NodeId::from_bytes([0xAA; 16]),
        tcp_port: 4662,
        version: 10,
        tags: vec![Tag::filename("test.txt"), Tag::filesize(12345)],
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::HelloReq(req) = pkt2 {
        assert_eq!(req.version, 10);
        assert_eq!(req.tags.len(), 2);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
fn test_hello_req_v4_roundtrip_without_optional_fields() {
    let pkt = KadPacket::HelloReq(HelloReq {
        node_id: NodeId::from_bytes([0xBB; 16]),
        tcp_port: 4662,
        version: 4,
        tags: vec![],
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::HelloReq(req) = pkt2 {
        assert_eq!(req.version, 4);
        assert!(req.tags.is_empty());
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_hello_req_wire_shape_matches_oracle_layout() {
    let node_id = NodeId::from_bytes([0xDD; 16]);
    let pkt = KadPacket::HelloReq(HelloReq {
        node_id,
        tcp_port: 4662,
        version: crate::constants::KAD_VERSION,
        tags: vec![Tag::new_short(
            crate::constants::tag_name::SOURCEUPORT,
            TagValue::U16(41000),
        )],
    });

    let bytes = pkt.encode().unwrap();

    assert_eq!(bytes[0], crate::constants::OP_KADEMLIAHEADER);
    assert_eq!(bytes[1], crate::constants::opcode::HELLO_REQ);
    assert_eq!(&bytes[2..18], &node_id.0);
    assert_eq!(u16::from_le_bytes([bytes[18], bytes[19]]), 4662);
    assert_eq!(bytes[20], crate::constants::KAD_VERSION);
    assert_eq!(bytes[21], 1);
}

#[test]
fn test_hello_res_ack_roundtrip() {
    let pkt = KadPacket::HelloResAck(HelloResAck {
        node_id: NodeId::from_bytes([0xCC; 16]),
        tags: vec![Tag::new_short(
            crate::constants::tag_name::KADMISCOPTIONS,
            TagValue::U8(4),
        )],
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::HelloResAck(ack) = pkt2 {
        assert_eq!(ack.node_id, NodeId::from_bytes([0xCC; 16]));
        assert_eq!(ack.tags.len(), 1);
    } else {
        panic!("wrong packet type");
    }
}

#[test]
fn test_search_res_roundtrip() {
    let entry = SearchResultEntry {
        entry_id: Ed2kHash::from_bytes([0xAB; 16]),
        tags: vec![Tag::filename("ubuntu.iso"), Tag::filesize(1_000_000_000)],
    };
    let pkt = KadPacket::SearchRes(SearchRes {
        sender_id: NodeId::from_bytes([0x11; 16]),
        target: NodeId::from_bytes([0x22; 16]),
        results: vec![entry],
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::SearchRes(res) = pkt2 {
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].tags.len(), 2);
        assert_eq!(res.results[0].entry_id, Ed2kHash::from_bytes([0xAB; 16]));
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_search_res_entry_id_uses_kad_chunk_byte_order() {
    let entry = SearchResultEntry {
        entry_id: "0102030405060708090a0b0c0d0e0f10".parse().unwrap(),
        tags: vec![],
    };
    let pkt = KadPacket::SearchRes(SearchRes {
        sender_id: NodeId::from_bytes([0x11; 16]),
        target: NodeId::from_bytes([0x22; 16]),
        results: vec![entry],
    });

    let bytes = pkt.encode().expect("encode search res");
    let search_res_bytes = &bytes[2..];
    assert_eq!(
        &search_res_bytes[34..50],
        &[
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0C, 0x0B, 0x0A, 0x09, 0x10, 0x0F,
            0x0E, 0x0D
        ]
    );

    let decoded = KadPacket::decode(&bytes).expect("decode search res");
    let KadPacket::SearchRes(search_res) = decoded else {
        panic!("wrong packet type");
    };
    assert_eq!(
        search_res.results[0].entry_id,
        "0102030405060708090a0b0c0d0e0f10".parse().unwrap()
    );
}

#[test]
fn test_search_res_decodes_legacy_cp1252_strings() {
    let mut bytes = vec![OP_KADEMLIAHEADER, opcode::SEARCH_RES];
    bytes.extend_from_slice(&[0x11; 16]); // sender_id
    bytes.extend_from_slice(&[0x22; 16]); // target
    bytes.extend_from_slice(&1u16.to_le_bytes()); // result count
    bytes.extend_from_slice(&[0x33; 16]); // file hash
    bytes.push(1); // tag count
    bytes.push(0x82); // short-name string tag
    bytes.push(crate::constants::tag_name::FILENAME);
    bytes.extend_from_slice(&4u16.to_le_bytes());
    bytes.extend_from_slice(&[b'T', 0xE9, b's', b't']); // "Tést" in cp1252

    let decoded = KadPacket::decode(&bytes).expect("decode search res");
    let KadPacket::SearchRes(search_res) = decoded else {
        panic!("wrong packet type");
    };
    assert_eq!(search_res.results.len(), 1);
    assert_eq!(
        search_res.results[0].entry_id,
        "33333333333333333333333333333333".parse().unwrap()
    );
    assert_eq!(search_res.results[0].tags.len(), 1);
    assert_eq!(search_res.results[0].tags[0], Tag::filename("Tést"));
}

#[test]
fn test_publish_key_req_roundtrip() {
    let entry = PublishEntry {
        hash: Ed2kHash::from_bytes([0xCC; 16]),
        tags: vec![Tag::filename("myfile.mp3"), Tag::sources(3)],
    };
    let pkt = KadPacket::PublishKeyReq(PublishKeyReq {
        target: NodeId::from_bytes([0x22; 16]),
        entries: vec![entry],
    });
    let bytes = pkt.encode().unwrap();
    let pkt2 = KadPacket::decode(&bytes).unwrap();
    if let KadPacket::PublishKeyReq(req) = pkt2 {
        assert_eq!(req.entries.len(), 1);
        assert_eq!(req.entries[0].tags.len(), 2);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_unknown_opcode_preserved() {
    let buf = vec![0xE4, 0xFE, 0x01, 0x02, 0x03];
    let pkt = KadPacket::decode(&buf).unwrap();
    if let KadPacket::Unknown { opcode, payload } = &pkt {
        assert_eq!(*opcode, 0xFE);
        assert_eq!(payload, &vec![0x01, 0x02, 0x03]);
    } else {
        panic!("expected Unknown");
    }
    // Re-encode should preserve bytes
    let encoded = pkt.encode().unwrap();
    assert_eq!(encoded, buf);
}

#[test]
fn publish_response_preserves_optional_stock_ack_request_byte() {
    let mut bytes = vec![0xE4, opcode::PUBLISH_RES];
    bytes.extend_from_slice(&[0x22; 16]);
    bytes.push(7);
    bytes.push(1);
    bytes.push(0xAA);

    let decoded = KadPacket::decode(&bytes).unwrap();
    let KadPacket::PublishRes(response) = decoded else {
        panic!("wrong type");
    };
    assert_eq!(response.target, NodeId::from_bytes([0x22; 16]));
    assert_eq!(response.load, 7);
    assert_eq!(response.options, Some(1));

    let encoded = KadPacket::PublishRes(PublishRes {
        target: response.target,
        load: response.load,
        options: response.options,
    })
    .encode()
    .unwrap();
    assert_eq!(encoded, bytes[..20]);
}

#[test]
fn publish_response_rejects_short_stock_body() {
    let mut short = vec![OP_KADEMLIAHEADER, opcode::PUBLISH_RES];
    short.extend_from_slice(&[0x25; 16]);

    assert!(matches!(
        KadPacket::decode(&short),
        Err(ProtoError::InvalidPacketSize {
            expected: 17,
            actual: 16,
            ..
        })
    ));
}

#[test]
fn test_invalid_protocol_byte() {
    let buf = vec![0xE3, 0x60]; // wrong header
    let err = KadPacket::decode(&buf);
    assert!(matches!(err, Err(ProtoError::InvalidProtocol(0xE3))));
}

#[test]
fn test_buffer_too_short() {
    let err = KadPacket::decode(&[0xE4]);
    assert!(matches!(err, Err(ProtoError::BufferTooShort)));
}

#[test]
fn test_req_roundtrip() {
    use crate::constants::KADEMLIA_FIND_VALUE;
    let pkt = KadPacket::Req(Req {
        count: KADEMLIA_FIND_VALUE,
        target: NodeId::from_bytes([0x33; 16]),
        recipient_id: NodeId::from_bytes([0x44; 16]),
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::Req(r) = pkt2 {
        assert_eq!(r.count, KADEMLIA_FIND_VALUE);
        assert_eq!(r.target, NodeId::from_bytes([0x33; 16]));
        assert_eq!(r.recipient_id, NodeId::from_bytes([0x44; 16]));
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_firewalled_req_roundtrip() {
    let pkt = KadPacket::FirewalledReq(FirewalledReq { tcp_port: 4662 });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::FirewalledReq(f) = pkt2 {
        assert_eq!(f.tcp_port, 4662);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn firewalled_req_rejects_stock_exact_size_trailing_bytes() {
    let bytes = vec![0xE4, opcode::FIREWALLED_REQ, 0x36, 0x12, 0xAA];
    assert!(KadPacket::decode(&bytes).is_err());
}

#[test]
fn test_firewalled2_req_roundtrip() {
    let pkt = KadPacket::Firewalled2Req(Firewalled2Req {
        tcp_port: 4662,
        user_hash: Ed2kHash::from_bytes([0x11; 16]),
        connect_options: 0x07,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::Firewalled2Req(f) = pkt2 {
        assert_eq!(f.tcp_port, 4662);
        assert_eq!(f.user_hash, Ed2kHash::from_bytes([0x11; 16]));
        assert_eq!(f.connect_options, 0x07);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn firewalled2_req_tolerates_stock_min_size_trailing_bytes() {
    let mut bytes = vec![0xE4, opcode::FIREWALLED2_REQ];
    bytes.extend_from_slice(&4662u16.to_le_bytes());
    bytes.extend_from_slice(&[0x11; 16]);
    bytes.push(0x07);
    bytes.push(0xAA);

    assert!(matches!(
        KadPacket::decode(&bytes).unwrap(),
        KadPacket::Firewalled2Req(_)
    ));
}

#[test]
fn test_firewalled_res_roundtrip() {
    // FIREWALLED_RES carries the requester's IP as a u32 (host byte order on the
    // eMule wire). Lock encode -> decode so the firewall helper send path stays
    // byte-stable.
    let pkt = KadPacket::FirewalledRes(FirewalledRes { ip: 0x0102_0304 });
    let bytes = pkt.encode().unwrap();
    // header byte + opcode + 4-byte IP body, little-endian.
    assert_eq!(
        bytes,
        vec![
            OP_KADEMLIAHEADER,
            opcode::FIREWALLED_RES,
            0x04,
            0x03,
            0x02,
            0x01
        ]
    );
    match roundtrip(&pkt) {
        KadPacket::FirewalledRes(f) => assert_eq!(f.ip, 0x0102_0304),
        other => panic!("wrong type {other:?}"),
    }
}

#[test]
fn test_firewall_udp_roundtrip() {
    // KADEMLIA2_FIREWALLUDP body = error_code:u8 + udp_port:u16 (little-endian).
    let pkt = KadPacket::FirewallUdp(FirewallUdp {
        error_code: 0,
        udp_port: 4672,
    });
    let bytes = pkt.encode().unwrap();
    assert_eq!(
        bytes,
        vec![OP_KADEMLIAHEADER, opcode::FIREWALLUDP, 0x00, 0x40, 0x12]
    );
    match roundtrip(&pkt) {
        KadPacket::FirewallUdp(f) => {
            assert_eq!(f.error_code, 0);
            assert_eq!(f.udp_port, 4672);
        }
        other => panic!("wrong type {other:?}"),
    }

    // A non-zero error code (already-known peer) survives the round trip too.
    let err_pkt = KadPacket::FirewallUdp(FirewallUdp {
        error_code: 1,
        udp_port: 51000,
    });
    match roundtrip(&err_pkt) {
        KadPacket::FirewallUdp(f) => {
            assert_eq!(f.error_code, 1);
            assert_eq!(f.udp_port, 51000);
        }
        other => panic!("wrong type {other:?}"),
    }
}

#[test]
fn firewalled_response_and_legacy_ack_reject_stock_exact_size_trailing_bytes() {
    let firewalled_res = vec![0xE4, opcode::FIREWALLED_RES, 1, 2, 3, 4, 0xAA];
    assert!(KadPacket::decode(&firewalled_res).is_err());

    let legacy_ack = vec![0xE4, opcode::FIREWALLED_ACK_RES, 0xAA];
    assert!(KadPacket::decode(&legacy_ack).is_err());
}

#[test]
fn firewall_udp_uses_stock_min_size_and_ignores_trailing_bytes() {
    let short = vec![OP_KADEMLIAHEADER, opcode::FIREWALLUDP, 0, 0];
    assert!(matches!(
        KadPacket::decode(&short),
        Err(ProtoError::InvalidPacketSize {
            expected: 3,
            actual: 2,
            ..
        })
    ));

    let with_trailing = vec![OP_KADEMLIAHEADER, opcode::FIREWALLUDP, 0, 0x40, 0x12, 0xAA];
    assert!(matches!(
        KadPacket::decode(&with_trailing).unwrap(),
        KadPacket::FirewallUdp(FirewallUdp {
            error_code: 0,
            udp_port: 4672
        })
    ));
}

#[test]
fn test_find_buddy_req_roundtrip() {
    let pkt = KadPacket::FindBuddyReq(FindBuddyReq {
        buddy_id: NodeId::from_bytes([0x21; 16]),
        client_hash: Ed2kHash::from_bytes([0x42; 16]),
        tcp_port: 4662,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::FindBuddyReq(req) = pkt2 {
        assert_eq!(req.buddy_id, NodeId::from_bytes([0x21; 16]));
        assert_eq!(req.client_hash, Ed2kHash::from_bytes([0x42; 16]));
        assert_eq!(req.tcp_port, 4662);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_find_buddy_res_roundtrip_without_connect_options() {
    let pkt = KadPacket::FindBuddyRes(FindBuddyRes {
        buddy_id: NodeId::from_bytes([0x31; 16]),
        client_hash: Ed2kHash::from_bytes([0x52; 16]),
        tcp_port: 4662,
        connect_options: None,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::FindBuddyRes(res) = pkt2 {
        assert_eq!(res.buddy_id, NodeId::from_bytes([0x31; 16]));
        assert_eq!(res.client_hash, Ed2kHash::from_bytes([0x52; 16]));
        assert_eq!(res.tcp_port, 4662);
        assert_eq!(res.connect_options, None);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_find_buddy_res_roundtrip_with_connect_options() {
    let pkt = KadPacket::FindBuddyRes(FindBuddyRes {
        buddy_id: NodeId::from_bytes([0x41; 16]),
        client_hash: Ed2kHash::from_bytes([0x62; 16]),
        tcp_port: 4662,
        connect_options: Some(0x07),
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::FindBuddyRes(res) = pkt2 {
        assert_eq!(res.buddy_id, NodeId::from_bytes([0x41; 16]));
        assert_eq!(res.client_hash, Ed2kHash::from_bytes([0x62; 16]));
        assert_eq!(res.tcp_port, 4662);
        assert_eq!(res.connect_options, Some(0x07));
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_callback_req_roundtrip() {
    let pkt = KadPacket::CallbackReq(CallbackReq {
        buddy_id: NodeId::from_bytes([0x51; 16]),
        file_hash: Ed2kHash::from_bytes([0x72; 16]),
        tcp_port: 4662,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::CallbackReq(req) = pkt2 {
        assert_eq!(req.buddy_id, NodeId::from_bytes([0x51; 16]));
        assert_eq!(req.file_hash, Ed2kHash::from_bytes([0x72; 16]));
        assert_eq!(req.tcp_port, 4662);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn stock_buddy_packets_reject_short_bodies() {
    for (opcode_value, expected_min) in [
        (opcode::FINDBUDDY_REQ, 34),
        (opcode::FINDBUDDY_RES, 34),
        (opcode::CALLBACK_REQ, 34),
        (opcode::PONG, 2),
    ] {
        let mut bytes = vec![OP_KADEMLIAHEADER, opcode_value];
        bytes.resize(2 + expected_min - 1, 0);

        assert!(matches!(
            KadPacket::decode(&bytes),
            Err(ProtoError::InvalidPacketSize {
                expected,
                actual,
                ..
            }) if expected == expected_min && actual == expected_min - 1
        ));
    }
}

#[test]
fn stock_buddy_packets_ignore_trailing_bytes() {
    let mut find_buddy_req = vec![OP_KADEMLIAHEADER, opcode::FINDBUDDY_REQ];
    find_buddy_req.resize(2 + 34, 0);
    find_buddy_req.push(0xAA);
    assert!(matches!(
        KadPacket::decode(&find_buddy_req).unwrap(),
        KadPacket::FindBuddyReq(_)
    ));

    let mut find_buddy_res = vec![OP_KADEMLIAHEADER, opcode::FINDBUDDY_RES];
    find_buddy_res.resize(2 + 34, 0);
    find_buddy_res.extend_from_slice(&[0x07, 0xAA]);
    match KadPacket::decode(&find_buddy_res).unwrap() {
        KadPacket::FindBuddyRes(res) => assert_eq!(res.connect_options, Some(0x07)),
        other => panic!("wrong packet type: {other:?}"),
    }

    let mut callback_req = vec![OP_KADEMLIAHEADER, opcode::CALLBACK_REQ];
    callback_req.resize(2 + 34, 0);
    callback_req.push(0xAA);
    assert!(matches!(
        KadPacket::decode(&callback_req).unwrap(),
        KadPacket::CallbackReq(_)
    ));

    let pong = vec![OP_KADEMLIAHEADER, opcode::PONG, 0x40, 0x12, 0xAA];
    assert!(matches!(
        KadPacket::decode(&pong).unwrap(),
        KadPacket::Pong(Pong { udp_port: 4672 })
    ));
}

#[test]
fn test_publish_source_req_roundtrip() {
    let pkt = KadPacket::PublishSourceReq(PublishSourceReq {
        target: NodeId::from_bytes([0x44; 16]),
        publisher_id: NodeId::from_bytes([0x55; 16]),
        tags: vec![Tag::sources(10)],
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::PublishSourceReq(req) = pkt2 {
        assert_eq!(req.target, NodeId::from_bytes([0x44; 16]));
        assert_eq!(req.publisher_id, NodeId::from_bytes([0x55; 16]));
        assert_eq!(req.tags.len(), 1);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_publish_source_req_uses_u8_tag_count_on_wire() {
    let pkt = KadPacket::PublishSourceReq(PublishSourceReq {
        target: NodeId::from_bytes([0x44; 16]),
        publisher_id: NodeId::from_bytes([0x55; 16]),
        tags: vec![Tag::sources(10), Tag::filesize(1234)],
    });

    let encoded = pkt.encode().unwrap();
    assert_eq!(encoded[0], OP_KADEMLIAHEADER);
    assert_eq!(encoded[1], opcode::PUBLISH_SOURCE_REQ);
    assert_eq!(encoded[34], 2, "source publish tag count must be u8");
}

#[test]
fn test_publish_notes_req_roundtrip() {
    let pkt = KadPacket::PublishNotesReq(PublishNotesReq {
        target: NodeId::from_bytes([0x44; 16]),
        publisher_id: NodeId::from_bytes([0x55; 16]),
        tags: vec![
            Tag::new_short(
                crate::constants::tag_name::FILERATING,
                crate::tag::TagValue::U8(4),
            ),
            Tag::new_short(
                crate::constants::tag_name::DESCRIPTION,
                crate::tag::TagValue::String("oracle-style validation note".to_string()),
            ),
        ],
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::PublishNotesReq(req) = pkt2 {
        assert_eq!(req.target, NodeId::from_bytes([0x44; 16]));
        assert_eq!(req.publisher_id, NodeId::from_bytes([0x55; 16]));
        assert_eq!(req.tags.len(), 2);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_publish_notes_req_uses_u8_tag_count_on_wire() {
    let pkt = KadPacket::PublishNotesReq(PublishNotesReq {
        target: NodeId::from_bytes([0x44; 16]),
        publisher_id: NodeId::from_bytes([0x55; 16]),
        tags: vec![
            Tag::new_short(
                crate::constants::tag_name::FILERATING,
                crate::tag::TagValue::U8(4),
            ),
            Tag::new_short(
                crate::constants::tag_name::DESCRIPTION,
                crate::tag::TagValue::String("validation".to_string()),
            ),
        ],
    });

    let encoded = pkt.encode().unwrap();
    assert_eq!(encoded[0], OP_KADEMLIAHEADER);
    assert_eq!(encoded[1], opcode::PUBLISH_NOTES_REQ);
    assert_eq!(encoded[34], 2, "notes publish tag count must be u8");
}

#[test]
fn test_publish_key_req_entry_uses_u8_tag_count_on_wire() {
    let pkt = KadPacket::PublishKeyReq(PublishKeyReq {
        target: NodeId::from_bytes([0x22; 16]),
        entries: vec![PublishEntry {
            hash: Ed2kHash([0x33; 16]),
            tags: vec![Tag::filename("ubuntu linux"), Tag::sources(10)],
        }],
    });

    let encoded = pkt.encode().unwrap();
    assert_eq!(encoded[0], OP_KADEMLIAHEADER);
    assert_eq!(encoded[1], opcode::PUBLISH_KEY_REQ);
    // 2-byte Kad header + 16-byte target + 2-byte entry count + 16-byte file hash.
    assert_eq!(encoded[36], 2, "keyword publish tag count must be u8");
}

#[test]
fn test_search_source_req_roundtrip() {
    let pkt = KadPacket::SearchSourceReq(SearchSourceReq {
        target: NodeId::from_bytes([0x66; 16]),
        start_position: 7,
        size: 99_999_999,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::SearchSourceReq(req) = pkt2 {
        assert_eq!(req.start_position, 7);
        assert_eq!(req.size, 99_999_999);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_search_source_req_decode_masks_stock_start_position_high_bit() {
    let mut encoded = vec![OP_KADEMLIAHEADER, opcode::SEARCH_SOURCE_REQ];
    encoded.extend([0x66; 16]);
    encoded.extend(0x8007_u16.to_le_bytes());
    encoded.extend(99_999_999_u64.to_le_bytes());

    let decoded = KadPacket::decode(&encoded).expect("decode source search request");
    let KadPacket::SearchSourceReq(req) = decoded else {
        panic!("wrong type");
    };
    assert_eq!(req.target, NodeId::from_bytes([0x66; 16]));
    assert_eq!(req.start_position, 7);
    assert_eq!(req.size, 99_999_999);
}

#[test]
fn test_search_source_req_matches_non_obfuscated_capture_sample() {
    let pkt = KadPacket::SearchSourceReq(SearchSourceReq {
        target: NodeId::from_bytes([
            0x60, 0xF2, 0x0A, 0x2D, 0x03, 0xA8, 0xD0, 0x1F, 0x23, 0xCF, 0xD7, 0xC9, 0x5A, 0xC8,
            0xAD, 0xA9,
        ]),
        start_position: 0,
        size: 2_409_452,
    });

    assert_eq!(
        pkt.encode().unwrap()[2..],
        vec![
            0x60, 0xF2, 0x0A, 0x2D, 0x03, 0xA8, 0xD0, 0x1F, 0x23, 0xCF, 0xD7, 0xC9, 0x5A, 0xC8,
            0xAD, 0xA9, 0x00, 0x00, 0xEC, 0xC3, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    );
}

#[test]
fn test_search_key_req_roundtrip_plain() {
    let pkt = KadPacket::SearchKeyReq(SearchKeyReq {
        target: NodeId::from_bytes([0x22; 16]),
        start_position: 0,
        restrictive_payload: Vec::new(),
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::SearchKeyReq(req) = pkt2 {
        assert_eq!(req.target, NodeId::from_bytes([0x22; 16]));
        assert_eq!(req.start_position, 0);
        assert!(req.restrictive_payload.is_empty());
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_search_key_req_roundtrip_restrictive_payload() {
    let pkt = KadPacket::SearchKeyReq(SearchKeyReq {
        target: NodeId::from_bytes([0x33; 16]),
        start_position: 0x8000,
        restrictive_payload: vec![0x01, 0x02, 0xA5, 0xFF],
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::SearchKeyReq(req) = pkt2 {
        assert_eq!(req.target, NodeId::from_bytes([0x33; 16]));
        assert_eq!(req.start_position, 0x8000);
        assert_eq!(req.restrictive_payload, vec![0x01, 0x02, 0xA5, 0xFF]);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_search_notes_req_roundtrip() {
    let pkt = KadPacket::SearchNotesReq(SearchNotesReq {
        target: NodeId::from_bytes([0x77; 16]),
        size: 123_456_789,
    });
    let pkt2 = roundtrip(&pkt);
    if let KadPacket::SearchNotesReq(req) = pkt2 {
        assert_eq!(req.target, NodeId::from_bytes([0x77; 16]));
        assert_eq!(req.size, 123_456_789);
    } else {
        panic!("wrong type");
    }
}

#[test]
fn test_contact_entry_ip_addr() {
    // Store as little-endian u32: 192.168.1.1 = 0xC0A80101
    // to_be_bytes() of 0xC0A80101 = [0xC0, 0xA8, 0x01, 0x01]
    let c = ContactEntry {
        node_id: NodeId::ZERO,
        ip: 0xC0A8_0101_u32,
        udp_port: 4672,
        tcp_port: 4662,
        version: 9,
    };
    assert_eq!(c.ip_addr(), std::net::Ipv4Addr::new(192, 168, 1, 1));
}
