use super::crypto::{derive_udp_verify_key, md5_key_material};
use super::*;
use emulebb_kad_proto::constants::OP_KADEMLIAHEADER;
use emulebb_kad_proto::opcode;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn sender_addr() -> SocketAddr {
    "1.2.3.4:4672".parse().unwrap()
}

fn receiver_addr() -> SocketAddr {
    "5.6.7.8:4672".parse().unwrap()
}

#[test]
fn test_verify_key_derivation_is_stable_and_non_zero() {
    let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xCAFE_BABE, true);
    let ip: Ipv4Addr = "5.6.7.8".parse().unwrap();
    assert_eq!(layer.verify_key_for_ip(ip), layer.verify_key_for_ip(ip));
    assert_ne!(layer.verify_key_for_ip(ip), 0);
}

#[test]
fn test_verify_key_derivation_matches_emule_memory_layout() {
    let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
    let our_udp_key: u32 = 0xA1B2_C3D4;

    let mut emule_key_data = [0u8; 8];
    emule_key_data[..4].copy_from_slice(&[1, 2, 3, 4]);
    emule_key_data[4..8].copy_from_slice(&our_udp_key.to_le_bytes());
    let digest = md5_key_material(&emule_key_data);
    let expected = (u32::from_le_bytes(digest[0..4].try_into().unwrap())
        ^ u32::from_le_bytes(digest[4..8].try_into().unwrap())
        ^ u32::from_le_bytes(digest[8..12].try_into().unwrap())
        ^ u32::from_le_bytes(digest[12..16].try_into().unwrap()))
        % 0xFFFF_FFFE
        + 1;

    assert_eq!(derive_udp_verify_key(our_udp_key, ip), expected);
}

#[test]
fn test_encrypt_decrypt_roundtrip_with_node_id_mode() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0x1234_5678, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x22; 16]), 0x8765_4321, true);
    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);

    sender.register_peer_version(receiver_addr(), 8);

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::SEARCH_KEY_REQ, 0xAA, 0xBB];
    let encrypted = sender.encrypt(receiver_addr(), opcode::SEARCH_KEY_REQ, &plaintext);
    assert_ne!(encrypted, plaintext);
    assert_ne!(encrypted[0], OP_KADEMLIAHEADER);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
    assert_eq!(
        decrypted.sender_verify_key,
        Some(sender.verify_key_for_ip(match receiver_addr().ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => unreachable!(),
        }))
    );
}

#[test]
fn test_encrypt_decrypt_roundtrip_with_receiver_key_mode() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x33; 16]), 0x1020_3040, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x44; 16]), 0x5566_7788, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };
    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PONG, 0x01, 0x02];
    let encrypted = sender.encrypt(receiver_addr(), opcode::PONG, &plaintext);
    assert_ne!(encrypted, plaintext);
    assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_response_opcodes_keep_node_id_when_identity_is_known() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x55; 16]), 0xAABB_CCDD, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x66; 16]), 0x1122_3344, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };

    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
    sender.register_peer_version(receiver_addr(), 8);
    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PUBLISH_RES, 0xAA, 0x55];
    let encrypted = sender.encrypt(receiver_addr(), opcode::PUBLISH_RES, &plaintext);

    assert_ne!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_request_opcodes_keep_node_id_when_identity_is_known() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x15; 16]), 0xAABB_CCDD, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x26; 16]), 0x1122_3344, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };

    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
    sender.register_peer_version(receiver_addr(), 8);
    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::SEARCH_KEY_REQ, 0xAA, 0x55];
    let encrypted = sender.encrypt(receiver_addr(), opcode::SEARCH_KEY_REQ, &plaintext);

    assert_ne!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_firewalled2_req_prefers_receiver_key_when_available() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x35; 16]), 0xAABB_CCDD, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x46; 16]), 0x1122_3344, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };

    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
    sender.register_peer_version(receiver_addr(), 8);
    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::FIREWALLED2_REQ, 0xAA, 0x55];
    let encrypted = sender.encrypt(receiver_addr(), opcode::FIREWALLED2_REQ, &plaintext);

    assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_pre_v6_contacts_fall_back_to_plaintext_without_receiver_key() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x77; 16]), 0x1020_3040, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x88; 16]), 0x5566_7788, true);

    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
    sender.register_peer_version(receiver_addr(), 5);

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PUBLISH_SOURCE_REQ, 0x01, 0x02];
    let encrypted = sender.encrypt(receiver_addr(), opcode::PUBLISH_SOURCE_REQ, &plaintext);

    assert_eq!(encrypted, plaintext);
}

#[test]
fn test_pre_v6_requests_use_receiver_key_when_available() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x99; 16]), 0xCAFE_BABE, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0xBEEF_CAFE, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };

    sender.register_peer_identity(receiver_addr(), receiver.our_node_id);
    sender.register_peer_version(receiver_addr(), 5);
    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PUBLISH_SOURCE_REQ, 0x10, 0x20];
    let encrypted = sender.encrypt(receiver_addr(), opcode::PUBLISH_SOURCE_REQ, &plaintext);

    assert_ne!(encrypted, plaintext);
    assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);
}

#[test]
fn test_receiver_verify_key_is_reused_across_ports_on_same_ip() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0xAB; 16]), 0xCAFE_BABE, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0xCD; 16]), 0xBEEF_CAFE, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };
    let learned_addr: SocketAddr = "5.6.7.8:9999".parse().unwrap();
    let reply_addr: SocketAddr = "5.6.7.8:4672".parse().unwrap();

    sender.register_peer_key(learned_addr, receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PONG, 0x44, 0x55];
    let encrypted = sender.encrypt(reply_addr, opcode::PONG, &plaintext);

    assert_ne!(encrypted, plaintext);
    assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_request_opcodes_use_receiver_key_when_node_id_is_missing() {
    let sender = ObfuscationLayer::new(NodeId::from_bytes([0x15; 16]), 0xAABB_CCDD, true);
    let receiver = ObfuscationLayer::new(NodeId::from_bytes([0x26; 16]), 0x1122_3344, true);
    let sender_ip = match sender_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!(),
    };

    sender.register_peer_key(receiver_addr(), receiver.verify_key_for_ip(sender_ip));

    let plaintext = vec![OP_KADEMLIAHEADER, opcode::SEARCH_KEY_REQ, 0xAA, 0x55];
    let encrypted = sender.encrypt(receiver_addr(), opcode::SEARCH_KEY_REQ, &plaintext);

    assert_eq!(encrypted[0] & 0x03, KAD_MARKER_RECEIVER_KEY);

    let decrypted = receiver.decrypt(sender_addr(), &encrypted);
    assert!(decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plaintext);
}

#[test]
fn test_decrypt_plaintext_unchanged() {
    let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xABCD_1234, true);
    let plain = vec![OP_KADEMLIAHEADER, opcode::PING, 0x00, 0x00];
    let decrypted = layer.decrypt(sender_addr(), &plain);
    assert!(!decrypted.was_obfuscated);
    assert_eq!(decrypted.data, plain);
    assert_eq!(decrypted.sender_verify_key, None);
}

#[test]
fn test_disabled_encrypt_returns_plaintext() {
    let layer = ObfuscationLayer::new(NodeId::from_bytes([0x11; 16]), 0xDEAD_BEEF, false);
    let plaintext = vec![OP_KADEMLIAHEADER, opcode::PING];
    assert_eq!(
        layer.encrypt(receiver_addr(), opcode::PING, &plaintext),
        plaintext
    );
}
