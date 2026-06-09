use super::*;
use emulebb_kad_proto::constants::opcode;
use emulebb_kad_proto::{KadPacket, NodeId};

#[tokio::test]
async fn test_hello_request_registers_identity_and_version_for_obfuscated_reply() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let obfuscation = ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, true);
    let rpc = make_rpc_with_shared_transport(Arc::clone(&transport), obfuscation);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_id = NodeId::from_bytes([0x44; 16]);
    let hello = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
        node_id: peer_id,
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded_hello = hello.encode().unwrap();
    let _ = inject_tx.send((encoded_hello, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloReq(_)));

    let search = KadPacket::SearchKeyReq(emulebb_kad_proto::SearchKeyReq {
        target: NodeId::from_bytes([0x55; 16]),
        start_position: 0,
        restrictive_payload: Vec::new(),
    });
    rpc.send(peer_addr, &search).await.unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0], emulebb_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_obfuscated_hello_response_keeps_node_id_for_future_requests() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let local_node_id = NodeId::from_bytes([0xAA; 16]);
    let local_udp_key = 0x1234_5678;
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(local_node_id, local_udp_key, true),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_node_id = NodeId::from_bytes([0x44; 16]);
    let peer_udp_key = 0x5566_7788;
    let peer_obfuscation = ObfuscationLayer::new(peer_node_id, peer_udp_key, true);
    let local_addr = make_local_addr();
    peer_obfuscation.register_peer_identity(local_addr, local_node_id);
    peer_obfuscation.register_peer_version(local_addr, 8);
    let local_ip = match local_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    let peer_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    peer_obfuscation.register_peer_key(local_addr, rpc.verify_key_for_ip(peer_ip));

    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: local_node_id,
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();
    transport.drain_outgoing();

    let hello_res = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: peer_node_id,
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded_hello_res = hello_res.encode().unwrap();
    let encrypted_hello_res =
        peer_obfuscation.encrypt(local_addr, opcode::HELLO_RES, &encoded_hello_res);
    let _ = inject_tx.send((encrypted_hello_res, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert!(received.was_obfuscated);
    assert_eq!(
        received.sender_verify_key,
        Some(peer_obfuscation.verify_key_for_ip(local_ip))
    );

    let search = KadPacket::SearchKeyReq(emulebb_kad_proto::SearchKeyReq {
        target: NodeId::from_bytes([0x55; 16]),
        start_position: 0,
        restrictive_payload: Vec::new(),
    });
    rpc.send(peer_addr, &search).await.unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0] & 0x03, 0x02);
    assert_ne!(outgoing[0].1[0], emulebb_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_lookup_search_response_does_not_teach_receiver_verify_key() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let local_node_id = NodeId::from_bytes([0xAA; 16]);
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(local_node_id, 0x1234_5678, true),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_node_id = NodeId::from_bytes([0x44; 16]);
    let peer_obfuscation = ObfuscationLayer::new(peer_node_id, 0x5566_7788, true);
    let local_addr = make_local_addr();
    let peer_ip = match peer_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!(),
    };
    peer_obfuscation.register_peer_identity(local_addr, local_node_id);
    peer_obfuscation.register_peer_version(local_addr, 8);
    peer_obfuscation.register_peer_key(local_addr, rpc.verify_key_for_ip(peer_ip));

    let search_res = KadPacket::SearchRes(emulebb_kad_proto::SearchRes {
        sender_id: peer_node_id,
        target: NodeId::from_bytes([0x55; 16]),
        results: Vec::new(),
    });
    let encrypted_search_res = peer_obfuscation.encrypt(
        local_addr,
        opcode::SEARCH_RES,
        &search_res.encode().unwrap(),
    );
    let _ = inject_tx.send((encrypted_search_res, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::SearchRes(_)));
    assert_eq!(
        received.sender_verify_key,
        Some(peer_obfuscation.verify_key_for_ip(match local_addr.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => unreachable!(),
        }))
    );

    rpc.send(
        peer_addr,
        &KadPacket::Firewalled2Req(emulebb_kad_proto::Firewalled2Req {
            tcp_port: 4662,
            user_hash: emulebb_kad_proto::Ed2kHash::ZERO,
            connect_options: 0,
        }),
    )
    .await
    .unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].0, peer_addr);
    assert_ne!(outgoing[0].1[0] & 0x03, 0x02);
    assert_ne!(outgoing[0].1[0], emulebb_kad_proto::OP_KADEMLIAHEADER);
}

#[tokio::test]
async fn test_plaintext_hello_request_send_keeps_raw_wire_shape() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, false),
    );

    let peer_addr = make_peer_addr();
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: emulebb_kad_proto::KAD_VERSION,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let outgoing = transport.drain_outgoing();
    assert_eq!(outgoing.len(), 1);
    let (_, wire) = &outgoing[0];
    assert_eq!(wire[0], emulebb_kad_proto::constants::OP_KADEMLIAHEADER);
    assert_eq!(wire[1], opcode::HELLO_REQ);
}
