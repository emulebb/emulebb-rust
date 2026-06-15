use super::*;
use emulebb_kad_proto::{KadPacket, NodeId};

#[tokio::test]
async fn test_unsolicited_request_broadcast() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();

    // Inject a HelloReq (requests are broadcast as unsolicited traffic).
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv()).await;
    assert!(received.is_ok(), "timed out waiting for broadcast");
    let received = received.unwrap().unwrap();
    assert!(matches!(received.packet, KadPacket::HelloReq(_)));
    assert_eq!(received.from, peer_addr);
    assert!(!received.was_obfuscated);
    assert_eq!(received.sender_verify_key, None);
    assert!(!received.receiver_verify_key_valid);
}

#[tokio::test]
async fn test_tracked_hello_response_is_broadcast_without_pending_request() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let obfuscation = ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, true);
    let rpc = make_rpc_with_shared_transport(Arc::clone(&transport), obfuscation);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let peer_id = NodeId::from_bytes([0x44; 16]);
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
            node_id: peer_id,
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert_eq!(received.from, peer_addr);
}

#[tokio::test]
async fn test_plaintext_hello_response_stays_plaintext_without_obfuscation() {
    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::from_bytes([0xAA; 16]), 0x1234_5678, false),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

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

    let hello = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: emulebb_kad_proto::KAD_VERSION,
        tags: Vec::new(),
    });
    let encoded = hello.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));
    assert!(!received.was_obfuscated);
    assert_eq!(received.sender_verify_key, None);
    assert!(!received.receiver_verify_key_valid);
}

#[tokio::test]
async fn test_untracked_response_is_dropped() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let encoded = hello.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let received = tokio::time::timeout(Duration::from_millis(200), subscriber.recv()).await;
    assert!(
        received.is_err(),
        "unexpectedly received untracked response"
    );
}

#[tokio::test]
async fn test_unrequested_response_is_counted_and_dropped() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let pong = KadPacket::Pong(emulebb_kad_proto::Pong { udp_port: 9999 });
    let encoded = pong.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_millis(100), subscriber.recv()).await;
    assert!(received.is_err(), "unexpectedly accepted unrequested pong");

    let snapshot = rpc.observability();
    let pong_stats = snapshot
        .response_opcodes
        .iter()
        .find(|opcode| opcode.opcode == "KADEMLIA2_PONG")
        .expect("pong counters present");
    assert_eq!(pong_stats.dropped_unrequested, 1);
    assert_eq!(pong_stats.matched_pending, 0);
    assert_eq!(pong_stats.matched_tracked, 0);
}

#[tokio::test]
async fn test_firewalled_res_reaches_handler_without_outbound_tracking() {
    // The oracle deliberately does NOT out-track FIREWALLED_REQ, validating the
    // response against the firewall-check-IP list inside the handler instead. So
    // a FIREWALLED_RES must reach the unsolicited path (where lib.rs validates the
    // sender IP) rather than being dropped as an unrequested response.
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let firewalled_res = KadPacket::FirewalledRes(emulebb_kad_proto::FirewalledRes {
        ip: 0x0102_0304,
    });
    let encoded = firewalled_res.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("FIREWALLED_RES timed out instead of reaching the handler")
        .unwrap();
    assert!(matches!(received.packet, KadPacket::FirewalledRes(_)));
    assert_eq!(received.from, peer_addr);

    let snapshot = rpc.observability();
    let stats = snapshot
        .response_opcodes
        .iter()
        .find(|opcode| opcode.opcode == "KADEMLIA2_FIREWALLED_RES");
    // It must NOT be counted as a dropped-unrequested response.
    if let Some(stats) = stats {
        assert_eq!(stats.dropped_unrequested, 0);
    }
}

#[tokio::test]
async fn test_tracked_response_without_pending_request_is_broadcast_and_counted() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    rpc.send(
        peer_addr,
        &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x55; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        }),
    )
    .await
    .unwrap();

    let hello_res = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded = hello_res.encode().unwrap();
    let _ = inject_tx.send((encoded, peer_addr)).await;

    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(received.packet, KadPacket::HelloRes(_)));

    let snapshot = rpc.observability();
    let hello_res_stats = snapshot
        .response_opcodes
        .iter()
        .find(|opcode| opcode.opcode == "KADEMLIA2_HELLO_RES")
        .expect("hello response counters present");
    assert_eq!(hello_res_stats.matched_tracked, 1);
    assert_eq!(hello_res_stats.dropped_unrequested, 0);
}
