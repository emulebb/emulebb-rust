use super::*;
use emulebb_kad_proto::constants::opcode;
use emulebb_kad_proto::{KadPacket, NodeId};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn v4(ip: IpAddr) -> Ipv4Addr {
    match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => unreachable!("Kad tests are IPv4-only"),
    }
}

fn encrypted_hello_request(
    sender: &ObfuscationLayer,
    receiver_addr: SocketAddr,
    node_id: NodeId,
    version: u8,
) -> Vec<u8> {
    let packet = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
        node_id,
        tcp_port: 4662,
        version,
        tags: Vec::new(),
    });
    sender.encrypt(receiver_addr, opcode::HELLO_REQ, &packet.encode().unwrap())
}

async fn wait_for_pending(rpc: &RpcManager, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if rpc.pending_len() == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending request state reached expected size");
}

async fn wait_for_massive_ping_drop(rpc: &RpcManager) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let massive_drop = rpc
                .observability()
                .tracker_buckets
                .into_iter()
                .find(|bucket| bucket.bucket == "ping_req")
                .is_some_and(|bucket| bucket.tracker_massive_drops > 0);
            if massive_drop {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("ping flood reached the massive-drop tier");
}

#[tokio::test]
async fn flood_rejected_request_cannot_replace_peer_metadata_or_dispatch() {
    let receiver_addr = make_local_addr();
    let receiver_id = NodeId::from_bytes([0xAA; 16]);
    let transport = Arc::new(MockTransport::new(receiver_addr));
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        Arc::clone(&transport),
        ObfuscationLayer::new(receiver_id, 0x1234_5678, true),
        RpcConfig {
            request_tracking_window: Duration::from_secs(60),
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:4672".parse().unwrap();
    let accepted_id = NodeId::from_bytes([0x44; 16]);
    let accepted_sender = ObfuscationLayer::new(accepted_id, 0x5566_7788, true);
    accepted_sender.register_peer_identity(receiver_addr, receiver_id);
    accepted_sender.register_peer_version(receiver_addr, 8);
    let accepted_key = accepted_sender.verify_key_for_ip(v4(receiver_addr.ip()));

    for _ in 0..3 {
        inject_tx
            .send((
                encrypted_hello_request(&accepted_sender, receiver_addr, accepted_id, 8),
                peer_addr,
            ))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
            .await
            .expect("accepted HELLO_REQ was not dispatched")
            .expect("subscriber closed");
        assert!(matches!(received.packet, KadPacket::HelloReq(_)));
    }

    let rejected_id = NodeId::from_bytes([0x77; 16]);
    let rejected_sender = ObfuscationLayer::new(rejected_id, 0x99AA_BBCC, true);
    rejected_sender.register_peer_identity(receiver_addr, receiver_id);
    rejected_sender.register_peer_version(receiver_addr, 8);
    let rejected_key = rejected_sender.verify_key_for_ip(v4(receiver_addr.ip()));
    assert_ne!(accepted_key, rejected_key);

    inject_tx
        .send((
            encrypted_hello_request(&rejected_sender, receiver_addr, rejected_id, 7),
            peer_addr,
        ))
        .await
        .unwrap();

    let sentinel_addr: SocketAddr = "8.8.8.8:4672".parse().unwrap();
    inject_tx
        .send((KadPacket::Ping.encode().unwrap(), sentinel_addr))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("sentinel packet was not dispatched")
        .expect("subscriber closed");
    assert_eq!(
        received.from, sentinel_addr,
        "rejected HELLO_REQ escaped admission"
    );
    assert!(matches!(received.packet, KadPacket::Ping));

    let state = rpc
        .inner
        .obfuscation
        .inspect_outbound(peer_addr, opcode::PING);
    assert_eq!(state.peer_node_id, Some(accepted_id));
    assert_eq!(state.peer_kad_version, Some(8));
    assert_eq!(state.receiver_verify_key, Some(accepted_key));
    let hello_bucket = rpc
        .observability()
        .tracker_buckets
        .into_iter()
        .find(|bucket| bucket.bucket == "hello_req")
        .expect("HELLO_REQ tracker bucket present");
    assert_eq!(hello_bucket.accepted_requests, 3);
    assert_eq!(hello_bucket.tracker_drops, 1);
}

#[tokio::test]
async fn encrypted_source_port_53_with_nonzero_sender_key_remains_valid() {
    let receiver_addr = make_local_addr();
    let receiver_id = NodeId::from_bytes([0xAA; 16]);
    let transport = MockTransport::new(receiver_addr);
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(receiver_id, 0x1234_5678, true),
        RpcConfig::default(),
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "198.51.100.7:53".parse().unwrap();
    let peer_id = NodeId::from_bytes([0x44; 16]);
    let sender = ObfuscationLayer::new(peer_id, 0x5566_7788, true);
    sender.register_peer_identity(receiver_addr, receiver_id);
    sender.register_peer_version(receiver_addr, 8);
    let expected_key = sender.verify_key_for_ip(v4(receiver_addr.ip()));
    assert_ne!(expected_key, 0);

    inject_tx
        .send((
            encrypted_hello_request(&sender, receiver_addr, peer_id, 8),
            peer_addr,
        ))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("valid encrypted source-port-53 packet was dropped")
        .expect("subscriber closed");
    assert_eq!(received.from, peer_addr);
    assert!(received.was_obfuscated);
    assert_eq!(received.sender_verify_key, Some(expected_key));

    let state = rpc
        .inner
        .obfuscation
        .inspect_outbound(peer_addr, opcode::PING);
    assert_eq!(state.peer_node_id, Some(peer_id));
    assert_eq!(state.peer_kad_version, Some(8));
    assert_eq!(state.receiver_verify_key, Some(expected_key));
}

#[tokio::test]
async fn flood_banned_response_cannot_learn_metadata_or_consume_pending() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig {
            max_outbound_pps: 1_000,
            request_tracking_window: Duration::from_secs(60),
            ..Default::default()
        },
    );
    let _handle = rpc.start();
    let peer_addr: SocketAddr = "1.2.3.4:4672".parse().unwrap();

    let request_rpc = rpc.clone();
    let request = tokio::spawn(async move {
        request_rpc
            .request(
                peer_addr,
                &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
                    node_id: NodeId::from_bytes([0x11; 16]),
                    tcp_port: 4662,
                    version: 8,
                    tags: Vec::new(),
                }),
                opcode::HELLO_RES,
                Duration::from_secs(60),
            )
            .await
    });
    wait_for_pending(&rpc, 1).await;

    for _ in 0..9 {
        inject_tx
            .send((KadPacket::Ping.encode().unwrap(), peer_addr))
            .await
            .unwrap();
    }
    wait_for_massive_ping_drop(&rpc).await;

    let mut subscriber = rpc.subscribe();
    let rejected_id = NodeId::from_bytes([0x66; 16]);
    let response = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: rejected_id,
        tcp_port: 4662,
        version: 7,
        tags: Vec::new(),
    });
    inject_tx
        .send((response.encode().unwrap(), peer_addr))
        .await
        .unwrap();
    let sentinel_addr: SocketAddr = "8.8.8.8:4672".parse().unwrap();
    inject_tx
        .send((KadPacket::Ping.encode().unwrap(), sentinel_addr))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("sentinel packet was not dispatched")
        .expect("subscriber closed");
    assert_eq!(received.from, sentinel_addr);

    assert_eq!(
        rpc.pending_len(),
        1,
        "banned reply consumed pending request"
    );
    assert!(
        !request.is_finished(),
        "banned reply completed request future"
    );
    let state = rpc
        .inner
        .obfuscation
        .inspect_outbound(peer_addr, opcode::PING);
    assert_eq!(state.peer_node_id, None);
    assert_eq!(state.peer_kad_version, None);
    assert_eq!(state.receiver_verify_key, None);

    request.abort();
    let _ = request.await;
    wait_for_pending(&rpc, 0).await;
}

#[tokio::test]
async fn spoofed_reply_preserves_pending_then_valid_reply_completes_it() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig {
            max_outbound_pps: 1_000,
            ..Default::default()
        },
    );
    let _handle = rpc.start();
    let peer_addr: SocketAddr = "1.2.3.4:4672".parse().unwrap();
    let spoof_addr: SocketAddr = "8.8.8.8:4672".parse().unwrap();

    let request_rpc = rpc.clone();
    let request = tokio::spawn(async move {
        request_rpc
            .request(
                peer_addr,
                &KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
                    node_id: NodeId::from_bytes([0x11; 16]),
                    tcp_port: 4662,
                    version: 8,
                    tags: Vec::new(),
                }),
                opcode::HELLO_RES,
                Duration::from_secs(5),
            )
            .await
    });
    wait_for_pending(&rpc, 1).await;

    let spoofed = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: NodeId::from_bytes([0x99; 16]),
        tcp_port: 4662,
        version: 7,
        tags: Vec::new(),
    });
    inject_tx
        .send((spoofed.encode().unwrap(), spoof_addr))
        .await
        .unwrap();

    let valid_id = NodeId::from_bytes([0x44; 16]);
    let valid = KadPacket::HelloRes(emulebb_kad_proto::HelloRes {
        node_id: valid_id,
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    inject_tx
        .send((valid.encode().unwrap(), peer_addr))
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .expect("valid reply did not complete pending request")
        .expect("request task panicked")
        .expect("valid reply was rejected");
    assert!(matches!(result, KadPacket::HelloRes(response) if response.node_id == valid_id));
    assert_eq!(rpc.pending_len(), 0);

    let spoof_state = rpc
        .inner
        .obfuscation
        .inspect_outbound(spoof_addr, opcode::PING);
    assert_eq!(spoof_state.peer_node_id, None);
    assert_eq!(spoof_state.peer_kad_version, None);
    let valid_state = rpc
        .inner
        .obfuscation
        .inspect_outbound(peer_addr, opcode::PING);
    assert_eq!(valid_state.peer_node_id, Some(valid_id));
    assert_eq!(valid_state.peer_kad_version, Some(8));
}
