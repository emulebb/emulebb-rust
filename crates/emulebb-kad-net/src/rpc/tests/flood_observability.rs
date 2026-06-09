use super::*;
use emulebb_kad_proto::{KadPacket, NodeId};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

#[tokio::test]
async fn test_flood_blocking() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(emulebb_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            max_inbound_per_ip: 20,
            flood_window: Duration::from_secs(1),
            broadcast_capacity: 256,
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let pong = KadPacket::Pong(emulebb_kad_proto::Pong { udp_port: 9999 });
    let encoded = pong.encode().unwrap();

    // Inject 100 packets — untracked responses should be dropped.
    let total = 100usize;
    for _ in 0..total {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    // Collect what we get within a short window
    let mut received_count = 0usize;
    let collect_timeout = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + collect_timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, subscriber.recv()).await {
            Ok(Ok(_)) => received_count += 1,
            _ => break,
        }
    }

    assert!(
        received_count == 0,
        "received {} packets, expected no unsolicited tracked responses",
        received_count
    );
}

#[tokio::test]
async fn test_search_res_uses_higher_flood_budget() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(emulebb_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            max_inbound_per_ip: 20,
            max_inbound_search_res_per_ip: 64,
            flood_window: Duration::from_secs(1),
            broadcast_capacity: 256,
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let packet = KadPacket::SearchRes(emulebb_kad_proto::SearchRes {
        sender_id: NodeId::from_bytes([0x44; 16]),
        target: NodeId::from_bytes([0x55; 16]),
        results: Vec::new(),
    });
    let encoded = packet.encode().unwrap();

    for _ in 0..40usize {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    let mut received_count = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, subscriber.recv()).await {
            Ok(Ok(_)) => received_count += 1,
            _ => break,
        }
    }

    assert!(
        received_count >= 40,
        "received {} SEARCH_RES packets, expected all 40 to pass",
        received_count
    );
}

#[tokio::test]
async fn test_massive_flood_invokes_handler_and_counts_tracker_actions() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let massive_flood_hits = Arc::new(AtomicU64::new(0));
    let massive_flood_hits_for_handler = Arc::clone(&massive_flood_hits);
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(emulebb_kad_proto::NodeId::ZERO, 0, false),
        RpcConfig {
            request_tracking_window: Duration::from_secs(60),
            massive_flood_handler: Some(Arc::new(move |_| {
                massive_flood_hits_for_handler.fetch_add(1, AtomicOrdering::Relaxed);
            })),
            ..Default::default()
        },
    );
    let _handle = rpc.start();

    let peer_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
    let hello = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
        node_id: NodeId::from_bytes([0x44; 16]),
        tcp_port: 4662,
        version: 8,
        tags: Vec::new(),
    });
    let encoded = hello.encode().unwrap();

    for _ in 0..13usize {
        let _ = inject_tx.send((encoded.clone(), peer_addr)).await;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snapshot = rpc.observability();
    let hello_bucket = snapshot
        .tracker_buckets
        .iter()
        .find(|bucket| bucket.bucket == "hello_req")
        .expect("hello bucket present");
    assert_eq!(hello_bucket.accepted_requests, 3);
    assert_eq!(hello_bucket.tracker_drops, 9);
    assert_eq!(hello_bucket.tracker_massive_drops, 1);
    assert_eq!(massive_flood_hits.load(AtomicOrdering::Relaxed), 1);
}

#[tokio::test]
async fn test_observability_tracks_outbound_work_classes() {
    let transport = MockTransport::new(make_local_addr());
    let rpc = make_rpc_with_transport(transport);
    let peer_addr = make_peer_addr();

    rpc.send_with_class(peer_addr, &KadPacket::Ping, RpcWorkClass::Harvest)
        .await
        .unwrap();
    rpc.send_with_class(peer_addr, &KadPacket::Ping, RpcWorkClass::Publish)
        .await
        .unwrap();

    let snapshot = rpc.observability();
    assert_eq!(
        snapshot.global_max_outbound_pps,
        RpcConfig::default().max_outbound_pps
    );
    assert_eq!(snapshot.work_classes.len(), 4);

    let harvest = snapshot
        .work_classes
        .iter()
        .find(|work_class| work_class.class == RpcWorkClass::Harvest)
        .expect("harvest class present");
    assert_eq!(harvest.sent_packets, 1);
    assert!(harvest.last_sent_at.is_some());

    let publish = snapshot
        .work_classes
        .iter()
        .find(|work_class| work_class.class == RpcWorkClass::Publish)
        .expect("publish class present");
    assert_eq!(publish.sent_packets, 1);
    assert!(publish.last_sent_at.is_some());
}
