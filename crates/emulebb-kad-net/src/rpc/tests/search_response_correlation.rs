use super::*;
use emulebb_kad_proto::{KadPacket, NodeId, SearchRes, constants::opcode};

fn search_response(target: NodeId) -> KadPacket {
    KadPacket::SearchRes(SearchRes {
        sender_id: NodeId::from_bytes([0x44; 16]),
        target,
        results: Vec::new(),
    })
}

fn dropped_search_responses(rpc: &RpcManager) -> u64 {
    let opcode_name = crate::rpc::packet_info::opcode_name(opcode::SEARCH_RES);
    rpc.observability()
        .response_opcodes
        .iter()
        .find(|snapshot| snapshot.opcode == opcode_name)
        .map_or(0, |snapshot| snapshot.dropped_unrequested)
}

async fn wait_for_dropped_search_responses(rpc: &RpcManager, expected: u64) {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if dropped_search_responses(rpc) >= expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("receive loop records rejected SEARCH_RES");
}

#[tokio::test]
async fn unsolicited_flood_does_not_consume_registered_response_budget() {
    let transport = MockTransport::new(make_local_addr());
    let injector = transport.injector();
    let rpc = RpcManager::new(
        transport,
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
        RpcConfig {
            max_inbound_search_res_per_ip: 1,
            flood_window: Duration::from_secs(60),
            ..Default::default()
        },
    );
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();
    let endpoint: SocketAddr = "1.2.3.4:4672".parse().unwrap();
    let target = NodeId::from_bytes([0x55; 16]);
    let encoded = search_response(target).encode().unwrap();

    for _ in 0..8 {
        injector.send((encoded.clone(), endpoint)).await.unwrap();
    }
    wait_for_dropped_search_responses(&rpc, 8).await;

    assert!(
        rpc.observability()
            .tracker_buckets
            .iter()
            .all(|bucket| bucket.bucket != "search_res"),
        "unregistered responses must not charge the SEARCH_RES tracker"
    );

    let _registration = rpc.register_search_response(target, endpoint);
    injector.send((encoded, endpoint)).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("registered response broadcast")
        .expect("broadcast remains open");
    assert_eq!(received.from, endpoint);
    assert!(matches!(received.packet, KadPacket::SearchRes(response) if response.target == target));

    let search_res_bucket = rpc
        .observability()
        .tracker_buckets
        .into_iter()
        .find(|bucket| bucket.bucket == "search_res")
        .expect("legitimate response charged the retained tracker");
    assert_eq!(search_res_bucket.accepted_requests, 1);
    assert_eq!(search_res_bucket.tracker_drops, 0);
}

#[tokio::test]
async fn wrong_target_and_endpoint_are_rejected() {
    let transport = MockTransport::new(make_local_addr());
    let injector = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();
    let endpoint: SocketAddr = "1.2.3.4:4672".parse().unwrap();
    let wrong_endpoint: SocketAddr = "1.2.3.4:4673".parse().unwrap();
    let target = NodeId::from_bytes([0x11; 16]);
    let wrong_target = NodeId::from_bytes([0x22; 16]);
    let _registration = rpc.register_search_response(target, endpoint);

    injector
        .send((search_response(wrong_target).encode().unwrap(), endpoint))
        .await
        .unwrap();
    injector
        .send((search_response(target).encode().unwrap(), wrong_endpoint))
        .await
        .unwrap();
    wait_for_dropped_search_responses(&rpc, 2).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), subscriber.recv())
            .await
            .is_err(),
        "mismatched responses must not reach the broadcast channel"
    );

    injector
        .send((search_response(target).encode().unwrap(), endpoint))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("matching response broadcast")
        .expect("broadcast remains open");
    assert_eq!(received.from, endpoint);
}

#[tokio::test]
async fn concurrent_registrations_are_refcounted_and_cleanup_rejects_late_responses() {
    let transport = MockTransport::new(make_local_addr());
    let injector = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();
    let endpoint: SocketAddr = "1.2.3.4:4672".parse().unwrap();
    let target = NodeId::from_bytes([0x77; 16]);
    let first = rpc.register_search_response(target, endpoint);
    let second = rpc.register_search_response(target, endpoint);

    drop(first);
    injector
        .send((search_response(target).encode().unwrap(), endpoint))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .expect("remaining registration accepts response")
        .expect("broadcast remains open");

    drop(second);
    injector
        .send((search_response(target).encode().unwrap(), endpoint))
        .await
        .unwrap();
    wait_for_dropped_search_responses(&rpc, 1).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), subscriber.recv())
            .await
            .is_err(),
        "last guard drop must remove the correlation"
    );
}
