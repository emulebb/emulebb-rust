use super::*;
use crate::error::NetError;
use emulebb_kad_proto::KadPacket;
use emulebb_kad_proto::constants::opcode;

#[tokio::test]
async fn test_request_response() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // In a background task: wait a bit, then inject a PONG from peer
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let pong = KadPacket::Pong(emulebb_kad_proto::Pong { udp_port: 9999 });
        let encoded = pong.encode().unwrap();
        let _ = inject_tx.send((encoded, peer_addr)).await;
    });

    let result = rpc
        .request(peer_addr, &ping, opcode::PONG, Duration::from_secs(5))
        .await;

    assert!(result.is_ok(), "expected Ok, got {:?}", result);
    assert!(matches!(
        result.unwrap(),
        KadPacket::Pong(emulebb_kad_proto::Pong { udp_port: 9999 })
    ));
}

#[tokio::test]
async fn out_of_order_lookup_and_publish_replies_follow_their_targets() {
    use emulebb_kad_proto::{NodeId, PublishKeyReq, PublishRes, Req, Res};

    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
    );
    let receiver = rpc.start();
    let peer = make_peer_addr();
    let first = NodeId::from_bytes([1; 16]);
    let second = NodeId::from_bytes([2; 16]);

    for expected_opcode in [opcode::RES, opcode::PUBLISH_RES] {
        let mut tasks = Vec::new();
        for target in [first, second] {
            let request = if expected_opcode == opcode::RES {
                KadPacket::Req(Req {
                    count: 2,
                    target,
                    recipient_id: NodeId::ZERO,
                })
            } else {
                KadPacket::PublishKeyReq(PublishKeyReq {
                    target,
                    entries: Vec::new(),
                })
            };
            let rpc = rpc.clone();
            tasks.push(tokio::spawn(async move {
                rpc.request(peer, &request, expected_opcode, Duration::from_secs(3))
                    .await
                    .unwrap()
            }));
            tokio::time::timeout(Duration::from_secs(1), async {
                while transport.drain_outgoing().is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        for target in [second, first] {
            let reply = if expected_opcode == opcode::RES {
                KadPacket::Res(Res {
                    target,
                    contacts: Vec::new(),
                })
            } else {
                KadPacket::PublishRes(PublishRes {
                    target,
                    load: 7,
                    options: None,
                })
            };
            transport.inject(reply.encode().unwrap(), peer).await;
        }
        for (task, expected) in tasks.into_iter().zip([first, second]) {
            let actual = match task.await.unwrap() {
                KadPacket::Res(reply) => reply.target,
                KadPacket::PublishRes(reply) => reply.target,
                other => panic!("unexpected reply: {other:?}"),
            };
            assert_eq!(actual, expected);
        }
    }
    receiver.abort();
}

#[tokio::test]
async fn detached_lookup_correlates_the_target_and_keeps_reply_metadata() {
    use emulebb_kad_proto::{NodeId, Req, Res};

    let transport = Arc::new(MockTransport::new(make_local_addr()));
    let rpc = make_rpc_with_shared_transport(
        Arc::clone(&transport),
        ObfuscationLayer::new(NodeId::ZERO, 0, false),
    );
    let receiver = rpc.start();
    let mut unsolicited = rpc.subscribe();
    let requested_endpoint = make_peer_addr();
    let observed_endpoint = SocketAddr::new(requested_endpoint.ip(), 4672);
    let target = NodeId::from_bytes([1; 16]);

    rpc.send(
        requested_endpoint,
        &KadPacket::Req(Req {
            count: 2,
            target,
            recipient_id: NodeId::ZERO,
        }),
    )
    .await
    .unwrap();
    for reply_target in [NodeId::ZERO, target] {
        let reply = KadPacket::Res(Res {
            target: reply_target,
            contacts: Vec::new(),
        });
        transport
            .inject(reply.encode().unwrap(), observed_endpoint)
            .await;
    }
    let response = tokio::time::timeout(Duration::from_secs(1), unsolicited.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(response.packet, KadPacket::Res(reply) if reply.target == target));
    assert_eq!(response.from, observed_endpoint);
    assert_eq!(rpc.pending_len(), 0);
    receiver.abort();
}

#[tokio::test]
async fn test_request_timeout() {
    let rpc = make_rpc(RpcConfig {
        max_outbound_pps: 0,
        ..Default::default()
    });
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // No response injected — should time out
    let result = rpc
        .request(peer_addr, &ping, opcode::PONG, Duration::from_millis(100))
        .await;

    assert!(matches!(result, Err(NetError::Timeout { .. })));
}

#[tokio::test]
async fn test_aborted_request_cleans_up_pending_entry() {
    // A converged traversal aborts outstanding query tasks while they await the
    // response timeout; the dropped future must still evict its pending entry
    // (RAII pending guard), or the map leaks and inbound RES matching turns O(n).
    let rpc = make_rpc(RpcConfig {
        max_outbound_pps: 1000,
        ..Default::default()
    });
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let rpc_for_task = rpc.clone();
    // Long timeout so the request is still parked in `timeout(rx)` when aborted.
    let task = tokio::spawn(async move {
        let ping = KadPacket::Ping;
        let _ = rpc_for_task
            .request(peer_addr, &ping, opcode::PONG, Duration::from_secs(60))
            .await;
    });

    // Let the task insert its pending entry and reach the await point.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(rpc.pending_len(), 1, "request should have a pending entry");

    // Abort mid-flight, mirroring JoinSet::abort_all on lookup convergence.
    task.abort();
    let _ = task.await;

    // The dropped request future's guard must have removed the entry.
    assert_eq!(
        rpc.pending_len(),
        0,
        "aborted request future must remove its pending entry"
    );
}

#[tokio::test]
async fn test_rate_limiter() {
    let rpc = make_rpc(RpcConfig {
        max_outbound_pps: 1000,
        ..Default::default()
    });
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let ping = KadPacket::Ping;

    // Send 5 packets rapidly — all should succeed with high PPS limit
    for _ in 0..5 {
        let result = rpc.send(peer_addr, &ping).await;
        assert!(result.is_ok());
    }
}
