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
