use super::*;
use crate::rpc::ForeignDatagramHandler;
use emulebb_kad_proto::{KadPacket, NodeId};
use std::sync::Arc;

/// A datagram that is not a Kad packet (eD2k OP_EMULEPROT + OP_REASKFILEPING +
/// a 16-byte hash) — `KadPacket::decode` rejects the 0xC5 protocol byte, so it
/// lands in the recv loop's decode-failure branch where the foreign handler runs.
fn non_kad_datagram() -> Vec<u8> {
    let mut d = vec![0xC5u8, 0x90];
    d.extend_from_slice(&[0xAB; 16]);
    d
}

#[tokio::test]
async fn foreign_handler_receives_non_kad_datagram() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
    let handler: ForeignDatagramHandler = Arc::new(move |data: &[u8], from: SocketAddr| {
        let _ = tx.send((data.to_vec(), from));
        true // consumed
    });
    assert!(rpc.set_foreign_datagram_handler(handler));
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    let datagram = non_kad_datagram();
    {
        let datagram = datagram.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = inject_tx.send((datagram, peer_addr)).await;
        });
    }

    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
    let (data, from) = got.expect("foreign handler not invoked in time").expect("channel closed");
    assert_eq!(data, datagram);
    assert_eq!(from, peer_addr);
}

#[tokio::test]
async fn foreign_handler_not_invoked_for_valid_kad_packet() {
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let handler: ForeignDatagramHandler = Arc::new(move |_data: &[u8], _from: SocketAddr| {
        let _ = tx.send(());
        true
    });
    rpc.set_foreign_datagram_handler(handler);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let hello = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let _ = inject_tx.send((hello.encode().unwrap(), peer_addr)).await;
    });

    // The Kad packet decodes and is broadcast as unsolicited; the foreign handler
    // must never see it.
    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv()).await;
    assert!(received.is_ok(), "kad packet was not processed");
    assert!(
        rx.try_recv().is_err(),
        "foreign handler was wrongly invoked for a valid Kad packet"
    );
}

#[tokio::test]
async fn foreign_handler_registration_is_at_most_once() {
    let rpc = make_rpc(RpcConfig::default());
    let first: ForeignDatagramHandler = Arc::new(|_: &[u8], _: SocketAddr| true);
    let second: ForeignDatagramHandler = Arc::new(|_: &[u8], _: SocketAddr| false);
    assert!(rpc.set_foreign_datagram_handler(first));
    assert!(
        !rpc.set_foreign_datagram_handler(second),
        "second registration should be rejected"
    );
}

#[tokio::test]
async fn declining_foreign_handler_falls_through_to_decode_failure() {
    // A handler that returns false (did not consume) must not suppress the normal
    // decode-failure path — the loop keeps running and processes later packets.
    let transport = MockTransport::new(make_local_addr());
    let inject_tx = transport.injector();
    let rpc = make_rpc_with_transport(transport);

    let handler: ForeignDatagramHandler = Arc::new(|_: &[u8], _: SocketAddr| false);
    rpc.set_foreign_datagram_handler(handler);
    let mut subscriber = rpc.subscribe();
    let _handle = rpc.start();

    let peer_addr = make_peer_addr();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        // First a non-Kad datagram the handler declines, then a valid Kad packet.
        let mut junk = vec![0xC5u8, 0x90];
        junk.extend_from_slice(&[0xAB; 16]);
        let _ = inject_tx.send((junk, peer_addr)).await;
        let hello = KadPacket::HelloReq(emulebb_kad_proto::HelloReq {
            node_id: NodeId::from_bytes([0x44; 16]),
            tcp_port: 4662,
            version: 8,
            tags: Vec::new(),
        });
        let _ = inject_tx.send((hello.encode().unwrap(), peer_addr)).await;
    });

    // The loop survived the declined datagram and still processes the Kad packet.
    let received = tokio::time::timeout(Duration::from_secs(2), subscriber.recv()).await;
    assert!(received.is_ok(), "recv loop stalled after a declined foreign datagram");
    assert!(matches!(received.unwrap().unwrap().packet, KadPacket::HelloReq(_)));
}
