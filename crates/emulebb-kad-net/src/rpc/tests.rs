use super::*;
use crate::obfuscation::ObfuscationLayer;
use crate::transport::MockTransport;
use std::sync::Arc;

mod flood_observability;
mod foreign_datagram;
mod obfuscation;
mod request_response;
mod search_response_correlation;
mod unsolicited;

fn make_local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn make_peer_addr() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
}

fn make_rpc(config: RpcConfig) -> RpcManager {
    let transport = MockTransport::new(make_local_addr());
    let obfuscation = ObfuscationLayer::new(emulebb_kad_proto::NodeId::ZERO, 0, false);
    RpcManager::new(transport, obfuscation, config)
}

fn make_rpc_with_transport(transport: MockTransport) -> RpcManager {
    let obfuscation = ObfuscationLayer::new(emulebb_kad_proto::NodeId::ZERO, 0, false);
    RpcManager::new(transport, obfuscation, RpcConfig::default())
}

fn make_rpc_with_shared_transport(
    transport: Arc<MockTransport>,
    obfuscation: ObfuscationLayer,
) -> RpcManager {
    RpcManager::new(transport, obfuscation, RpcConfig::default())
}

#[test]
fn kad_contact_liveness_expires_and_is_cleared_when_stopped() {
    let rpc = make_rpc(RpcConfig::default());
    *rpc.inner.last_contact_at.lock() =
        Some(std::time::Instant::now() - KAD_CONTACT_LIVENESS + Duration::from_secs(1));
    assert!(rpc.has_had_contact());

    *rpc.inner.last_contact_at.lock() = Some(std::time::Instant::now() - KAD_CONTACT_LIVENESS);
    assert!(!rpc.has_had_contact());

    *rpc.inner.last_contact_at.lock() = Some(std::time::Instant::now());
    rpc.set_kad_enabled(false);
    assert!(!rpc.has_had_contact());
    assert!(rpc.inner.last_contact_at.lock().is_none());
}
