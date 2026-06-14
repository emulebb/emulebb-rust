use super::*;
use crate::obfuscation::ObfuscationLayer;
use crate::transport::MockTransport;
use std::sync::Arc;

mod flood_observability;
mod foreign_datagram;
mod obfuscation;
mod request_response;
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
