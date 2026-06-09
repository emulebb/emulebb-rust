use std::net::{Ipv4Addr, SocketAddr};

use tokio::sync::broadcast;

use super::{ReceivedKadPacket, RpcManager, RpcObservabilitySnapshot};
use crate::error::NetError;

impl RpcManager {
    /// Subscribe to unsolicited incoming packets (HELLOs, PINGs, search requests, etc.)
    /// Packets that match a pending request are NOT broadcast here.
    pub fn subscribe(&self) -> broadcast::Receiver<ReceivedKadPacket> {
        self.inner.unsolicited_tx.subscribe()
    }

    /// Local UDP bind address.
    pub fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.inner.transport.local_addr().map_err(NetError::Io)
    }

    /// Snapshot the current tracker and response-handling counters.
    #[must_use]
    pub fn observability(&self) -> RpcObservabilitySnapshot {
        self.inner
            .observability
            .lock()
            .unwrap()
            .snapshot(self.inner.max_outbound_pps, self.inner.class_budgets)
    }

    /// Register a peer's announced receiver verify key for obfuscated replies.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        self.inner.obfuscation.register_peer_key(addr, key);
    }

    /// Derive the verify key we should announce to a specific IPv4 peer.
    #[must_use]
    pub fn verify_key_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.inner.obfuscation.verify_key_for_ip(ip)
    }

    /// Return the latest receiver verify key learned for the peer IP behind this endpoint.
    #[must_use]
    pub fn known_peer_key(&self, addr: SocketAddr) -> Option<u32> {
        self.inner.obfuscation.receiver_verify_key_for_addr(addr)
    }

    /// Register a peer's Kad node ID for request-obfuscation fallback when no
    /// receiver verify key is known yet.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: emulebb_kad_proto::NodeId) {
        self.inner.obfuscation.register_peer_identity(addr, node_id);
    }

    /// Register the peer Kad version so outbound transport shape can match the oracle gates.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        self.inner
            .obfuscation
            .register_peer_version(addr, kad_version);
    }
}
