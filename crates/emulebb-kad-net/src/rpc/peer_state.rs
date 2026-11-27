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
            .snapshot(self.inner.max_outbound_pps, self.inner.class_budgets)
    }

    /// Register a peer's announced receiver verify key for obfuscated replies.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        self.inner.obfuscation.register_peer_key(addr, key);
    }

    /// Fill an absent restored key without replacing live key evidence.
    pub fn register_peer_key_if_absent(&self, addr: SocketAddr, key: u32) {
        self.inner
            .obfuscation
            .register_peer_key_if_absent(addr, key);
    }

    /// Clear all peer receiver keys after our public IPv4 binding changes and
    /// control whether newly observed keys may be retained under that binding.
    pub fn reset_peer_keys(&self, accept_new_keys: bool) {
        self.inner
            .udp_probe_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.obfuscation.reset_peer_keys(accept_new_keys);
    }

    /// Freeze key learning without discarding the saved binding.
    pub fn seal_peer_keys(&self) {
        self.inner.obfuscation.seal_peer_keys();
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

    /// Capture a batch of learned keys with their generation and binding epoch.
    pub fn capture_peer_keys(&self, lookups: &mut [(Ipv4Addr, Option<u32>)]) -> Option<(u64, u64)> {
        self.inner.obfuscation.capture_peer_keys(lookups)
    }

    /// Register a peer's Kad node ID for request-obfuscation fallback when no
    /// receiver verify key is known yet.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: emulebb_kad_proto::NodeId) {
        self.inner.obfuscation.register_peer_identity(addr, node_id);
    }

    /// Restore an absent peer identity without replacing live evidence.
    pub fn register_peer_identity_if_absent(
        &self,
        addr: SocketAddr,
        node_id: emulebb_kad_proto::NodeId,
    ) {
        self.inner
            .obfuscation
            .register_peer_identity_if_absent(addr, node_id);
    }

    /// Register the peer Kad version so outbound transport shape can match the oracle gates.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        self.inner
            .obfuscation
            .register_peer_version(addr, kad_version);
    }

    /// Restore a peer version without lowering an already learned version.
    pub fn register_peer_version_if_higher(&self, addr: SocketAddr, kad_version: u8) {
        self.inner
            .obfuscation
            .register_peer_version_if_higher(addr, kad_version);
    }
}
