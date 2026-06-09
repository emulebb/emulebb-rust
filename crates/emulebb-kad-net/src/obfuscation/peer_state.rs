use crate::obfuscation::ObfuscationLayer;
use emulebb_kad_proto::NodeId;
use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub(super) struct PeerCryptoState {
    /// Target node ID used for NodeID-based request obfuscation.
    node_id: Option<NodeId>,
    /// Highest Kad version we have seen this peer advertise.
    kad_version: Option<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ResolvedPeerCryptoState {
    /// Latest sender verify key learned from any peer endpoint on this IP.
    /// The oracle binds this key to the public IP, not the UDP port tuple.
    pub(super) receiver_verify_key: Option<u32>,
    /// Target node ID used for NodeID-based request obfuscation.
    pub(super) node_id: Option<NodeId>,
    /// Highest Kad version we have seen this peer advertise.
    pub(super) kad_version: Option<u8>,
}

impl ObfuscationLayer {
    /// Register a peer node ID so outbound requests can use NodeID-based Kad obfuscation.
    pub fn register_peer_identity(&self, addr: SocketAddr, node_id: NodeId) {
        let mut guard = self.peers.lock().unwrap();
        guard.entry(addr).or_default().node_id = Some(node_id);
    }

    /// Register the peer Kad version so outbound obfuscation can follow the
    /// same version gates as the oracle UDP sender.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        let mut guard = self.peers.lock().unwrap();
        guard.entry(addr).or_default().kad_version = Some(kad_version);
    }

    /// Register the latest sender verify key learned from an obfuscated packet.
    ///
    /// The oracle stores this as the peer's `CKadUDPKey` value bound to our own
    /// public IP and reuses it for reply packets.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        self.receiver_verify_keys
            .lock()
            .unwrap()
            .insert(addr.ip(), key);
    }

    /// Return the latest receiver verify key learned for the peer IP behind this endpoint.
    #[must_use]
    pub fn receiver_verify_key_for_addr(&self, addr: SocketAddr) -> Option<u32> {
        self.receiver_verify_keys
            .lock()
            .unwrap()
            .get(&addr.ip())
            .copied()
    }

    pub(super) fn peer_state_for_addr(&self, addr: SocketAddr) -> ResolvedPeerCryptoState {
        let peer = self
            .peers
            .lock()
            .unwrap()
            .get(&addr)
            .cloned()
            .unwrap_or_default();
        let receiver_verify_key = self
            .receiver_verify_keys
            .lock()
            .unwrap()
            .get(&addr.ip())
            .copied();
        ResolvedPeerCryptoState {
            receiver_verify_key,
            node_id: peer.node_id,
            kad_version: peer.kad_version,
        }
    }
}
