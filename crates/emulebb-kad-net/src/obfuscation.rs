//! Kad UDP obfuscation state and encrypt/decrypt helpers.
//!
//! The oracle chooses between plaintext, NodeID-mode obfuscation, and
//! receiver-verify-key obfuscation based on what it currently knows about a
//! peer. This module keeps that per-peer state and exposes the exact transport
//! mode decision used by the runtime.

mod crypto;
mod inbound;
mod outbound;
mod peer_state;

#[cfg(test)]
mod tests;

use emulebb_kad_proto::NodeId;
use peer_state::{PeerCryptoState, VerifyKeyEntry};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

/// Kad UDP obfuscation sync constant used by the oracle `EncryptedDatagramSocket`.
const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;

/// Marker value used when the packet is encrypted with the receiver verify key.
const KAD_MARKER_RECEIVER_KEY: u8 = 0x02;

/// Padding is disabled in the oracle UDP path today, but the parser still
/// accepts it so we keep the same shape here.
const UDP_PADDING_LEN: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KadKeyMode {
    NodeId,
    ReceiverVerifyKey,
}

/// Result of attempting to decrypt an incoming packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptResult {
    /// Decrypted Kad payload, or the original buffer when no obfuscation was used.
    pub data: Vec<u8>,
    /// Whether the packet was successfully parsed as obfuscated Kad UDP.
    pub was_obfuscated: bool,
    /// Sender verify key recovered from the encrypted trailer.
    pub sender_verify_key: Option<u32>,
    /// Whether the packet proved our receiver verify key instead of using
    /// NodeID-mode request obfuscation.
    pub receiver_verify_key_valid: bool,
}

/// Outbound Kad UDP encryption mode chosen for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKadEncryptionMode {
    /// No Kad UDP obfuscation will be applied.
    Plaintext,
    /// NodeID-based Kad obfuscation will be used.
    NodeId,
    /// Receiver verify-key Kad obfuscation will be used.
    ReceiverVerifyKey,
}

impl OutboundKadEncryptionMode {
    /// Stable string form used by wire-observability logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::NodeId => "node_id",
            Self::ReceiverVerifyKey => "receiver_verify_key",
        }
    }
}

/// Snapshot of the peer crypto context used to decide outbound Kad UDP transport shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundKadEncryptionInfo {
    /// Final encryption mode the runtime will use for this destination.
    pub mode: OutboundKadEncryptionMode,
    /// Known Kad node ID for the peer, when available.
    pub peer_node_id: Option<NodeId>,
    /// Highest Kad version observed for the peer, when available.
    pub peer_kad_version: Option<u8>,
    /// Latest receiver verify key learned from this peer, when available.
    pub receiver_verify_key: Option<u32>,
    /// Verify key this node would announce to the destination peer.
    pub sender_verify_key: Option<u32>,
}

/// Oracle-shaped Kad UDP obfuscation layer.
///
/// This mirrors the Kad branch of eMule/aMule `EncryptedDatagramSocket`:
/// when a usable peer NodeID is available it stays the preferred Kad crypt
/// target for outbound packets, and the learned receiver verify key only takes
/// over when no usable NodeID context exists for that destination.
pub struct ObfuscationLayer {
    our_node_id: NodeId,
    our_udp_key: u32,
    enabled: bool,
    peers: Mutex<HashMap<SocketAddr, PeerCryptoState>>,
    receiver_verify_keys: Mutex<HashMap<IpAddr, VerifyKeyEntry>>,
}

impl ObfuscationLayer {
    /// Create a Kad UDP obfuscation layer with local node identity and key state.
    pub fn new(our_node_id: NodeId, our_udp_key: u32, enabled: bool) -> Self {
        Self {
            our_node_id,
            our_udp_key,
            enabled,
            peers: Mutex::new(HashMap::new()),
            receiver_verify_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Return whether Kad UDP obfuscation is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Our locally generated Kad UDP anti-spoofing seed.
    pub fn our_udp_key(&self) -> u32 {
        self.our_udp_key
    }
}
