use crate::obfuscation::ObfuscationLayer;
use emulebb_kad_proto::NodeId;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::time::Instant;

/// Hard ceiling on each obfuscation peer map. The runtime touches one entry per
/// distinct inbound endpoint and per distinct outbound destination, and neither
/// map was ever pruned, so a long-lived node accumulated state for every
/// endpoint it ever exchanged a packet with. The active routing/working set is
/// far smaller than this; the cap simply guarantees the maps stay bounded by
/// evicting the least-recently-touched entry once exceeded.
pub(super) const PEER_MAP_CAP: usize = 50_000;

#[derive(Debug, Clone, Default)]
pub(super) struct PeerCryptoState {
    /// Target node ID used for NodeID-based request obfuscation.
    node_id: Option<NodeId>,
    /// Highest Kad version we have seen this peer advertise.
    kad_version: Option<u8>,
    /// When this entry was last inserted/updated, for LRU-style eviction.
    last_seen: Option<Instant>,
}

/// Receiver verify key learned for a peer IP, tagged with a last-seen instant so
/// the key map can be bounded with the same LRU-style eviction as `peers`.
#[derive(Debug, Clone, Copy)]
pub(super) struct VerifyKeyEntry {
    pub(super) key: u32,
    last_seen: Instant,
}

/// Evict the least-recently-seen entry from `map` while it is over `cap`. Called
/// after each insert so the map size never exceeds `cap`. O(n) over the map, but
/// only runs on the rare over-cap insert.
fn evict_over_cap<K, V>(map: &mut HashMap<K, V>, cap: usize, last_seen: impl Fn(&V) -> Instant)
where
    K: Eq + Hash + Clone,
{
    while map.len() > cap {
        let oldest = map
            .iter()
            .min_by_key(|(_, value)| last_seen(value))
            .map(|(k, _)| k.clone());
        match oldest {
            Some(key) => {
                map.remove(&key);
            }
            None => break,
        }
    }
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
        let entry = guard.entry(addr).or_default();
        entry.node_id = Some(node_id);
        entry.last_seen = Some(Instant::now());
        evict_over_cap(&mut guard, PEER_MAP_CAP, |state| {
            state.last_seen.unwrap_or_else(Instant::now)
        });
    }

    /// Register the peer Kad version so outbound obfuscation can follow the
    /// same version gates as the oracle UDP sender.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        let mut guard = self.peers.lock().unwrap();
        let entry = guard.entry(addr).or_default();
        entry.kad_version = Some(kad_version);
        entry.last_seen = Some(Instant::now());
        evict_over_cap(&mut guard, PEER_MAP_CAP, |state| {
            state.last_seen.unwrap_or_else(Instant::now)
        });
    }

    /// Register the latest sender verify key learned from an obfuscated packet.
    ///
    /// The oracle stores this as the peer's `CKadUDPKey` value bound to our own
    /// public IP and reuses it for reply packets.
    pub fn register_peer_key(&self, addr: SocketAddr, key: u32) {
        let mut guard = self.receiver_verify_keys.lock().unwrap();
        guard.insert(
            addr.ip(),
            VerifyKeyEntry {
                key,
                last_seen: Instant::now(),
            },
        );
        evict_over_cap(&mut guard, PEER_MAP_CAP, |entry| entry.last_seen);
    }

    /// Return the latest receiver verify key learned for the peer IP behind this endpoint.
    #[must_use]
    pub fn receiver_verify_key_for_addr(&self, addr: SocketAddr) -> Option<u32> {
        self.receiver_verify_keys
            .lock()
            .unwrap()
            .get(&addr.ip())
            .map(|entry| entry.key)
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
            .map(|entry| entry.key);
        ResolvedPeerCryptoState {
            receiver_verify_key,
            node_id: peer.node_id,
            kad_version: peer.kad_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn evict_over_cap_keeps_map_bounded_and_drops_oldest() {
        // Build a map with strictly increasing last-seen instants keyed 0..=5, so
        // key 0 is the oldest. With a cap of 3, eviction must shed the three
        // oldest (0,1,2) and keep the three newest (3,4,5).
        let base = Instant::now();
        let mut map: HashMap<u32, VerifyKeyEntry> = HashMap::new();
        for i in 0u32..6 {
            map.insert(
                i,
                VerifyKeyEntry {
                    key: i,
                    last_seen: base + Duration::from_millis(u64::from(i)),
                },
            );
        }

        evict_over_cap(&mut map, 3, |entry| entry.last_seen);

        assert_eq!(map.len(), 3, "map must be bounded to the cap");
        assert!(!map.contains_key(&0), "oldest entry must be evicted");
        assert!(!map.contains_key(&1));
        assert!(!map.contains_key(&2));
        assert!(map.contains_key(&3), "newest entries must survive");
        assert!(map.contains_key(&4));
        assert!(map.contains_key(&5));
    }

    #[test]
    fn register_peer_key_stays_bounded_past_cap() {
        // Drive the real receiver-verify-key map a few inserts past the cap and
        // confirm it never exceeds it (LRU-style eviction on every over-cap insert).
        let layer = ObfuscationLayer::new(NodeId::ZERO, 0, true);
        let total = PEER_MAP_CAP + 16;
        for i in 0..total {
            let octets = (i as u32).to_be_bytes();
            let ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]));
            layer.register_peer_key(SocketAddr::new(ip, 4000), i as u32);
        }
        assert_eq!(
            layer.receiver_verify_keys.lock().unwrap().len(),
            PEER_MAP_CAP,
            "receiver verify key map must stay at the cap"
        );
    }
}
