use crate::obfuscation::ObfuscationLayer;
use emulebb_kad_proto::NodeId;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
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

pub(super) struct ReceiverKeys {
    entries: HashMap<std::net::IpAddr, VerifyKeyEntry>,
    generation: Option<u64>,
    sealed: bool,
}

impl Default for ReceiverKeys {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            generation: Some(0),
            sealed: false,
        }
    }
}

impl ReceiverKeys {
    fn changed(&mut self) {
        self.generation = self
            .generation
            .and_then(|generation| generation.checked_add(1));
    }
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
        let mut guard = self.peers.lock();
        let entry = guard.entry(addr).or_default();
        entry.node_id = Some(node_id);
        entry.last_seen = Some(Instant::now());
        evict_over_cap(&mut guard, PEER_MAP_CAP, |state| {
            state.last_seen.unwrap_or_else(Instant::now)
        });
    }

    /// Fill an absent peer identity without replacing live evidence.
    pub fn register_peer_identity_if_absent(&self, addr: SocketAddr, node_id: NodeId) {
        let mut guard = self.peers.lock();
        let entry = guard.entry(addr).or_default();
        entry.node_id.get_or_insert(node_id);
        entry.last_seen = Some(Instant::now());
        evict_over_cap(&mut guard, PEER_MAP_CAP, |state| {
            state.last_seen.unwrap_or_else(Instant::now)
        });
    }

    /// Register the peer Kad version so outbound obfuscation can follow the
    /// same version gates as the oracle UDP sender.
    pub fn register_peer_version(&self, addr: SocketAddr, kad_version: u8) {
        let mut guard = self.peers.lock();
        let entry = guard.entry(addr).or_default();
        entry.kad_version = Some(kad_version);
        entry.last_seen = Some(Instant::now());
        evict_over_cap(&mut guard, PEER_MAP_CAP, |state| {
            state.last_seen.unwrap_or_else(Instant::now)
        });
    }

    /// Preserve a newer live version while restoring durable routing evidence.
    pub fn register_peer_version_if_higher(&self, addr: SocketAddr, kad_version: u8) {
        let mut guard = self.peers.lock();
        let entry = guard.entry(addr).or_default();
        entry.kad_version = Some(
            entry
                .kad_version
                .map_or(kad_version, |current| current.max(kad_version)),
        );
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
        let epoch = self.peer_key_epoch();
        self.register_peer_key_at_epoch(addr, key, epoch);
    }

    pub(crate) fn peer_key_epoch(&self) -> u64 {
        self.peer_key_epoch.load(Ordering::Acquire)
    }

    pub(crate) fn register_peer_key_at_epoch(&self, addr: SocketAddr, key: u32, epoch: u64) {
        self.register_peer_key_at_epoch_inner(addr, key, epoch, false);
    }

    /// Fill an absent key without replacing newer live key evidence.
    pub fn register_peer_key_if_absent(&self, addr: SocketAddr, key: u32) {
        self.register_peer_key_at_epoch_inner(addr, key, self.peer_key_epoch(), true);
    }

    fn register_peer_key_at_epoch_inner(
        &self,
        addr: SocketAddr,
        key: u32,
        epoch: u64,
        only_if_absent: bool,
    ) {
        if !self.peer_key_learning_enabled.load(Ordering::Acquire) {
            return;
        }
        let mut guard = self.receiver_verify_keys.lock();
        // WHY: a packet admitted before an address reset can be delayed on the
        // map lock. Its old binding must not repopulate the new key epoch.
        if guard.sealed
            || !self.peer_key_learning_enabled.load(Ordering::Acquire)
            || epoch == u64::MAX
            || self.peer_key_epoch.load(Ordering::Acquire) != epoch
        {
            return;
        }
        let entry = VerifyKeyEntry {
            key,
            last_seen: Instant::now(),
        };
        let old = guard.entries.get(&addr.ip()).map(|entry| entry.key);
        if only_if_absent {
            guard.entries.entry(addr.ip()).or_insert(entry);
        } else {
            guard.entries.insert(addr.ip(), entry);
        }
        if old != guard.entries.get(&addr.ip()).map(|entry| entry.key) {
            guard.changed();
        }
        if guard.entries.len() > PEER_MAP_CAP {
            let oldest = guard
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                guard.entries.remove(&ip);
                guard.changed();
            }
        }
    }

    /// Forget every receiver verify key. Persisted Kad keys are bound to our
    /// public IPv4 address, so a public-address change must invalidate the live
    /// lookup map before any key can be reused.
    pub fn reset_peer_keys(&self, accept_new_keys: bool) {
        // Disable first so the receive loop cannot repopulate the map between
        // the clear and the new binding becoming active.
        let mut keys = self.receiver_verify_keys.lock();
        if keys.sealed {
            return;
        }
        self.peer_key_learning_enabled
            .store(false, Ordering::Release);
        let epoch = self.peer_key_epoch.load(Ordering::Acquire);
        let next = epoch.checked_add(1).unwrap_or(u64::MAX);
        self.peer_key_epoch.store(next, Ordering::Release);
        if !keys.entries.is_empty() {
            keys.entries.clear();
            keys.changed();
        }
        self.peer_key_learning_enabled
            .store(accept_new_keys && next != u64::MAX, Ordering::Release);
    }

    /// Freeze learned keys at the final persistence boundary.
    pub fn seal_peer_keys(&self) {
        let mut keys = self.receiver_verify_keys.lock();
        keys.sealed = true;
        self.peer_key_learning_enabled
            .store(false, Ordering::Release);
    }

    /// Return the latest receiver verify key learned for the peer IP behind this endpoint.
    #[must_use]
    pub fn receiver_verify_key_for_addr(&self, addr: SocketAddr) -> Option<u32> {
        self.receiver_verify_keys
            .lock()
            .entries
            .get(&addr.ip())
            .map(|entry| entry.key)
    }

    /// Capture key lookups and both counters under one key-map lock.
    pub fn capture_peer_keys(
        &self,
        lookups: &mut [(std::net::Ipv4Addr, Option<u32>)],
    ) -> Option<(u64, u64)> {
        let keys = self.receiver_verify_keys.lock();
        let epoch = self.peer_key_epoch.load(Ordering::Acquire);
        if epoch == u64::MAX {
            return None;
        }
        let generation = keys.generation?;
        for (ip, key) in lookups {
            *key = keys
                .entries
                .get(&std::net::IpAddr::V4(*ip))
                .map(|entry| entry.key);
        }
        Some((generation, epoch))
    }

    pub(super) fn peer_state_for_addr(&self, addr: SocketAddr) -> ResolvedPeerCryptoState {
        let peer = self.peers.lock().get(&addr).cloned().unwrap_or_default();
        let receiver_verify_key = self
            .receiver_verify_keys
            .lock()
            .entries
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
    fn key_generation_ignores_refresh_and_tracks_reset_and_exhaustion() {
        let layer = ObfuscationLayer::new(NodeId::ZERO, 1, true);
        let peer: SocketAddr = "192.0.2.1:20020".parse().unwrap();
        let mut lookups = [("192.0.2.1".parse().unwrap(), None)];
        assert_eq!(layer.capture_peer_keys(&mut lookups), Some((0, 0)));
        layer.register_peer_key(peer, 11);
        assert_eq!(layer.capture_peer_keys(&mut lookups), Some((1, 0)));
        assert_eq!(lookups[0].1, Some(11));
        layer.register_peer_key(peer, 11);
        assert_eq!(layer.capture_peer_keys(&mut lookups), Some((1, 0)));
        layer.register_peer_key(peer, 12);
        assert_eq!(layer.capture_peer_keys(&mut lookups), Some((2, 0)));
        layer.reset_peer_keys(true);
        assert_eq!(layer.capture_peer_keys(&mut lookups), Some((3, 1)));
        assert_eq!(lookups[0].1, None);
        layer.receiver_verify_keys.lock().generation = Some(u64::MAX);
        layer.register_peer_key(peer, 13);
        assert_eq!(layer.capture_peer_keys(&mut lookups), None);
    }

    #[test]
    fn exhausted_binding_epoch_never_accepts_an_old_registration() {
        let layer = ObfuscationLayer::new(NodeId::ZERO, 1, true);
        let peer: SocketAddr = "192.0.2.1:20020".parse().unwrap();
        layer.peer_key_epoch.store(u64::MAX - 1, Ordering::Release);
        layer.reset_peer_keys(true);
        layer.register_peer_key(peer, 7);
        assert_eq!(layer.receiver_verify_key_for_addr(peer), None);
        assert_eq!(layer.capture_peer_keys(&mut []), None);
    }

    #[test]
    fn delayed_registration_cannot_cross_a_key_reset() {
        let layer = ObfuscationLayer::new(NodeId::ZERO, 1, true);
        let peer: SocketAddr = "192.0.2.1:20020".parse().unwrap();
        let old_epoch = layer.peer_key_epoch();
        layer.reset_peer_keys(true);
        layer.register_peer_key_at_epoch(peer, 11, old_epoch);
        assert_eq!(layer.receiver_verify_key_for_addr(peer), None);
        layer.register_peer_key(peer, 22);
        assert_eq!(layer.receiver_verify_key_for_addr(peer), Some(22));
    }

    #[test]
    fn restored_peer_fields_do_not_replace_live_evidence() {
        let layer = ObfuscationLayer::new(NodeId::ZERO, 1, true);
        let peer: SocketAddr = "192.0.2.1:20020".parse().unwrap();
        let current = NodeId::from_bytes([1; 16]);
        layer.register_peer_identity(peer, current);
        layer.register_peer_version(peer, 10);
        layer.register_peer_key(peer, 22);
        layer.register_peer_identity_if_absent(peer, NodeId::from_bytes([2; 16]));
        layer.register_peer_version_if_higher(peer, 3);
        layer.register_peer_key_if_absent(peer, 11);
        let state = layer.peer_state_for_addr(peer);
        assert_eq!(state.node_id, Some(current));
        assert_eq!(state.kad_version, Some(10));
        assert_eq!(state.receiver_verify_key, Some(22));
    }

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
            layer.receiver_verify_keys.lock().entries.len(),
            PEER_MAP_CAP,
            "receiver verify key map must stay at the cap"
        );
        assert_eq!(
            layer.capture_peer_keys(&mut []).unwrap().0,
            (PEER_MAP_CAP + 32) as u64
        );
    }
}
