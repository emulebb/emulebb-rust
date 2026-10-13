//! Cross-reconnect ED2K client identity tracking.
//!
//! eMuleBB MFC retains a client's user hash for two hours and compares the
//! first HELLO on a later connection against the prior `(IPv4, TCP port)`
//! identity (`CClientList::ComparePriorUserhash`). This store provides the same
//! process-local guard with atomic compare/refresh semantics. A hard capacity
//! keeps spoofed endpoint churn from growing memory without bound; when full,
//! the entry nearest expiry is discarded first.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

/// eMule `KEEPTRACK_TIME` (`HR2MS(2)`) for deleted/tracked clients.
pub const TRACKED_CLIENT_IDENTITY_TTL: Duration = Duration::from_secs(2 * 60 * 60);

/// Defensive upper bound for distinct identities retained during the TTL.
///
/// This is intentionally far above the supported concurrent-connection
/// defaults while bounding adversarial reconnect churn to a predictable amount
/// of process memory.
pub const MAX_TRACKED_CLIENT_IDENTITIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackedClientIdentityObservation {
    FirstSeen,
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Copy)]
struct TrackedClientIdentity {
    user_hash: [u8; 16],
    expires_at: Instant,
}

/// Shared process-local identity history for ED2K peers.
#[derive(Debug)]
pub struct TrackedClientIdentityStore {
    entries: Mutex<HashMap<(Ipv4Addr, u16), TrackedClientIdentity>>,
    capacity: usize,
}

impl Default for TrackedClientIdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrackedClientIdentityStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_TRACKED_CLIENT_IDENTITIES)
    }

    fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "tracked-client identity capacity must be positive"
        );
        Self {
            entries: Mutex::new(HashMap::with_capacity(capacity.min(1_024))),
            capacity,
        }
    }

    /// Compare and refresh one peer identity using the current monotonic time.
    #[must_use]
    pub fn observe(
        &self,
        ip: Ipv4Addr,
        tcp_port: u16,
        user_hash: [u8; 16],
    ) -> TrackedClientIdentityObservation {
        self.observe_at(ip, tcp_port, user_hash, Instant::now())
    }

    fn observe_at(
        &self,
        ip: Ipv4Addr,
        tcp_port: u16,
        user_hash: [u8; 16],
        now: Instant,
    ) -> TrackedClientIdentityObservation {
        let endpoint = (ip, tcp_port);
        let mut entries = self.entries.lock();

        if let Some(entry) = entries.get_mut(&endpoint) {
            if entry.expires_at <= now {
                entries.remove(&endpoint);
            } else if entry.user_hash != user_hash {
                return TrackedClientIdentityObservation::Changed;
            } else {
                entry.expires_at = now + TRACKED_CLIENT_IDENTITY_TTL;
                return TrackedClientIdentityObservation::Unchanged;
            }
        }

        if entries.len() >= self.capacity
            && let Some(oldest_endpoint) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(endpoint, _)| *endpoint)
        {
            entries.remove(&oldest_endpoint);
        }

        entries.insert(
            endpoint,
            TrackedClientIdentity {
                user_hash,
                expires_at: now + TRACKED_CLIENT_IDENTITY_TTL,
            },
        );
        TrackedClientIdentityObservation::FirstSeen
    }

    /// Physically remove all expired identity records.
    pub fn prune_expired(&self, now: Instant) {
        self.entries
            .lock()
            .retain(|_, entry| entry.expires_at > now);
    }

    /// Number of identity records physically retained in memory.
    #[must_use]
    pub fn retained_entry_count(&self) -> usize {
        self.entries.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: [u8; 16] = [0xAA; 16];
    const HASH_B: [u8; 16] = [0xBB; 16];
    const IP_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);

    #[test]
    fn first_seen_and_matching_identity_refresh_the_entry() {
        let store = TrackedClientIdentityStore::new();
        let start = Instant::now();

        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start + Duration::from_secs(60)),
            TrackedClientIdentityObservation::Unchanged
        );
        assert_eq!(store.retained_entry_count(), 1);

        store.prune_expired(start + TRACKED_CLIENT_IDENTITY_TTL + Duration::from_secs(30));
        assert_eq!(store.retained_entry_count(), 1);
        store.prune_expired(start + TRACKED_CLIENT_IDENTITY_TTL + Duration::from_secs(61));
        assert_eq!(store.retained_entry_count(), 0);
    }

    #[test]
    fn changed_identity_is_reported_without_replacing_the_prior_hash() {
        let store = TrackedClientIdentityStore::new();
        let start = Instant::now();

        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_B, start + Duration::from_secs(1)),
            TrackedClientIdentityObservation::Changed
        );
        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start + Duration::from_secs(2)),
            TrackedClientIdentityObservation::Unchanged
        );
    }

    #[test]
    fn expired_identity_accepts_a_new_hash_as_first_seen() {
        let store = TrackedClientIdentityStore::new();
        let start = Instant::now();

        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_B, start + TRACKED_CLIENT_IDENTITY_TTL,),
            TrackedClientIdentityObservation::FirstSeen
        );
    }

    #[test]
    fn port_is_part_of_the_tracked_endpoint_identity() {
        let store = TrackedClientIdentityStore::new();
        let start = Instant::now();

        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(IP_A, 4_663, HASH_B, start),
            TrackedClientIdentityObservation::FirstSeen
        );
    }

    #[test]
    fn capacity_evicts_the_identity_nearest_expiry() {
        let store = TrackedClientIdentityStore::with_capacity(2);
        let start = Instant::now();
        let ip_b = Ipv4Addr::new(198, 51, 100, 11);
        let ip_c = Ipv4Addr::new(198, 51, 100, 12);

        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_A, start),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(ip_b, 4_662, HASH_A, start + Duration::from_secs(1)),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(
            store.observe_at(ip_c, 4_662, HASH_A, start + Duration::from_secs(2)),
            TrackedClientIdentityObservation::FirstSeen
        );
        assert_eq!(store.retained_entry_count(), 2);
        assert_eq!(
            store.observe_at(IP_A, 4_662, HASH_B, start + Duration::from_secs(3)),
            TrackedClientIdentityObservation::FirstSeen
        );
    }
}
