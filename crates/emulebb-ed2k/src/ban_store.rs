//! In-memory client ban store mirroring the eMuleBB master `CClientList`
//! ban lists (`ClientList.cpp:356-409`).
//!
//! The master keeps two `CMap`s keyed by IP (`m_bannedList`) and by user hash
//! (`m_bannedHashList`), each storing the tick at which the ban was placed; a
//! client is banned while `GetTickCount64() - banTick < CLIENTBANTIME` (4h,
//! `Opcodes.h:118 CLIENTBANTIME = HR2MS(4)`). The ban list is **not** persisted
//! across a restart -- it is purely in-memory, expiry-driven state -- so this
//! store matches that exactly: a process restart clears all bans, and the only
//! durable parity point is the 4-hour TTL.
//!
//! Both keys are checked on lookup, exactly like `IsBannedClient(const
//! CUpDownClient*)` which returns true if *either* the user-hash entry or the IP
//! entry is an unexpired ban.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

/// eMule `CLIENTBANTIME` -- the ban time-to-live (`Opcodes.h:118`,
/// `HR2MS(4)` = 4 hours).
pub const CLIENT_BAN_TIME: Duration = Duration::from_secs(4 * 60 * 60);

/// Shared, in-memory client ban store keyed by both IPv4 address and 16-byte
/// user hash, each entry carrying its expiry instant (placed-at + 4h TTL).
///
/// All methods take `&self`; the interior `Mutex` makes the store cheap to share
/// behind an `Arc` across the inbound listener, the outbound download driver,
/// the UDP reask runtime, and the core source-add path.
#[derive(Debug, Default)]
pub struct BanStore {
    /// IP -> ban expiry (`m_bannedList`).
    by_ip: Mutex<HashMap<Ipv4Addr, Instant>>,
    /// User hash -> ban expiry (`m_bannedHashList`).
    by_hash: Mutex<HashMap<[u8; 16], Instant>>,
}

impl BanStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ban a client by IP and/or user hash for `CLIENT_BAN_TIME` from now,
    /// mirroring `CClientList::AddBannedClient(const CUpDownClient*,
    /// clientBanScopeBoth)`: a valid user hash bans the hash, and a non-zero IP
    /// bans the IP. At least one of `ip` / `user_hash` should be `Some`.
    pub fn ban(&self, ip: Option<Ipv4Addr>, user_hash: Option<[u8; 16]>) {
        self.ban_at(ip, user_hash, Instant::now());
    }

    /// `ban`, parameterised on the placement instant for deterministic tests.
    pub fn ban_at(&self, ip: Option<Ipv4Addr>, user_hash: Option<[u8; 16]>, now: Instant) {
        let until = now + CLIENT_BAN_TIME;
        if let Some(ip) = ip.filter(|ip| !ip.is_unspecified()) {
            self.by_ip.lock().insert(ip, until);
        }
        if let Some(user_hash) = user_hash.filter(|hash| hash != &[0u8; 16]) {
            self.by_hash.lock().insert(user_hash, until);
        }
    }

    /// Whether `ip` currently has an unexpired ban
    /// (`IsBannedClient(uint32 dwIP)`).
    #[must_use]
    pub fn is_ip_banned(&self, ip: Ipv4Addr) -> bool {
        self.is_ip_banned_at(ip, Instant::now())
    }

    #[must_use]
    pub fn is_ip_banned_at(&self, ip: Ipv4Addr, now: Instant) -> bool {
        Self::lookup_alive(&self.by_ip, &ip, now)
    }

    /// Whether `user_hash` currently has an unexpired ban
    /// (the `m_bannedHashList` half of `IsBannedClient(const CUpDownClient*)`).
    #[must_use]
    pub fn is_hash_banned(&self, user_hash: &[u8; 16]) -> bool {
        self.is_hash_banned_at(user_hash, Instant::now())
    }

    #[must_use]
    pub fn is_hash_banned_at(&self, user_hash: &[u8; 16], now: Instant) -> bool {
        Self::lookup_alive(&self.by_hash, user_hash, now)
    }

    /// Whether the client identified by `ip` and/or `user_hash` is banned by
    /// either key, mirroring `IsBannedClient(const CUpDownClient*)` (hash OR IP).
    #[must_use]
    pub fn is_banned(&self, ip: Option<Ipv4Addr>, user_hash: Option<&[u8; 16]>) -> bool {
        self.is_banned_at(ip, user_hash, Instant::now())
    }

    #[must_use]
    pub fn is_banned_at(
        &self,
        ip: Option<Ipv4Addr>,
        user_hash: Option<&[u8; 16]>,
        now: Instant,
    ) -> bool {
        user_hash.is_some_and(|hash| self.is_hash_banned_at(hash, now))
            || ip.is_some_and(|ip| self.is_ip_banned_at(ip, now))
    }

    /// Lift any ban on `ip` and/or `user_hash` (the manual `UnBan` path).
    pub fn unban(&self, ip: Option<Ipv4Addr>, user_hash: Option<&[u8; 16]>) {
        if let Some(ip) = ip {
            self.by_ip.lock().remove(&ip);
        }
        if let Some(user_hash) = user_hash {
            self.by_hash.lock().remove(user_hash);
        }
    }

    /// Drop every expired entry from both maps. Lookups already treat expired
    /// entries as not-banned (matching the master's tick comparison), so this is
    /// only a memory reclaim; it can be called periodically.
    pub fn prune_expired(&self, now: Instant) {
        self.by_ip.lock().retain(|_, until| *until > now);
        self.by_hash.lock().retain(|_, until| *until > now);
    }

    fn lookup_alive<K: std::hash::Hash + Eq>(
        map: &Mutex<HashMap<K, Instant>>,
        key: &K,
        now: Instant,
    ) -> bool {
        map.lock().get(key).is_some_and(|until| *until > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: [u8; 16] = [1u8; 16];
    const HASH_B: [u8; 16] = [2u8; 16];

    #[test]
    fn ip_ban_is_active_then_expires_after_ttl() {
        let store = BanStore::new();
        let start = Instant::now();
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        store.ban_at(Some(ip), None, start);

        assert!(store.is_ip_banned_at(ip, start + Duration::from_secs(1)));
        // Just before the 4h TTL: still banned.
        assert!(store.is_ip_banned_at(ip, start + CLIENT_BAN_TIME - Duration::from_secs(1)));
        // After the 4h TTL: no longer banned.
        assert!(!store.is_ip_banned_at(ip, start + CLIENT_BAN_TIME + Duration::from_secs(1)));
    }

    #[test]
    fn hash_ban_is_active_then_expires_after_ttl() {
        let store = BanStore::new();
        let start = Instant::now();
        store.ban_at(None, Some(HASH_A), start);

        assert!(store.is_hash_banned_at(&HASH_A, start));
        assert!(!store.is_hash_banned_at(&HASH_B, start));
        assert!(
            !store.is_hash_banned_at(&HASH_A, start + CLIENT_BAN_TIME + Duration::from_secs(1))
        );
    }

    #[test]
    fn is_banned_matches_either_key() {
        let store = BanStore::new();
        let start = Instant::now();
        let ip = Ipv4Addr::new(198, 51, 100, 4);
        store.ban_at(Some(ip), Some(HASH_A), start);

        // Banned by IP even with an unknown hash.
        assert!(store.is_banned_at(Some(ip), Some(&HASH_B), start));
        // Banned by hash even from a different IP.
        let other_ip = Ipv4Addr::new(198, 51, 100, 9);
        assert!(store.is_banned_at(Some(other_ip), Some(&HASH_A), start));
        // Unrelated client is not banned.
        assert!(!store.is_banned_at(Some(other_ip), Some(&HASH_B), start));
    }

    #[test]
    fn zero_keys_are_ignored() {
        let store = BanStore::new();
        let start = Instant::now();
        store.ban_at(Some(Ipv4Addr::UNSPECIFIED), Some([0u8; 16]), start);
        assert!(!store.is_ip_banned_at(Ipv4Addr::UNSPECIFIED, start));
        assert!(!store.is_hash_banned_at(&[0u8; 16], start));
    }

    #[test]
    fn unban_lifts_an_active_ban() {
        let store = BanStore::new();
        let start = Instant::now();
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        store.ban_at(Some(ip), Some(HASH_A), start);
        store.unban(Some(ip), Some(&HASH_A));
        assert!(!store.is_banned_at(Some(ip), Some(&HASH_A), start));
    }

    #[test]
    fn prune_expired_reclaims_only_expired_entries() {
        let store = BanStore::new();
        let start = Instant::now();
        let live_ip = Ipv4Addr::new(192, 0, 2, 2);
        store.ban_at(Some(live_ip), Some(HASH_A), start);
        // Prune well after the TTL: both entries gone, but a re-check confirms
        // an entry banned at a later time survives.
        let later = start + CLIENT_BAN_TIME - Duration::from_secs(10);
        let fresh_ip = Ipv4Addr::new(192, 0, 2, 3);
        store.ban_at(Some(fresh_ip), None, later);
        store.prune_expired(start + CLIENT_BAN_TIME + Duration::from_secs(1));
        assert!(!store.is_ip_banned_at(live_ip, later + CLIENT_BAN_TIME));
        assert!(store.is_ip_banned_at(fresh_ip, later + Duration::from_secs(1)));
    }
}
