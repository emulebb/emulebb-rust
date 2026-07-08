//! eD2K per-file dead-source list (oracle `CDeadSourceList`).
//!
//! When a download source answers a file request with "file not found" — TCP
//! `OP_FILEREQANSNOFIL` (`ListenSocket.cpp:645-661`), UDP `OP_FILENOTFOUND`
//! (`DownloadClient.cpp:1774-1795` `UDPReaskFNF`), or an AICH-root mismatch
//! treated like FNF (`DownloadClient.cpp:2971-3004`) — the oracle adds the
//! (source, file) pair to that part file's `m_DeadSourceList`
//! (`PartFile.h:390`, initialized as a LOCAL list in `PartFile.cpp:564`) and
//! refuses to re-admit the source while blocked
//! (`DownloadQueue.cpp:1420`/`1530` `CheckAndAddSource` paths).
//!
//! Block window: the local (per-file) list blocks for 45 minutes regardless of
//! HighID/LowID (`DeadSourceList.cpp:32-33`, `BLOCKTIME`/`BLOCKTIMEFW` both
//! `MIN2MS(45)` when `!m_bGlobalList`). Expired entries are swept
//! opportunistically on add every 60 minutes (`CLEANUPTIME`,
//! `DeadSourceList.cpp:30`, `:143-145`); lookups additionally compare against
//! the expiry stamp (`DeadSourceList.cpp:114-121`), so a stale entry never
//! blocks past its window even before a sweep runs.
//!
//! Scope note: the oracle also keeps a GLOBAL dead list on the client list
//! (15/30-minute blocks, fed by connect-failure paths in `BaseClient.cpp`).
//! Rust handles those failure paths through its endpoint retry cooldown and
//! ban store, so only the per-file FNF list is mirrored here. Rust keys the
//! whole thing as one map over (file, source) — semantically identical to one
//! list per part file.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use emulebb_ed2k::ed2k_server::Ed2kFoundSource;

/// Oracle `BLOCKTIME`/`BLOCKTIMEFW` for the local (per-file) list: 45 minutes
/// (`DeadSourceList.cpp:32-33`).
pub(crate) const DEAD_SOURCE_BLOCK: Duration = Duration::from_secs(45 * 60);

/// Oracle `CLEANUPTIME`: sweep expired entries at most once per 60 minutes,
/// piggybacked on an add (`DeadSourceList.cpp:30`, `:143-145`).
const DEAD_SOURCE_CLEANUP: Duration = Duration::from_secs(60 * 60);

/// Identity of a dead source, mirroring oracle `CDeadSource`
/// (`DeadSourceList.cpp:47-64`): a HighID client is identified by its public
/// endpoint (oracle id==IP + port); a LowID client with a known server by the
/// server-scoped (server, client id, port) triple; a LowID client without
/// server context only by its user hash. A source with none of those has no
/// valid key and is never dead-listed (oracle `HasValidKey`,
/// `DeadSourceList.cpp:131-140`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DeadSourceKey {
    /// HighID / directly-addressable peer: public endpoint.
    Endpoint { ip: Ipv4Addr, tcp_port: u16 },
    /// LowID peer behind a known eD2K server: server-scoped client id.
    ServerScoped {
        server: SocketAddr,
        client_id: u32,
        tcp_port: u16,
    },
    /// LowID peer without server context: eD2K user hash.
    UserHash([u8; 16]),
}

impl DeadSourceKey {
    fn for_source(source: &Ed2kFoundSource) -> Option<Self> {
        if !source.low_id {
            return Some(Self::Endpoint {
                ip: source.ip,
                tcp_port: source.tcp_port,
            });
        }
        if let Some(server) = source.source_server {
            return Some(Self::ServerScoped {
                server,
                client_id: source.client_id,
                tcp_port: source.tcp_port,
            });
        }
        source.user_hash.map(Self::UserHash)
    }
}

/// Per-(file, source) dead-source list with the oracle 45-minute block.
#[derive(Debug, Default)]
pub(crate) struct DeadSourceList {
    /// (file hash hex, source identity) -> block expiry.
    entries: HashMap<(String, DeadSourceKey), Instant>,
    last_cleanup: Option<Instant>,
}

impl DeadSourceList {
    /// Dead-list `source` for `file_hash` for [`DEAD_SOURCE_BLOCK`] (oracle
    /// `CDeadSourceList::AddDeadSource`, `DeadSourceList.cpp:123-145`).
    /// Returns `false` when the source has no valid identity key (oracle
    /// skips those too).
    pub(crate) fn add_dead_source(
        &mut self,
        now: Instant,
        file_hash: &str,
        source: &Ed2kFoundSource,
    ) -> bool {
        let Some(key) = DeadSourceKey::for_source(source) else {
            return false;
        };
        self.insert(now, file_hash, key);
        true
    }

    /// Whether `source` is currently blocked for `file_hash` (oracle
    /// `CDeadSourceList::IsDeadSource`, `DeadSourceList.cpp:114-121`): present
    /// AND its expiry is still in the future.
    pub(crate) fn is_dead_source(
        &self,
        now: Instant,
        file_hash: &str,
        source: &Ed2kFoundSource,
    ) -> bool {
        let Some(key) = DeadSourceKey::for_source(source) else {
            return false;
        };
        self.entries
            .get(&(file_hash.to_string(), key))
            .is_some_and(|expiry| now < *expiry)
    }

    fn insert(&mut self, now: Instant, file_hash: &str, key: DeadSourceKey) {
        self.entries
            .insert((file_hash.to_string(), key), now + DEAD_SOURCE_BLOCK);
        // Opportunistic expiry sweep, at most once per CLEANUPTIME (oracle
        // piggybacks it on AddDeadSource the same way).
        if self
            .last_cleanup
            .is_none_or(|last| now.duration_since(last) >= DEAD_SOURCE_CLEANUP)
        {
            self.entries.retain(|_, expiry| now < *expiry);
            self.last_cleanup = Some(now);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use emulebb_ed2k::ed2k_server::Ed2kFoundSource;
    use emulebb_kad_proto::Ed2kHash;

    use super::{DEAD_SOURCE_BLOCK, DeadSourceList};

    const FILE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FILE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn high_id_source(last_octet: u8, tcp_port: u16) -> Ed2kFoundSource {
        Ed2kFoundSource {
            file_hash: Ed2kHash::from_bytes([0x44; 16]),
            ip: Ipv4Addr::new(198, 51, 100, last_octet),
            tcp_port,
            client_id: u32::from_be_bytes([198, 51, 100, last_octet]),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }
    }

    #[test]
    fn fnf_dead_lists_the_source_for_45_minutes() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        let source = high_id_source(1, 4662);

        assert!(!list.is_dead_source(now, FILE_A, &source));
        assert!(list.add_dead_source(now, FILE_A, &source));
        assert!(list.is_dead_source(now, FILE_A, &source));
        // Still blocked just inside the oracle 45-minute window.
        let almost = now + DEAD_SOURCE_BLOCK - Duration::from_secs(1);
        assert!(list.is_dead_source(almost, FILE_A, &source));
    }

    #[test]
    fn block_expires_after_45_minutes_allowing_re_admission() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        let source = high_id_source(2, 4662);

        list.add_dead_source(now, FILE_A, &source);
        let expired = now + DEAD_SOURCE_BLOCK;
        assert!(!list.is_dead_source(expired, FILE_A, &source));
    }

    #[test]
    fn unrelated_files_and_sources_are_unaffected() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        let dead = high_id_source(3, 4662);
        let other = high_id_source(4, 4662);

        list.add_dead_source(now, FILE_A, &dead);
        // Same source, different file: the list is per-(file, source).
        assert!(!list.is_dead_source(now, FILE_B, &dead));
        // Different source, same file.
        assert!(!list.is_dead_source(now, FILE_A, &other));
    }

    #[test]
    fn low_id_source_without_identity_is_never_dead_listed() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        let mut source = high_id_source(5, 4662);
        source.low_id = true; // no server, no user hash -> no valid key

        assert!(!list.add_dead_source(now, FILE_A, &source));
        assert!(!list.is_dead_source(now, FILE_A, &source));
    }

    #[test]
    fn low_id_source_is_keyed_by_server_scope_or_user_hash() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        let server: SocketAddr = "203.0.113.1:4661".parse().unwrap();

        let mut server_scoped = high_id_source(6, 4662);
        server_scoped.low_id = true;
        server_scoped.client_id = 777;
        server_scoped.source_server = Some(server);
        assert!(list.add_dead_source(now, FILE_A, &server_scoped));
        assert!(list.is_dead_source(now, FILE_A, &server_scoped));

        let mut hashed = high_id_source(7, 4662);
        hashed.low_id = true;
        hashed.user_hash = Some([0x77; 16]);
        assert!(list.add_dead_source(now, FILE_A, &hashed));
        assert!(list.is_dead_source(now, FILE_A, &hashed));
        // A different user hash is a different identity.
        let mut other_hash = hashed.clone();
        other_hash.user_hash = Some([0x78; 16]);
        assert!(!list.is_dead_source(now, FILE_A, &other_hash));
    }

    #[test]
    fn cleanup_sweeps_expired_entries_on_a_later_add() {
        let mut list = DeadSourceList::default();
        let now = Instant::now();
        list.add_dead_source(now, FILE_A, &high_id_source(9, 4662));
        assert_eq!(list.len(), 1);

        // A later add past both the block and the cleanup cadence sweeps the
        // expired entry (oracle CLEANUPTIME piggybacked on AddDeadSource).
        let later = now + Duration::from_secs(61 * 60);
        list.add_dead_source(later, FILE_A, &high_id_source(10, 4662));
        assert_eq!(list.len(), 1);
    }
}
