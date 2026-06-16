//! In-memory Kad publish cache used to answer inbound search traffic.
//!
//! The store mirrors the semantic meaning of the publish/search packet families:
//! keyword publishes are indexed by file hash, source publishes by publisher
//! identity and IP, and notes publishes by publisher identity plus note tags.

use std::{net::Ipv4Addr, time::Duration};

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{
    Ed2kHash, NodeId, PublishEntry, SearchKeyReq, SearchNotesReq, SearchRes, SearchResultEntry,
    SearchSourceReq, Tag,
};

use crate::{
    KadKeywordPublishSnapshot, KadNotePublishSnapshot, KadPublishCacheSnapshot,
    KadSourcePublishSnapshot,
};

mod entry_store;
mod keyword;
mod notes;
mod size_tags;
mod source;

use entry_store::{purge_expired, upsert_entry};
use keyword::{
    STOCK_MAX_KEYWORD_ENTRIES, StoredKeywordPublish, has_stock_keyword_filename,
    keyword_dedup_key, keyword_entry_matches_restrictive_payload, keyword_result_tags,
    stock_keyword_file_size, stock_keyword_publish_decision,
};
use notes::{
    StoredNotesPublish, has_stock_note_tags, notes_dedup_key, notes_result_tags,
    stock_notes_publish_load, upsert_notes_entry,
};
use size_tags::{
    search_response, stock_notes_file_size_matches_request,
    stock_source_file_size_matches_request, stock_stored_publish_tags,
};
use source::{
    StoredSourcePublish, is_stock_source_publish, source_dedup_key, source_entry_id,
    source_result_tags, stock_source_publish_load, stock_source_tcp_port,
    stock_stored_source_publish_tags, upsert_source_entry,
};

// Stock per-file caps (Opcodes.h KADEMLIAMAXSOURCEPERFILE /
// KADEMLIAMAXNOTESPERFILE): the maximum entries the index keeps for a *single*
// target (file). These bound one file's source/note list, independent of the
// overall store size. (The keyword caps live in the keyword submodule.)
const STOCK_MAX_SOURCES_PER_FILE: usize = 1000;
const STOCK_MAX_NOTES_PER_FILE: usize = 150;
// Global store caps that bound total memory across all targets. The keyword
// global mirrors stock `KADEMLIAMAXENTRIES` (re-exported from the keyword
// submodule); the source/note globals are our finite-memory extension and are
// deliberately larger than the per-file caps so the two semantics never
// coincide.
const DEFAULT_MAX_SOURCE_ENTRIES: usize = 100_000;
const DEFAULT_MAX_NOTE_ENTRIES: usize = 60_000;

/// Runtime policy for the local Kad publish cache.
///
/// Capacities come in two flavours that must not be conflated:
/// - `*_per_file_capacity` is the stock per-target cap (per file / per keyword),
///   bounding how many entries we keep for one target (Opcodes.h
///   `KADEMLIAMAXSOURCEPERFILE` / `KADEMLIAMAXNOTESPERFILE`).
/// - `*_capacity` is the global store cap across all targets, bounding total
///   memory (the keyword global mirrors stock `KADEMLIAMAXENTRIES`; the
///   source/note globals are our finite-memory extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KadLocalStoreConfig {
    pub enabled: bool,
    pub keyword_ttl: Duration,
    pub source_ttl: Duration,
    pub notes_ttl: Duration,
    /// Global cap on stored keyword entries (stock `KADEMLIAMAXENTRIES`).
    pub keyword_capacity: usize,
    /// Global cap on stored source entries across all files.
    pub source_capacity: usize,
    /// Global cap on stored note entries across all files.
    pub notes_capacity: usize,
    /// Per-file cap on source entries (stock `KADEMLIAMAXSOURCEPERFILE`).
    pub source_per_file_capacity: usize,
    /// Per-file cap on note entries (stock `KADEMLIAMAXNOTESPERFILE`).
    pub notes_per_file_capacity: usize,
}

impl Default for KadLocalStoreConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keyword_ttl: Duration::from_secs(86_400),
            // Master inbound source entry lifetime = KADEMLIAREPUBLISHTIMES (5h),
            // set on each stored source entry in KademliaUDPListener.cpp:1349
            // (`m_tLifetime = time(NULL) + KADEMLIAREPUBLISHTIMES`). Keyword and
            // notes keep their 24h lifetimes (KADEMLIAREPUBLISHTIMEK/N).
            source_ttl: Duration::from_secs(5 * 60 * 60),
            notes_ttl: Duration::from_secs(86_400),
            keyword_capacity: STOCK_MAX_KEYWORD_ENTRIES,
            source_capacity: DEFAULT_MAX_SOURCE_ENTRIES,
            notes_capacity: DEFAULT_MAX_NOTE_ENTRIES,
            source_per_file_capacity: STOCK_MAX_SOURCES_PER_FILE,
            notes_per_file_capacity: STOCK_MAX_NOTES_PER_FILE,
        }
    }
}

/// In-memory Kad publish cache used to answer inbound search traffic.
#[derive(Debug, Clone)]
pub struct KadLocalStore {
    config: KadLocalStoreConfig,
    keyword_entries: Vec<StoredKeywordPublish>,
    source_entries: Vec<StoredSourcePublish>,
    notes_entries: Vec<StoredNotesPublish>,
}

impl KadLocalStore {
    #[must_use]
    pub fn new(config: KadLocalStoreConfig) -> Self {
        Self {
            config,
            keyword_entries: Vec::new(),
            source_entries: Vec::new(),
            notes_entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn config(&self) -> KadLocalStoreConfig {
        self.config
    }

    pub fn record_keyword_publish_batch(
        &mut self,
        target: NodeId,
        entries: &[PublishEntry],
        observed_at: DateTime<Utc>,
    ) -> u8 {
        let mut load = 0;
        if !self.config.enabled {
            return load;
        }
        purge_expired(
            &mut self.keyword_entries,
            self.config.keyword_ttl,
            observed_at,
        );
        for entry in entries {
            let Some(size) = stock_keyword_file_size(&entry.tags) else {
                continue;
            };
            if !has_stock_keyword_filename(&entry.tags) {
                continue;
            }
            let (entry_load, should_store) =
                stock_keyword_publish_decision(&self.keyword_entries, target, entry.hash);
            load = entry_load;
            if !should_store {
                continue;
            }
            let dedup_key = keyword_dedup_key(target, entry.hash, size);
            upsert_entry(
                &mut self.keyword_entries,
                self.config.keyword_capacity,
                dedup_key.clone(),
                StoredKeywordPublish {
                    observed_at,
                    target,
                    file_hash: entry.hash,
                    tags: stock_stored_publish_tags(&entry.tags),
                    dedup_key,
                },
            );
        }
        load
    }

    pub fn record_source_publish(
        &mut self,
        target: NodeId,
        publisher_id: NodeId,
        source_ip: Ipv4Addr,
        source_udp_port: u16,
        tags: &[Tag],
        observed_at: DateTime<Utc>,
    ) -> Option<u8> {
        if !self.config.enabled {
            return None;
        }
        if !is_stock_source_publish(tags) {
            return None;
        }
        if source_ip.octets() == [0, 0, 0, 0] || source_udp_port == 0 {
            return None;
        }
        let source_tcp_port = stock_source_tcp_port(tags)?;
        purge_expired(
            &mut self.source_entries,
            self.config.source_ttl,
            observed_at,
        );
        let load = stock_source_publish_load(
            &self.source_entries,
            target,
            self.config.source_per_file_capacity,
            source_ip,
            source_tcp_port,
            source_udp_port,
        );
        let dedup_key = source_dedup_key(target, source_ip, source_tcp_port, source_udp_port);
        upsert_source_entry(
            &mut self.source_entries,
            self.config.source_per_file_capacity,
            self.config.source_capacity,
            StoredSourcePublish {
                observed_at,
                target,
                publisher_id,
                source_ip,
                source_tcp_port,
                source_udp_port,
                tags: stock_stored_source_publish_tags(tags),
                dedup_key,
            },
        );
        Some(load)
    }

    pub fn record_notes_publish(
        &mut self,
        target: NodeId,
        publisher_id: NodeId,
        publisher_ip: Ipv4Addr,
        tags: &[Tag],
        observed_at: DateTime<Utc>,
    ) -> Option<u8> {
        if !self.config.enabled {
            return None;
        }
        if publisher_ip.octets() == [0, 0, 0, 0] || !has_stock_note_tags(tags) {
            return None;
        }
        purge_expired(&mut self.notes_entries, self.config.notes_ttl, observed_at);
        let load = stock_notes_publish_load(
            &self.notes_entries,
            target,
            self.config.notes_per_file_capacity,
            publisher_id,
            publisher_ip,
        );
        let dedup_key = notes_dedup_key(target, publisher_id, publisher_ip);
        upsert_notes_entry(
            &mut self.notes_entries,
            self.config.notes_per_file_capacity,
            self.config.notes_capacity,
            StoredNotesPublish {
                observed_at,
                target,
                publisher_id,
                publisher_ip,
                tags: stock_stored_publish_tags(tags),
                dedup_key,
            },
        );
        Some(load)
    }

    pub fn keyword_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchKeyReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || limit == 0 {
            return None;
        }

        let restrictive_payload = ((request.start_position & 0x8000) != 0)
            .then_some(request.restrictive_payload.as_slice());
        purge_expired(&mut self.keyword_entries, self.config.keyword_ttl, now);
        let offset = usize::from(request.start_position & 0x7FFF);
        let results = self
            .keyword_entries
            .iter()
            .filter(|entry| entry.target == request.target)
            .filter(|entry| keyword_entry_matches_restrictive_payload(entry, restrictive_payload))
            .skip(offset)
            .take(limit)
            .map(|entry| SearchResultEntry {
                entry_id: entry.file_hash,
                tags: keyword_result_tags(entry),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    pub fn source_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchSourceReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || limit == 0 {
            return None;
        }

        purge_expired(&mut self.source_entries, self.config.source_ttl, now);
        let offset = usize::from(request.start_position & 0x7FFF);
        let results = self
            .source_entries
            .iter()
            .rev()
            .filter(|entry| entry.target == request.target)
            .skip(offset)
            .filter(|entry| stock_source_file_size_matches_request(&entry.tags, request.size))
            .take(limit)
            .map(|entry| SearchResultEntry {
                entry_id: source_entry_id(entry.publisher_id),
                tags: source_result_tags(entry),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    pub fn notes_search_response(
        &mut self,
        sender_id: NodeId,
        request: &SearchNotesReq,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Option<SearchRes> {
        if !self.config.enabled || limit == 0 {
            return None;
        }

        purge_expired(&mut self.notes_entries, self.config.notes_ttl, now);
        let results = self
            .notes_entries
            .iter()
            .rev()
            .filter(|entry| entry.target == request.target)
            .filter(|entry| stock_notes_file_size_matches_request(&entry.tags, request.size))
            .take(limit)
            .map(|entry| SearchResultEntry {
                entry_id: Ed2kHash::from_bytes(entry.publisher_id.to_be_bytes()),
                tags: notes_result_tags(entry),
            })
            .collect::<Vec<_>>();
        search_response(sender_id, request.target, results)
    }

    pub fn publish_snapshot(&mut self, now: DateTime<Utc>) -> KadPublishCacheSnapshot {
        if !self.config.enabled {
            return KadPublishCacheSnapshot::default();
        }
        purge_expired(&mut self.keyword_entries, self.config.keyword_ttl, now);
        purge_expired(&mut self.source_entries, self.config.source_ttl, now);
        purge_expired(&mut self.notes_entries, self.config.notes_ttl, now);
        KadPublishCacheSnapshot {
            keyword_publishes: self
                .keyword_entries
                .iter()
                .map(|entry| KadKeywordPublishSnapshot {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    file_hash: entry.file_hash,
                    tags: entry.tags.clone(),
                    load: None,
                })
                .collect(),
            source_publishes: self
                .source_entries
                .iter()
                .map(|entry| KadSourcePublishSnapshot {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    publisher_id: entry.publisher_id,
                    source_ip: entry.source_ip,
                    source_tcp_port: entry.source_tcp_port,
                    source_udp_port: entry.source_udp_port,
                    tags: entry.tags.clone(),
                    load: None,
                })
                .collect(),
            note_publishes: self
                .notes_entries
                .iter()
                .map(|entry| KadNotePublishSnapshot {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    publisher_id: entry.publisher_id,
                    publisher_ip: entry.publisher_ip,
                    tags: entry.tags.clone(),
                    load: None,
                })
                .collect(),
        }
    }

    pub fn merge_publish_snapshot(
        &mut self,
        snapshot: KadPublishCacheSnapshot,
        now: DateTime<Utc>,
    ) {
        if !self.config.enabled {
            return;
        }
        for entry in snapshot.keyword_publishes {
            if entry.observed_at + self.config.keyword_ttl <= now {
                continue;
            }
            let Some(size) = stock_keyword_file_size(&entry.tags) else {
                continue;
            };
            let dedup_key = keyword_dedup_key(entry.target, entry.file_hash, size);
            upsert_entry(
                &mut self.keyword_entries,
                self.config.keyword_capacity,
                dedup_key.clone(),
                StoredKeywordPublish {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    file_hash: entry.file_hash,
                    tags: entry.tags,
                    dedup_key,
                },
            );
        }
        for entry in snapshot.source_publishes {
            if entry.observed_at + self.config.source_ttl <= now
                || entry.source_ip.octets() == [0, 0, 0, 0]
                || entry.source_tcp_port == 0
                || entry.source_udp_port == 0
            {
                continue;
            }
            upsert_source_entry(
                &mut self.source_entries,
                self.config.source_per_file_capacity,
                self.config.source_capacity,
                StoredSourcePublish {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    publisher_id: entry.publisher_id,
                    source_ip: entry.source_ip,
                    source_tcp_port: entry.source_tcp_port,
                    source_udp_port: entry.source_udp_port,
                    tags: entry.tags,
                    dedup_key: source_dedup_key(
                        entry.target,
                        entry.source_ip,
                        entry.source_tcp_port,
                        entry.source_udp_port,
                    ),
                },
            );
        }
        for entry in snapshot.note_publishes {
            if entry.observed_at + self.config.notes_ttl <= now
                || entry.publisher_ip.octets() == [0, 0, 0, 0]
            {
                continue;
            }
            upsert_notes_entry(
                &mut self.notes_entries,
                self.config.notes_per_file_capacity,
                self.config.notes_capacity,
                StoredNotesPublish {
                    observed_at: entry.observed_at,
                    target: entry.target,
                    publisher_id: entry.publisher_id,
                    publisher_ip: entry.publisher_ip,
                    tags: entry.tags,
                    dedup_key: notes_dedup_key(
                        entry.target,
                        entry.publisher_id,
                        entry.publisher_ip,
                    ),
                },
            );
        }
    }

    /// Total indexed keyword publish entries held locally — the count this node
    /// would report as "indexed keywords" (oracle `CIndexed::m_uTotalIndexKeyword`,
    /// which counts every keyword->source publish entry, not distinct keyword IDs).
    /// Each [`StoredKeywordPublish`] is exactly one such entry.
    #[must_use]
    pub fn keyword_entry_count(&self) -> usize {
        self.keyword_entries.len()
    }

    /// Total indexed source publish entries held locally — the count this node
    /// would report as "indexed sources" (oracle `CIndexed::m_uTotalIndexSource`,
    /// which counts every file->source publish entry). Each [`StoredSourcePublish`]
    /// is exactly one such entry.
    #[must_use]
    pub fn source_entry_count(&self) -> usize {
        self.source_entries.len()
    }

    #[cfg(test)]
    fn notes_entry_count(&self) -> usize {
        self.notes_entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{KadLocalStore, KadLocalStoreConfig, source_entry_id};
    use chrono::{DateTime, TimeZone, Utc};
    use emulebb_kad_proto::{
        Ed2kHash, NodeId, PublishEntry, SearchKeyReq, SearchNotesReq, SearchSourceReq, Tag,
        TagName, TagValue, tag_name,
    };
    use std::{net::Ipv4Addr, time::Duration};

    fn config() -> KadLocalStoreConfig {
        KadLocalStoreConfig {
            enabled: true,
            keyword_ttl: Duration::from_secs(60),
            source_ttl: Duration::from_secs(60),
            notes_ttl: Duration::from_secs(60),
            keyword_capacity: 2,
            source_capacity: 2,
            notes_capacity: 2,
            // Per-file caps default to the stock constants; the per-file-cap
            // tests below raise the global caps and rely on these.
            source_per_file_capacity: super::STOCK_MAX_SOURCES_PER_FILE,
            notes_per_file_capacity: super::STOCK_MAX_NOTES_PER_FILE,
        }
    }

    fn ts(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    #[test]
    fn default_source_ttl_matches_master_kademliarepublishtimes() {
        // Master inbound source entry lifetime = KADEMLIAREPUBLISHTIMES (5h),
        // KademliaUDPListener.cpp:1349. Keyword/notes keep the 24h lifetimes.
        let config = KadLocalStoreConfig::default();
        assert_eq!(config.source_ttl, Duration::from_secs(5 * 60 * 60));
        assert_eq!(config.keyword_ttl, Duration::from_secs(24 * 60 * 60));
        assert_eq!(config.notes_ttl, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn keyword_store_dedupes_and_expires_entries() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let entry = PublishEntry {
            hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
        };

        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0)),
            1
        );
        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(5)),
            0
        );
        assert_eq!(store.keyword_entry_count(), 1);

        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(30),
            )
            .expect("keyword response");
        assert_eq!(response.results.len(), 1);

        let expired = store.keyword_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchKeyReq {
                target,
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            10,
            ts(70),
        );
        assert!(expired.is_none());
        assert_eq!(store.keyword_entry_count(), 0);
    }

    #[test]
    fn keyword_publish_rejects_entries_without_stock_name_or_size() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let missing_name = PublishEntry {
            hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![Tag::filesize(123)],
        };
        let missing_size = PublishEntry {
            hash: Ed2kHash::from_bytes([3; 16]),
            tags: vec![Tag::filename("ubuntu linux.iso")],
        };
        let zero_size = PublishEntry {
            hash: Ed2kHash::from_bytes([4; 16]),
            tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(0)],
        };
        let empty_name = PublishEntry {
            hash: Ed2kHash::from_bytes([5; 16]),
            tags: vec![Tag::filename(""), Tag::filesize(123)],
        };

        assert_eq!(
            store.record_keyword_publish_batch(
                target,
                &[missing_name, missing_size, zero_size, empty_name],
                ts(0),
            ),
            0
        );
        assert_eq!(store.keyword_entry_count(), 0);
    }

    #[test]
    fn keyword_publish_replaces_same_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let first = PublishEntry {
            hash: file_hash,
            tags: vec![
                Tag::filename("ubuntu linux.iso"),
                Tag::filesize(123),
                Tag::sources(1),
            ],
        };
        let replacement = PublishEntry {
            hash: file_hash,
            tags: vec![
                Tag::filename("ubuntu linux.iso"),
                Tag::filesize(123),
                Tag::sources(9),
            ],
        };

        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&first), ts(0)),
            1
        );
        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&replacement), ts(5)),
            0
        );
        assert_eq!(store.keyword_entry_count(), 1);
        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(10),
            )
            .expect("keyword response");
        assert_eq!(response.results.len(), 1);
        assert!(response.results[0].tags.iter().any(|tag| {
            matches!(
                (&tag.name, &tag.value),
                (TagName::Short(name), TagValue::UInt(value))
                    if *name == tag_name::SOURCES && *value == 9
            )
        }));
    }

    #[test]
    fn keyword_publish_uses_primary_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let entry = PublishEntry {
            hash: file_hash,
            tags: vec![
                Tag::filename("ubuntu linux.iso"),
                Tag::new_short(tag_name::FILESIZE, TagValue::U32(123)),
                Tag::new_short(tag_name::FILESIZE, TagValue::U32(999)),
            ],
        };

        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0)),
            1
        );
        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(1),
            )
            .expect("keyword response");
        assert!(matches!(
            response.results[0].tags[1].value,
            TagValue::UInt(value) if value == 123
        ));
    }

    #[test]
    fn keyword_publish_accepts_bsob_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let size = (2_u64 << 32) | 1;
        let entry = PublishEntry {
            hash: Ed2kHash::from_bytes([2; 16]),
            tags: vec![
                Tag::filename("large.bin"),
                Tag::new_short(
                    tag_name::FILESIZE,
                    TagValue::SmallBlob(size.to_le_bytes().into()),
                ),
            ],
        };

        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0)),
            1
        );
        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(1),
            )
            .expect("keyword response");
        assert!(matches!(
            response.results[0].tags[1].value,
            TagValue::UInt(value) if value == size
        ));
    }

    #[test]
    fn keyword_publish_drops_duplicate_name_and_size_tags_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let entry = PublishEntry {
            hash: file_hash,
            tags: vec![
                Tag::filename("ubuntu linux.iso"),
                Tag::filesize(123),
                Tag::filename("ignored.iso"),
                Tag::filesize(999),
            ],
        };

        store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0));
        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(1),
            )
            .expect("keyword response");

        assert_eq!(
            short_tag_names(&response.results[0].tags),
            vec![
                tag_name::FILENAME,
                tag_name::FILESIZE,
                tag_name::PUBLISHINFO,
            ]
        );
    }

    #[test]
    fn keyword_search_materializes_stock_publish_info_and_aich_result_tags() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        let file_hash = Ed2kHash::from_bytes([2; 16]);
        let aich_hash = [0xAB; 20];
        let entry = PublishEntry {
            hash: file_hash,
            tags: vec![
                Tag::new_short(tag_name::SOURCES, TagValue::UInt(7)),
                Tag::filesize(123),
                Tag::filename("ubuntu linux.iso"),
                Tag::kad_aich_hash_pub(aich_hash),
                Tag::new_short(tag_name::PUBLISHINFO, TagValue::U32(0xFFFF_FFFF)),
                Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(vec![0])),
            ],
        };

        assert_eq!(
            store.record_keyword_publish_batch(target, std::slice::from_ref(&entry), ts(0)),
            1
        );
        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0,
                    restrictive_payload: Vec::new(),
                },
                10,
                ts(1),
            )
            .expect("keyword response");
        let result_tags = &response.results[0].tags;
        assert_eq!(
            short_tag_names(result_tags),
            vec![
                tag_name::FILENAME,
                tag_name::FILESIZE,
                tag_name::SOURCES,
                tag_name::PUBLISHINFO,
                tag_name::KADAICHHASHRESULT,
            ]
        );
        assert!(matches!(
            result_tags[3].value,
            TagValue::U32(value) if value == 0x0101_03E8
        ));
        assert!(matches!(
            &result_tags[4].value,
            TagValue::SmallBlob(value)
                if value.len() == 22 && value[0] == 1 && value[1] == 1 && value[2..] == aich_hash
        ));
    }

    #[test]
    fn source_store_eviction_keeps_newest_entries() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher_one = NodeId::from_bytes([
            0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05, 0x0C, 0x0B, 0x0A, 0x09, 0x10, 0x0F,
            0x0E, 0x0D,
        ]);
        let publisher_two = NodeId::from_bytes([
            0x14, 0x13, 0x12, 0x11, 0x18, 0x17, 0x16, 0x15, 0x1C, 0x1B, 0x1A, 0x19, 0x20, 0x1F,
            0x1E, 0x1D,
        ]);
        let publisher_three = NodeId::from_bytes([
            0x24, 0x23, 0x22, 0x21, 0x28, 0x27, 0x26, 0x25, 0x2C, 0x2B, 0x2A, 0x29, 0x30, 0x2F,
            0x2E, 0x2D,
        ]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                publisher_one,
                Ipv4Addr::new(1, 1, 1, 1),
                4672,
                &tags,
                ts(1),
            ),
            Some(1)
        );
        assert_eq!(
            store.record_source_publish(
                target,
                publisher_two,
                Ipv4Addr::new(2, 2, 2, 2),
                4673,
                &tags,
                ts(2),
            ),
            Some(0)
        );
        assert_eq!(
            store.record_source_publish(
                target,
                publisher_three,
                Ipv4Addr::new(3, 3, 3, 3),
                4674,
                &tags,
                ts(3),
            ),
            Some(0)
        );

        assert_eq!(store.source_entry_count(), 2);
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(3),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 2);
        assert_eq!(
            response.results[0].entry_id,
            source_entry_id(publisher_three)
        );
        assert_eq!(response.results[1].entry_id, source_entry_id(publisher_two));
        assert!(response.results.iter().all(|entry| {
            entry
                .tags
                .iter()
                .any(|tag| matches!(&tag.name, TagName::Short(name) if *name == tag_name::SOURCEIP))
        }));
    }

    #[test]
    fn source_publish_without_stock_source_type_is_rejected() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let tags = vec![
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                4672,
                &tags,
                ts(1),
            ),
            None
        );
        assert_eq!(store.source_entry_count(), 0);
    }

    #[test]
    fn source_publish_without_stock_tcp_port_is_rejected() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(0)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                4672,
                &tags,
                ts(1),
            ),
            None
        );
        assert_eq!(store.source_entry_count(), 0);
    }

    #[test]
    fn source_publish_without_stock_ip_or_udp_port_is_rejected() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                publisher,
                Ipv4Addr::new(0, 0, 0, 0),
                4672,
                &tags,
                ts(1),
            ),
            None
        );
        assert_eq!(
            store.record_source_publish(
                target,
                publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                0,
                &tags,
                ts(1),
            ),
            None
        );
        assert_eq!(store.source_entry_count(), 0);
    }

    #[test]
    fn source_publish_replaces_same_ip_and_tcp_or_udp_port_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let first_publisher = NodeId::from_bytes([4; 16]);
        let second_publisher = NodeId::from_bytes([5; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                first_publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                4672,
                &tags,
                ts(1),
            ),
            Some(1)
        );
        assert_eq!(
            store.record_source_publish(
                target,
                second_publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                4673,
                &tags,
                ts(2),
            ),
            Some(0)
        );

        assert_eq!(store.source_entry_count(), 1);
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(2),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(
            response.results[0].entry_id,
            source_entry_id(second_publisher)
        );
    }

    #[test]
    fn source_search_materializes_stock_source_tag_shape() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(4662)),
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x0202_0202)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::UInt(4672)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(9999)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::UInt(9999)),
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(2)),
        ];

        assert_eq!(
            store.record_source_publish(
                target,
                publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                4672,
                &tags,
                ts(1),
            ),
            Some(1)
        );
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(1),
            )
            .expect("source response");
        let result_tags = &response.results[0].tags;
        assert_eq!(
            short_tag_names(result_tags),
            vec![
                tag_name::FILESIZE,
                tag_name::SOURCEIP,
                tag_name::SOURCETYPE,
                tag_name::SOURCEPORT,
                tag_name::SOURCEIP,
                tag_name::SOURCEUPORT,
            ]
        );
        assert!(matches!(
            result_tags[1].value,
            TagValue::U32(value) if value == 0x0101_0101
        ));
        assert!(matches!(
            result_tags[3].value,
            TagValue::U32(value) if value == 4662
        ));
        assert!(matches!(
            result_tags[4].value,
            TagValue::U32(value) if value == 0x0202_0202
        ));
        assert!(matches!(
            result_tags[5].value,
            TagValue::U16(value) if value == 4672
        ));
    }

    #[test]
    fn source_search_does_not_backfill_missing_udp_port_tag_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(4662)),
            Tag::filesize(456),
        ];

        store.record_source_publish(
            target,
            NodeId::from_bytes([4; 16]),
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(1),
            )
            .expect("source response");

        assert!(!short_tag_names(&response.results[0].tags).contains(&tag_name::SOURCEUPORT));
    }

    #[test]
    fn source_publish_drops_non_integer_server_ip_tag_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::UInt(4662)),
            Tag::new_short(tag_name::SERVERIP, TagValue::String("bad".into())),
            Tag::new_short(tag_name::SERVERIP, TagValue::U32(0x0202_0202)),
            Tag::filesize(456),
        ];

        store.record_source_publish(
            target,
            NodeId::from_bytes([4; 16]),
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );
        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                10,
                ts(1),
            )
            .expect("source response");

        let server_ip_tags = response.results[0]
            .tags
            .iter()
            .filter(|tag| matches!(&tag.name, TagName::Short(name) if *name == tag_name::SERVERIP))
            .collect::<Vec<_>>();
        assert_eq!(server_ip_tags.len(), 1);
        assert!(matches!(
            &server_ip_tags[0].value,
            TagValue::U32(value) if *value == 0x0202_0202
        ));
    }

    #[test]
    fn source_publish_filters_result_only_tags_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
            Tag::new_short(tag_name::PUBLISHINFO, TagValue::U32(0xFFFF_FFFF)),
            Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(vec![1])),
        ];

        store.record_source_publish(
            target,
            NodeId::from_bytes([4; 16]),
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 0,
                },
                10,
                ts(2),
            )
            .expect("source response");
        let tag_names = short_tag_names(&response.results[0].tags);
        assert!(!tag_names.contains(&tag_name::PUBLISHINFO));
        assert!(!tag_names.contains(&tag_name::KADAICHHASHRESULT));
    }

    #[test]
    fn source_search_zero_size_matches_known_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);

        store.record_source_publish(
            target,
            publisher,
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &source_publish_tags(4662),
            ts(1),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 0,
                },
                10,
                ts(2),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].entry_id, source_entry_id(publisher));
    }

    #[test]
    fn source_search_matches_split_large_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let size = (2_u64 << 32) | 1;
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        store.record_source_publish(
            target,
            publisher,
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size,
                },
                10,
                ts(2),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 1);
        assert!(matches!(
            response.results[0].tags[0].value,
            TagValue::UInt(value) if value == size
        ));
    }

    #[test]
    fn source_search_matches_bsob_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let size = (2_u64 << 32) | 1;
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(
                tag_name::FILESIZE,
                TagValue::SmallBlob(size.to_le_bytes().into()),
            ),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        store.record_source_publish(
            target,
            publisher,
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size,
                },
                10,
                ts(2),
            )
            .expect("source response");
        assert_eq!(response.results.len(), 1);
        assert!(matches!(
            response.results[0].tags[0].value,
            TagValue::UInt(value) if value == size
        ));
    }

    #[test]
    fn source_search_offset_applies_before_size_filter_like_stock() {
        let mut config = config();
        config.source_capacity = 3;
        let mut store = KadLocalStore::new(config);
        let target = NodeId::from_bytes([3; 16]);
        let other_size_tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::FILESIZE, TagValue::UInt(456)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];
        let requested_size_tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::FILESIZE, TagValue::UInt(123)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        store.record_source_publish(
            target,
            NodeId::from_bytes([1; 16]),
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &requested_size_tags,
            ts(1),
        );
        store.record_source_publish(
            target,
            NodeId::from_bytes([2; 16]),
            Ipv4Addr::new(2, 2, 2, 2),
            4672,
            &requested_size_tags,
            ts(2),
        );
        store.record_source_publish(
            target,
            NodeId::from_bytes([3; 16]),
            Ipv4Addr::new(3, 3, 3, 3),
            4672,
            &other_size_tags,
            ts(3),
        );
        assert_eq!(store.source_entry_count(), 3);

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 1,
                    size: 123,
                },
                10,
                ts(4),
            )
            .expect("source response");

        assert_eq!(response.results.len(), 2);
        assert_eq!(
            response.results[0].entry_id,
            source_entry_id(NodeId::from_bytes([2; 16]))
        );
        assert_eq!(
            response.results[1].entry_id,
            source_entry_id(NodeId::from_bytes([1; 16]))
        );
    }

    #[test]
    fn source_search_result_uses_primary_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([3; 16]);
        let publisher = NodeId::from_bytes([4; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(123)),
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(999)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(4662)),
        ];

        store.record_source_publish(
            target,
            publisher,
            Ipv4Addr::new(1, 1, 1, 1),
            4672,
            &tags,
            ts(1),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 123,
                },
                10,
                ts(2),
            )
            .expect("source response");
        assert!(matches!(
            response.results[0].tags[0].value,
            TagValue::UInt(value) if value == 123
        ));
    }

    #[test]
    fn source_publish_load_matches_stock_source_count_percentage() {
        let mut config = config();
        config.source_capacity = super::STOCK_MAX_SOURCES_PER_FILE + 2;
        config.source_ttl = std::time::Duration::from_secs(10_000);
        let mut store = KadLocalStore::new(config);
        let target = NodeId::from_bytes([3; 16]);

        for index in 0..super::STOCK_MAX_SOURCES_PER_FILE {
            let source_tcp_port = 4000 + index as u16;
            let expected_load = if index == 0 {
                1
            } else {
                (index * 100 / super::STOCK_MAX_SOURCES_PER_FILE) as u8
            };
            assert_eq!(
                store.record_source_publish(
                    target,
                    numbered_node_id(index),
                    numbered_ipv4(index),
                    5000 + index as u16,
                    &source_publish_tags(source_tcp_port),
                    ts(index as i64),
                ),
                Some(expected_load),
                "unexpected stock source load at index {index}"
            );
        }

        let full_index = super::STOCK_MAX_SOURCES_PER_FILE;
        assert_eq!(
            store.record_source_publish(
                target,
                numbered_node_id(full_index),
                numbered_ipv4(full_index),
                5000 + full_index as u16,
                &source_publish_tags(4000 + full_index as u16),
                ts(full_index as i64),
            ),
            Some(100)
        );
        assert_eq!(
            store.source_entry_count(),
            super::STOCK_MAX_SOURCES_PER_FILE + 1
        );

        let overflow_index = super::STOCK_MAX_SOURCES_PER_FILE + 1;
        assert_eq!(
            store.record_source_publish(
                target,
                numbered_node_id(overflow_index),
                numbered_ipv4(overflow_index),
                5000 + overflow_index as u16,
                &source_publish_tags(4000 + overflow_index as u16),
                ts(overflow_index as i64),
            ),
            Some(100)
        );
        assert_eq!(
            store.source_entry_count(),
            super::STOCK_MAX_SOURCES_PER_FILE + 1
        );
    }

    #[test]
    fn per_file_and_global_source_caps_are_independent() {
        // Per-file cap is per target; the global cap bounds the whole store.
        // The per-file cap uses stock `> cap` semantics, so one file settles at
        // `per_file_capacity + 1` entries (matching the existing stock-load
        // test). With a larger global cap, a second file fills independently
        // until the global cap engages across files.
        let mut config = config();
        config.source_per_file_capacity = 2; // one file settles at 3 entries
        config.source_capacity = 5; // global across all files
        config.source_ttl = std::time::Duration::from_secs(10_000);
        let mut store = KadLocalStore::new(config);
        let file_a = NodeId::from_bytes([0xA1; 16]);
        let file_b = NodeId::from_bytes([0xB2; 16]);

        // Five sources for file A: the per-file cap (2) holds it at cap+1 = 3.
        for index in 0..5 {
            store.record_source_publish(
                file_a,
                numbered_node_id(index),
                numbered_ipv4(index),
                5000 + index as u16,
                &source_publish_tags(4000 + index as u16),
                ts(index as i64),
            );
        }
        assert_eq!(store.source_entry_count(), 3, "file A bounded by per-file cap");

        // Two sources for file B: file B settles within its own per-file cap and
        // the store total (3 + 2 = 5) is exactly the global cap.
        for index in 100..102 {
            store.record_source_publish(
                file_b,
                numbered_node_id(index),
                numbered_ipv4(index),
                5000 + index as u16,
                &source_publish_tags(4000 + index as u16),
                ts(index as i64),
            );
        }
        assert_eq!(store.source_entry_count(), 5);

        // A third source for file B is within file B's per-file cap, but would
        // push the store to 6 entries: the global cap (5) evicts the oldest.
        store.record_source_publish(
            file_b,
            numbered_node_id(102),
            numbered_ipv4(102),
            5102,
            &source_publish_tags(4102),
            ts(102),
        );
        assert_eq!(
            store.source_entry_count(),
            5,
            "global cap bounds the whole store across files"
        );
    }

    #[test]
    fn default_source_caps_do_not_conflate_per_file_and_global() {
        // Regression for the conflated defaults: the global source cap must be
        // strictly larger than the per-file cap so the two are distinct.
        let cfg = KadLocalStoreConfig::default();
        assert!(cfg.source_capacity > cfg.source_per_file_capacity);
        assert!(cfg.notes_capacity > cfg.notes_per_file_capacity);
        assert_eq!(cfg.source_per_file_capacity, super::STOCK_MAX_SOURCES_PER_FILE);
        assert_eq!(cfg.notes_per_file_capacity, super::STOCK_MAX_NOTES_PER_FILE);
    }

    #[test]
    fn source_overflow_evicts_tail_position_not_refreshed_timestamp_like_stock() {
        let mut config = config();
        config.source_capacity = super::STOCK_MAX_SOURCES_PER_FILE + 2;
        config.source_ttl = std::time::Duration::from_secs(10_000);
        let mut store = KadLocalStore::new(config);
        let target = NodeId::from_bytes([3; 16]);

        for index in 0..=super::STOCK_MAX_SOURCES_PER_FILE {
            store.record_source_publish(
                target,
                numbered_node_id(index),
                numbered_ipv4(index),
                5000 + index as u16,
                &source_publish_tags(4000 + index as u16),
                ts(index as i64),
            );
        }

        let refreshed_first_publisher = NodeId::from_bytes([0xEE; 16]);
        store.record_source_publish(
            target,
            refreshed_first_publisher,
            numbered_ipv4(0),
            5000,
            &source_publish_tags(4000),
            ts(2_000),
        );
        store.record_source_publish(
            target,
            numbered_node_id(super::STOCK_MAX_SOURCES_PER_FILE + 1),
            numbered_ipv4(super::STOCK_MAX_SOURCES_PER_FILE + 1),
            5000 + (super::STOCK_MAX_SOURCES_PER_FILE + 1) as u16,
            &source_publish_tags(4000 + (super::STOCK_MAX_SOURCES_PER_FILE + 1) as u16),
            ts(2_001),
        );

        let response = store
            .source_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchSourceReq {
                    target,
                    start_position: 0,
                    size: 456,
                },
                super::STOCK_MAX_SOURCES_PER_FILE + 2,
                ts(2_002),
            )
            .expect("source response");
        let result_ids = response
            .results
            .iter()
            .map(|entry| entry.entry_id)
            .collect::<Vec<_>>();
        assert!(!result_ids.contains(&source_entry_id(refreshed_first_publisher)));
        assert!(result_ids.contains(&source_entry_id(numbered_node_id(1))));
    }

    #[test]
    fn notes_store_filters_by_size_when_available() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);
        let tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        assert_eq!(
            store.record_notes_publish(
                target,
                publisher_id,
                Ipv4Addr::new(1, 1, 1, 1),
                &tags,
                ts(1),
            ),
            Some(1)
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 900 },
                10,
                ts(10),
            )
            .expect("notes response");
        assert_eq!(store.notes_entry_count(), 1);
        assert_eq!(response.results.len(), 1);
        assert_eq!(
            response.results[0].entry_id,
            Ed2kHash::from_bytes(publisher_id.to_be_bytes())
        );

        let missing = store.notes_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchNotesReq { target, size: 901 },
            10,
            ts(10),
        );
        assert!(missing.is_none());
    }

    #[test]
    fn notes_search_zero_size_matches_known_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);
        let tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        store.record_notes_publish(
            target,
            publisher_id,
            Ipv4Addr::new(1, 1, 1, 1),
            &tags,
            ts(1),
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 0 },
                10,
                ts(2),
            )
            .expect("notes response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(
            response.results[0].entry_id,
            Ed2kHash::from_bytes(publisher_id.to_be_bytes())
        );
    }

    #[test]
    fn notes_search_matches_split_large_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);
        let size = (2_u64 << 32) | 1;
        let tags = vec![
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        store.record_notes_publish(
            target,
            publisher_id,
            Ipv4Addr::new(1, 1, 1, 1),
            &tags,
            ts(1),
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size },
                10,
                ts(2),
            )
            .expect("notes response");
        assert_eq!(response.results.len(), 1);
        assert!(matches!(
            response.results[0].tags[0].value,
            TagValue::UInt(value) if value == size
        ));
    }

    #[test]
    fn notes_publish_ignores_bsob_file_size_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);
        let size = (2_u64 << 32) | 1;
        let tags = vec![
            Tag::new_short(
                tag_name::FILESIZE,
                TagValue::SmallBlob(size.to_le_bytes().into()),
            ),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        store.record_notes_publish(
            target,
            publisher_id,
            Ipv4Addr::new(1, 1, 1, 1),
            &tags,
            ts(1),
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size },
                10,
                ts(2),
            )
            .expect("notes response");
        assert_eq!(response.results.len(), 1);
        assert!(!short_tag_names(&response.results[0].tags).contains(&tag_name::FILESIZE));
    }

    #[test]
    fn notes_publish_rejects_empty_stock_identity_or_tags() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);

        assert_eq!(
            store.record_notes_publish(
                target,
                publisher_id,
                Ipv4Addr::new(0, 0, 0, 0),
                &[Tag::filesize(900)],
                ts(1),
            ),
            None
        );
        assert_eq!(
            store
                .record_notes_publish(target, publisher_id, Ipv4Addr::new(1, 1, 1, 1), &[], ts(1),),
            None
        );
        assert_eq!(store.notes_entry_count(), 0);
    }

    #[test]
    fn notes_publish_replaces_same_ip_or_publisher_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let first_publisher = NodeId::from_bytes([8; 16]);
        let second_publisher = NodeId::from_bytes([9; 16]);
        let first_tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("first".into())),
        ];
        let replacement_tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("second".into())),
        ];

        assert_eq!(
            store.record_notes_publish(
                target,
                first_publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                &first_tags,
                ts(1),
            ),
            Some(1)
        );
        assert_eq!(
            store.record_notes_publish(
                target,
                second_publisher,
                Ipv4Addr::new(1, 1, 1, 1),
                &replacement_tags,
                ts(2),
            ),
            Some(0)
        );

        assert_eq!(store.notes_entry_count(), 1);
        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 900 },
                10,
                ts(3),
            )
            .expect("notes response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(
            response.results[0].entry_id,
            Ed2kHash::from_bytes(second_publisher.to_be_bytes())
        );
        assert!(response.results[0].tags.iter().any(|tag| {
            matches!(
                (&tag.name, &tag.value),
                (TagName::Short(name), TagValue::String(value))
                    if *name == tag_name::DESCRIPTION && value == "second"
            )
        }));
    }

    #[test]
    fn notes_search_materializes_stock_tag_shape() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let publisher_id = NodeId::from_bytes([8; 16]);
        let tags = vec![
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
            Tag::filesize(900),
            Tag::filename("ubuntu linux.iso"),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("better".into())),
            Tag::filesize(901),
            Tag::filename("ignored.iso"),
        ];

        assert_eq!(
            store.record_notes_publish(
                target,
                publisher_id,
                Ipv4Addr::new(1, 1, 1, 1),
                &tags,
                ts(1),
            ),
            Some(1)
        );
        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 900 },
                10,
                ts(2),
            )
            .expect("notes response");
        let result_tags = &response.results[0].tags;
        assert_eq!(
            short_tag_names(result_tags),
            vec![
                tag_name::FILENAME,
                tag_name::FILESIZE,
                tag_name::DESCRIPTION,
                tag_name::DESCRIPTION,
            ]
        );
        assert!(matches!(
            &result_tags[0].value,
            TagValue::String(value) if value == "ubuntu linux.iso"
        ));
        assert!(matches!(
            result_tags[1].value,
            TagValue::UInt(value) if value == 900
        ));
    }

    #[test]
    fn notes_publish_filters_result_only_tags_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([7; 16]);
        let tags = vec![
            Tag::filename("ubuntu linux.iso"),
            Tag::filesize(123),
            Tag::new_short(tag_name::PUBLISHINFO, TagValue::U32(0xFFFF_FFFF)),
            Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(vec![1])),
        ];

        store.record_notes_publish(
            target,
            NodeId::from_bytes([8; 16]),
            Ipv4Addr::new(1, 1, 1, 1),
            &tags,
            ts(1),
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 0 },
                10,
                ts(2),
            )
            .expect("notes response");
        let tag_names = short_tag_names(&response.results[0].tags);
        assert!(!tag_names.contains(&tag_name::PUBLISHINFO));
        assert!(!tag_names.contains(&tag_name::KADAICHHASHRESULT));
    }

    #[test]
    fn notes_overflow_evicts_tail_position_not_refreshed_timestamp_like_stock() {
        let mut config = config();
        config.notes_capacity = super::STOCK_MAX_NOTES_PER_FILE + 2;
        config.notes_ttl = std::time::Duration::from_secs(10_000);
        let mut store = KadLocalStore::new(config);
        let target = NodeId::from_bytes([7; 16]);
        let tags = vec![
            Tag::filesize(900),
            Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
        ];

        for index in 0..=super::STOCK_MAX_NOTES_PER_FILE {
            store.record_notes_publish(
                target,
                numbered_node_id(index),
                numbered_ipv4(index),
                &tags,
                ts(index as i64),
            );
        }

        let refreshed_first_publisher = NodeId::from_bytes([0xEE; 16]);
        store.record_notes_publish(
            target,
            refreshed_first_publisher,
            numbered_ipv4(0),
            &tags,
            ts(2_000),
        );
        store.record_notes_publish(
            target,
            numbered_node_id(super::STOCK_MAX_NOTES_PER_FILE + 1),
            numbered_ipv4(super::STOCK_MAX_NOTES_PER_FILE + 1),
            &tags,
            ts(2_001),
        );

        let response = store
            .notes_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchNotesReq { target, size: 900 },
                super::STOCK_MAX_NOTES_PER_FILE + 2,
                ts(2_002),
            )
            .expect("notes response");
        let result_ids = response
            .results
            .iter()
            .map(|entry| entry.entry_id)
            .collect::<Vec<_>>();
        assert!(!result_ids.contains(&Ed2kHash::from_bytes(
            refreshed_first_publisher.to_be_bytes()
        )));
        assert!(result_ids.contains(&Ed2kHash::from_bytes(numbered_node_id(1).to_be_bytes())));
    }

    #[test]
    fn restrictive_keyword_searches_filter_local_results_like_stock() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        store.record_keyword_publish_batch(
            target,
            &[
                PublishEntry {
                    hash: Ed2kHash::from_bytes([2; 16]),
                    tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
                },
                PublishEntry {
                    hash: Ed2kHash::from_bytes([3; 16]),
                    tags: vec![Tag::filename("fedora workstation.iso"), Tag::filesize(456)],
                },
            ],
            ts(1),
        );

        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0x8000,
                    restrictive_payload: restrictive_string_payload("linux"),
                },
                10,
                ts(2),
            )
            .expect("restrictive keyword response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].entry_id, Ed2kHash::from_bytes([2; 16]));
    }

    #[test]
    fn restrictive_keyword_searches_apply_stock_offset_after_filtering() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        store.record_keyword_publish_batch(
            target,
            &[
                PublishEntry {
                    hash: Ed2kHash::from_bytes([2; 16]),
                    tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
                },
                PublishEntry {
                    hash: Ed2kHash::from_bytes([3; 16]),
                    tags: vec![Tag::filename("debian linux.iso"), Tag::filesize(456)],
                },
            ],
            ts(1),
        );

        let response = store
            .keyword_search_response(
                NodeId::from_bytes([9; 16]),
                &SearchKeyReq {
                    target,
                    start_position: 0x8001,
                    restrictive_payload: restrictive_string_payload("linux"),
                },
                10,
                ts(2),
            )
            .expect("restrictive keyword response");
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].entry_id, Ed2kHash::from_bytes([3; 16]));
    }

    #[test]
    fn invalid_restrictive_keyword_payload_does_not_emit_local_results() {
        let mut store = KadLocalStore::new(config());
        let target = NodeId::from_bytes([1; 16]);
        store.record_keyword_publish_batch(
            target,
            &[PublishEntry {
                hash: Ed2kHash::from_bytes([2; 16]),
                tags: vec![Tag::filename("ubuntu linux.iso"), Tag::filesize(123)],
            }],
            ts(1),
        );

        let response = store.keyword_search_response(
            NodeId::from_bytes([9; 16]),
            &SearchKeyReq {
                target,
                start_position: 0x8000,
                restrictive_payload: vec![0xAA],
            },
            10,
            ts(2),
        );
        assert!(response.is_none());
    }

    #[test]
    fn stock_first_file_size_uses_primary_size_and_first_high_part() {
        let size = super::size_tags::stock_first_file_size(&[
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(1)),
            Tag::new_short(tag_name::FILESIZE, TagValue::U32(999)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(2)),
            Tag::new_short(tag_name::FILESIZE_HI, TagValue::U32(9)),
        ]);
        assert_eq!(size, Some((2_u64 << 32) | 1));
    }

    fn numbered_node_id(index: usize) -> NodeId {
        let mut bytes = [0; 16];
        bytes[0..4].copy_from_slice(&(index as u32).to_le_bytes());
        NodeId::from_bytes(bytes)
    }

    fn numbered_ipv4(index: usize) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, (index / 250 + 1) as u8, (index % 250 + 1) as u8)
    }

    fn source_publish_tags(source_tcp_port: u16) -> Vec<Tag> {
        vec![
            Tag::new_short(tag_name::SOURCETYPE, TagValue::UInt(1)),
            Tag::filesize(456),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(source_tcp_port)),
        ]
    }

    fn restrictive_string_payload(value: &str) -> Vec<u8> {
        let mut payload = vec![0x01];
        payload.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
        payload.extend(value.as_bytes());
        payload
    }

    fn short_tag_names(tags: &[Tag]) -> Vec<u8> {
        tags.iter()
            .filter_map(|tag| match tag.name {
                TagName::Short(name) => Some(name),
                _ => None,
            })
            .collect()
    }
}
