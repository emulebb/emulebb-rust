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
    KeywordPublishTracker, STOCK_MAX_KEYWORD_ENTRIES, StoredKeywordPublish,
    has_stock_keyword_filename, keyword_dedup_key, keyword_entry_matches_restrictive_payload,
    keyword_result_tags, stock_keyword_file_size, stock_keyword_first_filename,
    stock_keyword_publish_decision,
};
use notes::{
    StoredNotesPublish, has_stock_note_tags, notes_dedup_key, notes_result_tags,
    stock_notes_publish_load, upsert_notes_entry,
};
use size_tags::{
    search_response, stock_notes_file_size_matches_request, stock_source_file_size_matches_request,
    stock_stored_publish_tags,
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
    /// Live per-keyword-entry publish diversity feeding the `FT_PUBLISHINFO`
    /// search-result tag. Not persisted; rebuilt from republishes.
    keyword_tracker: KeywordPublishTracker,
}

impl KadLocalStore {
    #[must_use]
    pub fn new(config: KadLocalStoreConfig) -> Self {
        Self {
            config,
            keyword_entries: Vec::new(),
            source_entries: Vec::new(),
            notes_entries: Vec::new(),
            keyword_tracker: KeywordPublishTracker::default(),
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
        publisher_ip: Ipv4Addr,
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
            // Track this publisher IP + filename for the FT_PUBLISHINFO tag
            // (oracle CKeyEntry publish tracking).
            self.keyword_tracker.record(
                target,
                entry.hash,
                publisher_ip,
                stock_keyword_first_filename(&entry.tags),
            );
        }
        self.reconcile_keyword_tracker();
        load
    }

    /// Prune the keyword publish tracker to the surviving entry set (after any
    /// purge / capacity eviction), keeping its global /24 counter consistent.
    fn reconcile_keyword_tracker(&mut self) {
        let live_keys: std::collections::HashSet<(NodeId, Ed2kHash)> = self
            .keyword_entries
            .iter()
            .map(|entry| (entry.target, entry.file_hash))
            .collect();
        self.keyword_tracker.retain_keys(&live_keys);
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
        // Keep the publish tracker consistent with entries dropped by the purge.
        self.reconcile_keyword_tracker();
        let offset = usize::from(request.start_position & 0x7FFF);
        let tracker = &self.keyword_tracker;
        let results = self
            .keyword_entries
            .iter()
            .filter(|entry| entry.target == request.target)
            .filter(|entry| keyword_entry_matches_restrictive_payload(entry, restrictive_payload))
            .skip(offset)
            .take(limit)
            .map(|entry| SearchResultEntry {
                entry_id: entry.file_hash,
                tags: keyword_result_tags(entry, tracker),
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
mod tests;
