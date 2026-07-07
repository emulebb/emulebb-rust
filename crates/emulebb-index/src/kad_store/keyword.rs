//! Keyword publish store: the stored keyword record plus the publish-decision,
//! dedup, restrictive-payload filtering, and result-tag materialisation logic
//! specific to keyword->file publishes. The `KadLocalStore` orchestrator in the
//! parent owns the entry vector and drives these helpers.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag, TagName, TagValue, tag_name};

use crate::matches_restrictive_keyword_payload;

use super::entry_store::{DedupEntry, TimedEntry};
use super::size_tags::{stock_first_filename, stock_first_keyword_source_file_size};

/// Anti-spam publish points per publishing /24 subnet (oracle
/// `PUBLISHPOINTSSPERSUBNET`, Entry.cpp `RecalcualteTrustValue`).
const PUBLISH_POINTS_PER_SUBNET: f32 = 10.0;

/// Per-keyword-entry publish diversity: the distinct publisher IPs and file
/// names observed for one `(target, file_hash)` entry, mirroring the oracle
/// `CKeyEntry` `m_pliPublishingIPs` / `m_listFileNames`. Live (not persisted):
/// rebuilt as republishes arrive.
#[derive(Debug, Clone, Default)]
struct KeywordDiversity {
    publisher_ips: HashSet<Ipv4Addr>,
    file_names: HashSet<String>,
}

/// Tracks publish diversity per keyword entry plus a global per-/24 publish
/// counter, so the `FT_PUBLISHINFO` search-result tag can report real
/// name/publisher counts and the oracle anti-spam trust value instead of a
/// fabricated constant. Mirrors `CKeyEntry` publish tracking +
/// `s_mapGlobalPublishIPs` (Entry.cpp). In-memory only; a restart resets it and
/// it rebuilds from the next republish cycle (a restored-but-unrefreshed entry
/// falls back to the single-publisher floor when it emits its tag).
#[derive(Debug, Clone, Default)]
pub(super) struct KeywordPublishTracker {
    entries: HashMap<(NodeId, Ed2kHash), KeywordDiversity>,
    /// Global count of (entry, publisher-IP) associations per /24 subnet — the
    /// divisor in the oracle trust formula (`s_mapGlobalPublishIPs[ip & ~0xFF]`).
    global_subnet_counts: HashMap<[u8; 3], u32>,
}

fn subnet24(ip: Ipv4Addr) -> [u8; 3] {
    let [a, b, c, _] = ip.octets();
    [a, b, c]
}

impl KeywordPublishTracker {
    /// Record one publish of `(target, file_hash)` from `publisher_ip` carrying
    /// `file_name`. A publisher IP new to this entry bumps its /24's global
    /// count (oracle `AdjustGlobalPublishTracking(ip, true)`); a repeat publish
    /// only refreshes (deduped by exact IP, oracle `MergeIPsAndFilenames`).
    pub(super) fn record(
        &mut self,
        target: NodeId,
        file_hash: Ed2kHash,
        publisher_ip: Ipv4Addr,
        file_name: Option<String>,
    ) {
        let diversity = self.entries.entry((target, file_hash)).or_default();
        if diversity.publisher_ips.insert(publisher_ip) {
            *self
                .global_subnet_counts
                .entry(subnet24(publisher_ip))
                .or_insert(0) += 1;
        }
        if let Some(name) = file_name
            && !name.is_empty()
        {
            diversity.file_names.insert(name);
        }
    }

    /// Drop every tracked entry whose key is not in `live_keys`, releasing its
    /// global /24 bookkeeping (oracle `CleanUpTrackedPublishers` /
    /// `AdjustGlobalPublishTracking(ip, false)` on expiry / eviction). Keeps the
    /// global counter consistent with the surviving entry set.
    pub(super) fn retain_keys(&mut self, live_keys: &HashSet<(NodeId, Ed2kHash)>) {
        let dropped: Vec<(NodeId, Ed2kHash)> = self
            .entries
            .keys()
            .filter(|key| !live_keys.contains(*key))
            .copied()
            .collect();
        for key in dropped {
            if let Some(diversity) = self.entries.remove(&key) {
                for ip in &diversity.publisher_ips {
                    if let Some(count) = self.global_subnet_counts.get_mut(&subnet24(*ip)) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.global_subnet_counts.remove(&subnet24(*ip));
                        }
                    }
                }
            }
        }
    }

    /// Compute the `FT_PUBLISHINFO` payload `(names, publishers, trust*100)` for
    /// one entry (oracle `CKeyEntry::WriteTagList`): `names`/`publishers` are the
    /// distinct filename / publisher-IP counts (`% 256`), and `trust` is the sum
    /// over publisher IPs of `10 / (global /24 publish count)` (anti-spam:
    /// entries from busy — spammy — /24s score low). An entry with no live
    /// tracking (e.g. restored from cache, not yet republished) falls back to
    /// the single-trusted-publisher floor `(1, 1, 1000)`.
    fn publish_info(&self, target: NodeId, file_hash: Ed2kHash) -> (u32, u32, u32) {
        let Some(diversity) = self.entries.get(&(target, file_hash)) else {
            return (1, 1, 1000);
        };
        if diversity.publisher_ips.is_empty() {
            return (1, 1, 1000);
        }
        let mut trust = 0.0f32;
        for ip in &diversity.publisher_ips {
            let global = self
                .global_subnet_counts
                .get(&subnet24(*ip))
                .copied()
                .unwrap_or(1)
                .max(1);
            trust += PUBLISH_POINTS_PER_SUBNET / global as f32;
        }
        let names = (diversity.file_names.len().max(1) % 256) as u32;
        let publishers = (diversity.publisher_ips.len() % 256) as u32;
        let trust_times_100 = (trust * 100.0) as u32;
        (names, publishers, trust_times_100)
    }
}

// Stock per-keyword index cap (Opcodes.h KADEMLIAMAXINDEX): the maximum number
// of distinct files indexed under a single keyword target.
pub(super) const STOCK_MAX_KEYWORD_INDEX: usize = 50_000;
// Stock overall keyword-entry cap (Opcodes.h KADEMLIAMAXENTRIES): the global
// limit across *all* keywords. eMule keeps an equivalent overall index count
// (CIndexed m_uTotalIndexSource / m_uTotalIndexKeyword) but only the keyword
// path has a hard overall cap; for sources/notes the overall store size is
// bounded purely to keep memory finite. These defaults are deliberately larger
// than the per-file caps so the two semantics never coincide.
pub(super) const STOCK_MAX_KEYWORD_ENTRIES: usize = 60_000;
const STOCK_HOT_KEYWORD_REPUBLISH_MARGIN: usize = 5_000;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct StoredKeywordPublish {
    pub(super) observed_at: DateTime<Utc>,
    pub(super) target: NodeId,
    pub(super) file_hash: Ed2kHash,
    pub(super) tags: Vec<Tag>,
    pub(super) dedup_key: String,
}

impl TimedEntry for StoredKeywordPublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl DedupEntry for StoredKeywordPublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

pub(super) fn keyword_entry_matches_restrictive_payload(
    entry: &StoredKeywordPublish,
    restrictive_payload: Option<&[u8]>,
) -> bool {
    let Some(payload) = restrictive_payload else {
        return true;
    };
    let Some(filename) = stock_first_filename(&entry.tags) else {
        return false;
    };
    matches_restrictive_keyword_payload(&filename, &entry.tags, payload)
}

pub(super) fn keyword_result_tags(
    entry: &StoredKeywordPublish,
    tracker: &KeywordPublishTracker,
) -> Vec<Tag> {
    let mut tags = Vec::new();
    if let Some(name) = stock_first_filename(&entry.tags) {
        tags.push(Tag::filename(name));
    }
    if let Some(size) = stock_first_keyword_source_file_size(&entry.tags).filter(|size| *size > 0) {
        tags.push(Tag::filesize(size));
    }

    let mut aich_result_hash = None;
    for tag in &entry.tags {
        match tag.name {
            TagName::Short(name) if name == tag_name::FILENAME || name == tag_name::FILESIZE => {}
            TagName::Short(name) if name == tag_name::KADAICHHASHPUB => {
                if aich_result_hash.is_none() {
                    aich_result_hash = stock_aich_publish_hash(tag);
                }
            }
            TagName::Short(name)
                if name == tag_name::PUBLISHINFO || name == tag_name::KADAICHHASHRESULT => {}
            _ => tags.push(tag.clone()),
        }
    }

    tags.push(keyword_publish_info_tag(entry, tracker));
    if let Some(hash) = aich_result_hash {
        tags.push(keyword_aich_result_tag(hash));
    }
    tags
}

fn keyword_publish_info_tag(entry: &StoredKeywordPublish, tracker: &KeywordPublishTracker) -> Tag {
    // 32-bit tag: <namecount u8><publishers u8><trust*100 u16> (oracle
    // CKeyEntry::WriteTagList). Computed from tracked publish diversity, not a
    // fabricated constant.
    let (names, publishers, trust_times_100) = tracker.publish_info(entry.target, entry.file_hash);
    let value = ((names & 0xFF) << 24)
        | ((publishers & 0xFF) << 16)
        | (trust_times_100.min(0xFFFF) & 0xFFFF);
    Tag::new_short(tag_name::PUBLISHINFO, TagValue::U32(value))
}

fn stock_aich_publish_hash(tag: &Tag) -> Option<[u8; 20]> {
    let bytes = match &tag.value {
        TagValue::Blob(bytes) | TagValue::SmallBlob(bytes) => bytes,
        _ => return None,
    };
    bytes.as_slice().try_into().ok()
}

fn keyword_aich_result_tag(hash: [u8; 20]) -> Tag {
    let mut payload = Vec::with_capacity(22);
    payload.push(1);
    payload.push(1);
    payload.extend_from_slice(&hash);
    Tag::new_short(tag_name::KADAICHHASHRESULT, TagValue::SmallBlob(payload))
}

pub(super) fn stock_keyword_file_size(tags: &[Tag]) -> Option<u64> {
    stock_first_keyword_source_file_size(tags).filter(|size| *size > 0)
}

/// The first stock filename in a publish tag set, for publisher-diversity
/// name tracking (`m_listFileNames`).
pub(super) fn stock_keyword_first_filename(tags: &[Tag]) -> Option<String> {
    stock_first_filename(tags)
}

pub(super) fn has_stock_keyword_filename(tags: &[Tag]) -> bool {
    tags.iter().any(|tag| {
        matches!(
            (&tag.name, &tag.value),
            (TagName::Short(name), TagValue::String(value))
                if *name == tag_name::FILENAME && !value.is_empty()
        )
    })
}

pub(super) fn stock_keyword_publish_decision(
    entries: &[StoredKeywordPublish],
    target: NodeId,
    file_hash: Ed2kHash,
) -> (u8, bool) {
    if entries.len() > STOCK_MAX_KEYWORD_ENTRIES {
        return (100, false);
    }

    let source_count = keyword_source_count(entries, target);
    if source_count == 0 {
        return (1, true);
    }
    if source_count > STOCK_MAX_KEYWORD_INDEX {
        return (100, false);
    }
    if keyword_source_exists(entries, target, file_hash)
        && source_count > STOCK_MAX_KEYWORD_INDEX - STOCK_HOT_KEYWORD_REPUBLISH_MARGIN
    {
        return (100, false);
    }

    let load = (source_count * 100 / STOCK_MAX_KEYWORD_INDEX) as u8;
    (load, true)
}

fn keyword_source_count(entries: &[StoredKeywordPublish], target: NodeId) -> usize {
    entries
        .iter()
        .filter(|entry| entry.target == target)
        .map(|entry| entry.file_hash)
        .collect::<HashSet<_>>()
        .len()
}

fn keyword_source_exists(
    entries: &[StoredKeywordPublish],
    target: NodeId,
    file_hash: Ed2kHash,
) -> bool {
    entries
        .iter()
        .any(|entry| entry.target == target && entry.file_hash == file_hash)
}

pub(super) fn keyword_dedup_key(target: NodeId, file_hash: Ed2kHash, size: u64) -> String {
    format!("keyword:{target}:{file_hash}:{size}")
}
