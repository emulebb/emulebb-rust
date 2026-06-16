//! Keyword publish store: the stored keyword record plus the publish-decision,
//! dedup, restrictive-payload filtering, and result-tag materialisation logic
//! specific to keyword->file publishes. The `KadLocalStore` orchestrator in the
//! parent owns the entry vector and drives these helpers.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag, TagName, TagValue, tag_name};

use crate::matches_restrictive_keyword_payload;

use super::entry_store::{DedupEntry, TimedEntry};
use super::size_tags::{stock_first_filename, stock_first_keyword_source_file_size};

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

pub(super) fn keyword_result_tags(entry: &StoredKeywordPublish) -> Vec<Tag> {
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

    tags.push(keyword_publish_info_tag(entry));
    if let Some(hash) = aich_result_hash {
        tags.push(keyword_aich_result_tag(hash));
    }
    tags
}

fn keyword_publish_info_tag(_entry: &StoredKeywordPublish) -> Tag {
    let trust_times_100 = 1000_u32;
    let publishers = 1_u32;
    let names = 1_u32;
    let value = (names << 24) | (publishers << 16) | trust_times_100;
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
