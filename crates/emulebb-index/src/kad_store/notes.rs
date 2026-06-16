//! Notes publish store: the stored note record plus the publish-decision,
//! dedup/upsert, per-file/global cap eviction, and result-tag materialisation
//! logic specific to publisher->notes publishes. The `KadLocalStore`
//! orchestrator in the parent owns the entry vector and drives these helpers.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{NodeId, Tag, TagName, TagValue, tag_name};

use super::entry_store::{DedupEntry, TargetedEntry, TimedEntry, oldest_target_entry_index};
use super::size_tags::{stock_first_file_size, stock_first_filename};

#[derive(Debug, Clone, PartialEq)]
pub(super) struct StoredNotesPublish {
    pub(super) observed_at: DateTime<Utc>,
    pub(super) target: NodeId,
    pub(super) publisher_id: NodeId,
    pub(super) publisher_ip: Ipv4Addr,
    pub(super) tags: Vec<Tag>,
    pub(super) dedup_key: String,
}

impl TimedEntry for StoredNotesPublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl TargetedEntry for StoredNotesPublish {
    fn target(&self) -> NodeId {
        self.target
    }
}

impl DedupEntry for StoredNotesPublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

pub(super) fn notes_result_tags(entry: &StoredNotesPublish) -> Vec<Tag> {
    let mut tags = Vec::new();
    if let Some(name) = stock_first_filename(&entry.tags) {
        tags.push(Tag::filename(name));
    }
    if let Some(size) = stock_first_file_size(&entry.tags).filter(|size| *size > 0) {
        tags.push(Tag::filesize(size));
    }

    for tag in &entry.tags {
        match tag.name {
            TagName::Short(name) if name == tag_name::FILENAME || name == tag_name::FILESIZE => {}
            _ => tags.push(tag.clone()),
        }
    }
    tags
}

pub(super) fn upsert_notes_entry(
    entries: &mut Vec<StoredNotesPublish>,
    per_file_capacity: usize,
    capacity: usize,
    entry: StoredNotesPublish,
) {
    if let Some(existing) = entries.iter_mut().find(|candidate| {
        candidate.target == entry.target
            && (candidate.publisher_ip == entry.publisher_ip
                || candidate.publisher_id == entry.publisher_id)
    }) {
        *existing = entry;
        return;
    }

    // Per-file cap (stock KADEMLIAMAXNOTESPERFILE): evict the oldest note for
    // this target so one file cannot exceed its per-target note list.
    if entries
        .iter()
        .filter(|candidate| candidate.target == entry.target)
        .count()
        > per_file_capacity
        && let Some(oldest_index) = oldest_target_entry_index(entries, entry.target)
    {
        entries.remove(oldest_index);
    }

    // Global store cap: bound total memory across all files.
    if entries.len() >= capacity
        && let Some((oldest_index, _)) = entries
            .iter()
            .enumerate()
            .min_by_key(|(_, candidate)| candidate.observed_at())
    {
        entries.remove(oldest_index);
    }
    entries.push(entry);
}

pub(super) fn stock_notes_publish_load(
    entries: &[StoredNotesPublish],
    target: NodeId,
    per_file_capacity: usize,
    publisher_id: NodeId,
    publisher_ip: Ipv4Addr,
) -> u8 {
    let target_count = entries
        .iter()
        .filter(|candidate| candidate.target == target)
        .count();
    if target_count == 0 {
        return 1;
    }
    if target_count > per_file_capacity
        && !notes_replacement_matches(entries, target, publisher_id, publisher_ip)
    {
        return 100;
    }
    (target_count * 100 / per_file_capacity.max(1)) as u8
}

fn notes_replacement_matches(
    entries: &[StoredNotesPublish],
    target: NodeId,
    publisher_id: NodeId,
    publisher_ip: Ipv4Addr,
) -> bool {
    entries.iter().any(|candidate| {
        candidate.target == target
            && (candidate.publisher_ip == publisher_ip || candidate.publisher_id == publisher_id)
    })
}

pub(super) fn has_stock_note_tags(tags: &[Tag]) -> bool {
    tags.iter().any(|tag| match (&tag.name, &tag.value) {
        (TagName::Short(name), TagValue::String(value)) if *name == tag_name::FILENAME => {
            !value.is_empty()
        }
        (TagName::Short(name), _) if *name == tag_name::FILESIZE => {
            stock_first_file_size(std::slice::from_ref(tag))
                .map(|size| size > 0)
                .unwrap_or(false)
        }
        (TagName::Short(name), _) => *name != tag_name::FILENAME && *name != tag_name::FILESIZE,
        (TagName::Long(_), _) => true,
    })
}

pub(super) fn notes_dedup_key(
    target: NodeId,
    publisher_id: NodeId,
    publisher_ip: Ipv4Addr,
) -> String {
    format!("notes:{target}:{publisher_id}:{publisher_ip}")
}
