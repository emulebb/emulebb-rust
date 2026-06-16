//! Source publish store: the stored source record plus the publish-decision,
//! dedup/upsert, per-file/global cap eviction, and result-tag materialisation
//! logic specific to file->source publishes. The `KadLocalStore` orchestrator
//! in the parent owns the entry vector and drives these helpers.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag, TagName, TagValue, tag_name};

use super::entry_store::{DedupEntry, TargetedEntry, TimedEntry, oldest_target_entry_index};
use super::size_tags::{
    is_integer_tag_value, stock_first_keyword_source_file_size, stock_stored_publish_tags,
};

#[derive(Debug, Clone, PartialEq)]
pub(super) struct StoredSourcePublish {
    pub(super) observed_at: DateTime<Utc>,
    pub(super) target: NodeId,
    pub(super) publisher_id: NodeId,
    pub(super) source_ip: Ipv4Addr,
    pub(super) source_tcp_port: u16,
    pub(super) source_udp_port: u16,
    pub(super) tags: Vec<Tag>,
    pub(super) dedup_key: String,
}

impl TimedEntry for StoredSourcePublish {
    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl TargetedEntry for StoredSourcePublish {
    fn target(&self) -> NodeId {
        self.target
    }
}

impl DedupEntry for StoredSourcePublish {
    fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

pub(super) fn stock_stored_source_publish_tags(tags: &[Tag]) -> Vec<Tag> {
    stock_stored_publish_tags(tags)
        .into_iter()
        .filter(|tag| {
            !matches!(
                (&tag.name, &tag.value),
                (TagName::Short(name), value)
                    if *name == tag_name::SERVERIP && !is_integer_tag_value(value)
            )
        })
        .collect()
}

pub(super) fn is_stock_source_publish(tags: &[Tag]) -> bool {
    tags.iter()
        .any(|tag| matches!(tag.name, TagName::Short(tag_name::SOURCETYPE)))
}

pub(super) fn stock_source_tcp_port(tags: &[Tag]) -> Option<u16> {
    tags.iter().find_map(|tag| {
        if !matches!(tag.name, TagName::Short(tag_name::SOURCEPORT)) {
            return None;
        }
        match tag.value {
            TagValue::UInt(value) => u16::try_from(value).ok().filter(|port| *port > 0),
            TagValue::U64(value) => u16::try_from(value).ok().filter(|port| *port > 0),
            TagValue::U32(value) => u16::try_from(value).ok().filter(|port| *port > 0),
            TagValue::U16(value) => (value > 0).then_some(value),
            TagValue::U8(value) => (value > 0).then_some(u16::from(value)),
            _ => None,
        }
    })
}

pub(super) fn source_result_tags(entry: &StoredSourcePublish) -> Vec<Tag> {
    let mut tags = Vec::new();
    if let Some(size) = stock_first_keyword_source_file_size(&entry.tags) {
        tags.push(Tag::filesize(size));
    }

    let mut saw_source_type = false;
    let mut saw_source_tcp_port = false;
    let mut saw_source_udp_port = false;
    for tag in &entry.tags {
        match tag.name {
            TagName::Short(name) if name == tag_name::SOURCETYPE => {
                if !saw_source_type {
                    tags.push(source_ip_tag(entry.source_ip));
                    tags.push(tag.clone());
                    saw_source_type = true;
                }
            }
            TagName::Short(name) if name == tag_name::FILESIZE => {}
            TagName::Short(name) if name == tag_name::SOURCEPORT => {
                if !saw_source_tcp_port {
                    tags.push(normalized_source_port_tag(tag));
                    saw_source_tcp_port = true;
                }
            }
            TagName::Short(name) if name == tag_name::SOURCEUPORT => {
                if !saw_source_udp_port && let Some(tag) = normalized_source_udp_port_tag(tag) {
                    tags.push(tag);
                    saw_source_udp_port = true;
                }
            }
            _ => tags.push(tag.clone()),
        }
    }
    tags
}

fn source_ip_tag(source_ip: Ipv4Addr) -> Tag {
    Tag::new_short(
        tag_name::SOURCEIP,
        TagValue::U32(u32::from_be_bytes(source_ip.octets())),
    )
}

fn normalized_source_port_tag(tag: &Tag) -> Tag {
    let mut tag = tag.clone();
    if let TagValue::UInt(value) = tag.value
        && u32::try_from(value).is_ok()
    {
        tag.value = TagValue::U32(value as u32);
    }
    tag
}

fn normalized_source_udp_port_tag(tag: &Tag) -> Option<Tag> {
    let port = match tag.value {
        TagValue::UInt(value) => u16::try_from(value).ok()?,
        TagValue::U64(value) => u16::try_from(value).ok()?,
        TagValue::U32(value) => u16::try_from(value).ok()?,
        TagValue::U16(value) => value,
        TagValue::U8(value) => u16::from(value),
        _ => return None,
    };
    if port == 0 {
        return None;
    }
    Some(Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(port)))
}

pub(super) fn source_entry_id(publisher_id: NodeId) -> Ed2kHash {
    Ed2kHash::from_bytes(publisher_id.to_be_bytes())
}

pub(super) fn upsert_source_entry(
    entries: &mut Vec<StoredSourcePublish>,
    per_file_capacity: usize,
    capacity: usize,
    entry: StoredSourcePublish,
) {
    if let Some(existing) = entries.iter_mut().find(|candidate| {
        candidate.target == entry.target
            && candidate.source_ip == entry.source_ip
            && (candidate.source_tcp_port == entry.source_tcp_port
                || candidate.source_udp_port == entry.source_udp_port)
    }) {
        *existing = entry;
        return;
    }

    // Per-file cap (stock KADEMLIAMAXSOURCEPERFILE): evict the oldest entry for
    // this target so one file cannot exceed its per-target source list.
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

pub(super) fn stock_source_publish_load(
    entries: &[StoredSourcePublish],
    target: NodeId,
    per_file_capacity: usize,
    source_ip: Ipv4Addr,
    source_tcp_port: u16,
    source_udp_port: u16,
) -> u8 {
    let target_count = entries
        .iter()
        .filter(|candidate| candidate.target == target)
        .count();
    if target_count == 0 {
        return 1;
    }
    if target_count > per_file_capacity
        && !source_replacement_matches(entries, target, source_ip, source_tcp_port, source_udp_port)
    {
        return 100;
    }
    (target_count * 100 / per_file_capacity.max(1)) as u8
}

fn source_replacement_matches(
    entries: &[StoredSourcePublish],
    target: NodeId,
    source_ip: Ipv4Addr,
    source_tcp_port: u16,
    source_udp_port: u16,
) -> bool {
    entries.iter().any(|candidate| {
        candidate.target == target
            && candidate.source_ip == source_ip
            && (candidate.source_tcp_port == source_tcp_port
                || candidate.source_udp_port == source_udp_port)
    })
}

pub(super) fn source_dedup_key(
    target: NodeId,
    source_ip: Ipv4Addr,
    source_tcp_port: u16,
    source_udp_port: u16,
) -> String {
    format!("source:{target}:{source_ip}:{source_tcp_port}:{source_udp_port}")
}
