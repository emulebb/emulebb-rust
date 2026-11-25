//! Source publish store: the stored source record plus the publish-decision,
//! dedup/upsert, per-file/global cap eviction, and result-tag materialisation
//! logic specific to file->source publishes. The `KadLocalStore` orchestrator
//! in the parent owns the entry vector and drives these helpers.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag, TagName, TagValue, tag_name};

use super::entry_store::{
    AdmissionDisposition, DedupEntry, TargetedEntry, TimedEntry, oldest_target_entry_index,
};
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

pub(super) fn stock_source_udp_port(tags: &[Tag], observed_port: u16) -> u16 {
    tags.iter()
        .find_map(source_udp_port_tag_value)
        .unwrap_or(observed_port)
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
                if !saw_source_udp_port && source_udp_port_tag_value(tag).is_some() {
                    tags.push(tag.clone());
                    saw_source_udp_port = true;
                }
            }
            _ => tags.push(tag.clone()),
        }
    }
    if !saw_source_udp_port {
        tags.push(Tag::new_short(
            tag_name::SOURCEUPORT,
            TagValue::UInt(u64::from(entry.source_udp_port)),
        ));
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

fn source_udp_port_tag_value(tag: &Tag) -> Option<u16> {
    if tag.name != TagName::Short(tag_name::SOURCEUPORT) {
        return None;
    }
    let value = match tag.value {
        TagValue::UInt(value) | TagValue::U64(value) => value,
        TagValue::U32(value) => u64::from(value),
        TagValue::U16(value) => u64::from(value),
        TagValue::U8(value) => u64::from(value),
        _ => return None,
    };
    // Stock takes the low 16 bits for indexing while retaining the original tag.
    let port = (value & u64::from(u16::MAX)) as u16;
    (port != 0).then_some(port)
}

pub(super) fn source_entry_id(publisher_id: NodeId) -> Ed2kHash {
    Ed2kHash::from_bytes(publisher_id.to_be_bytes())
}

pub(super) fn upsert_source_entry(
    entries: &mut Vec<StoredSourcePublish>,
    per_file_capacity: usize,
    capacity: usize,
    entry: StoredSourcePublish,
) -> AdmissionDisposition {
    if let Some(existing) = entries.iter_mut().find(|candidate| {
        candidate.target == entry.target
            && candidate.source_ip == entry.source_ip
            && (candidate.source_tcp_port == entry.source_tcp_port
                || candidate.source_udp_port == entry.source_udp_port)
    }) {
        *existing = entry;
        return AdmissionDisposition::Refreshed;
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
        entries.push(entry);
        return AdmissionDisposition::Recycled;
    }

    // The global finite-memory cap is an admission bound, not an eviction
    // policy. A new publish must not displace an unrelated file's source.
    if entries.len() >= capacity {
        return AdmissionDisposition::RejectedGlobalCapacity;
    }
    entries.push(entry);
    AdmissionDisposition::Inserted
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
