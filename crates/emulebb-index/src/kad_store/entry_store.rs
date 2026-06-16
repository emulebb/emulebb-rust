//! Generic storage primitives shared by the keyword/source/notes publish
//! stores: the small entry traits plus TTL purging, dedup upsert, and
//! per-target eviction helpers. The concrete `Stored*Publish` records and
//! their trait impls live in the parent module.

use std::time::Duration;

use chrono::{DateTime, Utc};
use emulebb_kad_proto::NodeId;

pub(super) trait TimedEntry {
    fn observed_at(&self) -> DateTime<Utc>;
}

pub(super) trait DedupEntry {
    fn dedup_key(&self) -> &str;
}

pub(super) trait TargetedEntry {
    fn target(&self) -> NodeId;
}

pub(super) fn purge_expired<T>(entries: &mut Vec<T>, ttl: Duration, now: DateTime<Utc>)
where
    T: TimedEntry,
{
    entries.retain(|entry| entry.observed_at() + ttl > now);
}

pub(super) fn upsert_entry<T>(entries: &mut Vec<T>, capacity: usize, dedup_key: String, entry: T)
where
    T: TimedEntry + DedupEntry,
{
    if let Some(existing) = entries
        .iter_mut()
        .find(|candidate| candidate.dedup_key() == dedup_key)
    {
        *existing = entry;
        return;
    }

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

pub(super) fn oldest_target_entry_index<T>(entries: &[T], target: NodeId) -> Option<usize>
where
    T: TargetedEntry,
{
    entries
        .iter()
        .position(|candidate| candidate.target() == target)
}
