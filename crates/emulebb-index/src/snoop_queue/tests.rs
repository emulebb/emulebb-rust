use crate::SnoopEntry;
use chrono::{TimeZone, Utc};

use super::SnoopQueue;
use crate::SnoopQueueConfig;

mod keyword_notes;
mod merge_snapshot;
mod replay_restore;
mod source_selection;

pub(super) fn queue() -> SnoopQueue {
    SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 2,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 2,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    })
}

pub(super) fn ts(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

pub(super) fn keyword_entry(
    logical_key: &str,
    target: &str,
    start_position: u16,
    restrictive_payload_hex: Option<&str>,
    seen_at: i64,
) -> SnoopEntry {
    SnoopEntry::Keyword {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        start_position,
        restrictive_payload_hex: restrictive_payload_hex.map(str::to_string),
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}

pub(super) fn source_entry(
    logical_key: &str,
    target: &str,
    start_position: u16,
    size: u64,
    seen_at: i64,
) -> SnoopEntry {
    SnoopEntry::Source {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        start_position,
        size,
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}

pub(super) fn notes_entry(logical_key: &str, target: &str, size: u64, seen_at: i64) -> SnoopEntry {
    SnoopEntry::Notes {
        logical_key: logical_key.to_string(),
        target: target.to_string(),
        size,
        hit_count: 1,
        first_seen: ts(seen_at),
        last_seen: ts(seen_at),
        last_drained_at: None,
    }
}
