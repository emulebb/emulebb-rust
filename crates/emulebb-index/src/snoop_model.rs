use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Runtime settings for passive replay scheduling of harvested Kad search requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnoopQueueConfig {
    /// Window used to decide whether a harvested query is still fresh demand.
    pub dedup_window_secs: u64,
    /// Shared passive drain budget for keyword and notes requests over ten minutes.
    pub general_max_queries_per_600s: u32,
    /// Shared cooldown before keyword or notes requests may be replayed again.
    pub general_drain_cooldown_secs: u64,
    /// Dedicated passive drain budget for source requests over ten minutes.
    pub source_max_queries_per_600s: u32,
    /// Cooldown before one source request may be replayed again.
    pub source_drain_cooldown_secs: u64,
    /// Result count considered good enough for one passive source replay cycle.
    pub source_stop_after_results: usize,
}

impl Default for SnoopQueueConfig {
    fn default() -> Self {
        Self {
            dedup_window_secs: 28_800,
            general_max_queries_per_600s: 24,
            general_drain_cooldown_secs: 900,
            source_max_queries_per_600s: 60,
            source_drain_cooldown_secs: 300,
            source_stop_after_results: 2,
        }
    }
}

/// Persistable harvested Kad search-request shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum SnoopEntry {
    Keyword {
        logical_key: String,
        target: String,
        start_position: u16,
        restrictive_payload_hex: Option<String>,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
    Source {
        logical_key: String,
        target: String,
        start_position: u16,
        size: u64,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
    Notes {
        logical_key: String,
        target: String,
        size: u64,
        hit_count: u32,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
        last_drained_at: Option<DateTime<Utc>>,
    },
}

impl SnoopEntry {
    #[must_use]
    pub fn logical_key(&self) -> &str {
        match self {
            SnoopEntry::Keyword { logical_key, .. }
            | SnoopEntry::Source { logical_key, .. }
            | SnoopEntry::Notes { logical_key, .. } => logical_key,
        }
    }

    #[must_use]
    pub fn target(&self) -> &str {
        match self {
            SnoopEntry::Keyword { target, .. }
            | SnoopEntry::Source { target, .. }
            | SnoopEntry::Notes { target, .. } => target,
        }
    }

    #[must_use]
    pub fn hit_count(&self) -> u32 {
        match self {
            SnoopEntry::Keyword { hit_count, .. }
            | SnoopEntry::Source { hit_count, .. }
            | SnoopEntry::Notes { hit_count, .. } => *hit_count,
        }
    }

    pub fn set_hit_count(&mut self, value: u32) {
        match self {
            SnoopEntry::Keyword { hit_count, .. }
            | SnoopEntry::Source { hit_count, .. }
            | SnoopEntry::Notes { hit_count, .. } => *hit_count = value,
        }
    }

    #[must_use]
    pub fn first_seen(&self) -> DateTime<Utc> {
        match self {
            SnoopEntry::Keyword { first_seen, .. }
            | SnoopEntry::Source { first_seen, .. }
            | SnoopEntry::Notes { first_seen, .. } => *first_seen,
        }
    }

    pub fn set_first_seen(&mut self, value: DateTime<Utc>) {
        match self {
            SnoopEntry::Keyword { first_seen, .. }
            | SnoopEntry::Source { first_seen, .. }
            | SnoopEntry::Notes { first_seen, .. } => *first_seen = value,
        }
    }

    #[must_use]
    pub fn last_seen(&self) -> DateTime<Utc> {
        match self {
            SnoopEntry::Keyword { last_seen, .. }
            | SnoopEntry::Source { last_seen, .. }
            | SnoopEntry::Notes { last_seen, .. } => *last_seen,
        }
    }

    pub fn set_last_seen(&mut self, value: DateTime<Utc>) {
        match self {
            SnoopEntry::Keyword { last_seen, .. }
            | SnoopEntry::Source { last_seen, .. }
            | SnoopEntry::Notes { last_seen, .. } => *last_seen = value,
        }
    }

    #[must_use]
    pub fn last_drained_at(&self) -> Option<DateTime<Utc>> {
        match self {
            SnoopEntry::Keyword {
                last_drained_at, ..
            }
            | SnoopEntry::Source {
                last_drained_at, ..
            }
            | SnoopEntry::Notes {
                last_drained_at, ..
            } => *last_drained_at,
        }
    }

    pub fn set_last_drained_at(&mut self, value: Option<DateTime<Utc>>) {
        match self {
            SnoopEntry::Keyword {
                last_drained_at, ..
            }
            | SnoopEntry::Source {
                last_drained_at, ..
            }
            | SnoopEntry::Notes {
                last_drained_at, ..
            } => *last_drained_at = value,
        }
    }

    #[must_use]
    pub fn restrictive_payload_hex(&self) -> Option<&str> {
        match self {
            SnoopEntry::Keyword {
                restrictive_payload_hex,
                ..
            } => restrictive_payload_hex.as_deref(),
            SnoopEntry::Source { .. } | SnoopEntry::Notes { .. } => None,
        }
    }
}
