use std::collections::{HashMap, VecDeque};
use std::str::FromStr;

use chrono::{DateTime, TimeDelta, Utc};
use emulebb_kad_proto::{NodeId, SearchKeyReq, SearchNotesReq, SearchSourceReq};

use crate::{SnoopEntry, SnoopQueueConfig};

/// In-memory scheduler state for harvested KAD search requests.
#[derive(Debug, Clone)]
pub struct SnoopQueue {
    config: SnoopQueueConfig,
    entries: HashMap<String, SnoopEntry>,
    replay_feedback: HashMap<String, ReplayFeedback>,
    recent_general_drains: VecDeque<DateTime<Utc>>,
    recent_source_drains: VecDeque<DateTime<Utc>>,
}

/// Outcome of recording one harvested search shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnoopRecordOutcome {
    pub is_new: bool,
    pub hit_count: u32,
    pub queue_depth: usize,
    pub family_queue_depth: usize,
}

/// Current queue depth by harvested Kad search family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnoopQueueFamilyCounts {
    pub keyword: usize,
    pub source: usize,
    pub notes: usize,
}

/// One queued snoop entry selected for an active passive replay cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduledSnoopRequest<Request> {
    pub logical_key: String,
    pub request: Request,
}

/// In-memory replay feedback used to bias the next passive replay choice.
///
/// This state is intentionally process-local: it helps the scheduler avoid
/// spending every crawl cycle on the same zero-yield shape, but it should not
/// become persisted queue metadata yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ReplayFeedback {
    zero_result_streak: u32,
    last_result_count: u32,
    last_outcome_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
struct ReplayCandidate<Request> {
    scheduled: ScheduledSnoopRequest<Request>,
    hit_count: u32,
    last_seen: DateTime<Utc>,
    zero_result_streak: u32,
    last_result_count: u32,
    observed_after_outcome: bool,
}

impl SnoopQueue {
    /// Creates an empty snoop queue with the provided scheduling settings.
    pub fn new(config: SnoopQueueConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            replay_feedback: HashMap::new(),
            recent_general_drains: VecDeque::new(),
            recent_source_drains: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn config(&self) -> &SnoopQueueConfig {
        &self.config
    }

    /// Restores persisted entries into the in-memory queue.
    pub fn merge_snapshot(&mut self, entries: Vec<SnoopEntry>) {
        for entry in entries {
            if should_skip_restored_entry(&entry) {
                continue;
            }
            self.merge_entry(entry);
        }
    }

    /// Returns a snapshot suitable for flush/persistence calls.
    pub fn snapshot(&self) -> Vec<SnoopEntry> {
        let mut entries = self.entries.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.logical_key().cmp(right.logical_key()));
        entries
    }

    /// Returns the number of unique harvested search shapes currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no harvested search shapes are currently tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Records a harvested search request occurrence.
    pub fn record(&mut self, entry: SnoopEntry) -> SnoopRecordOutcome {
        let family = entry_family(&entry);
        let (is_new, hit_count) = self.merge_entry(entry);
        SnoopRecordOutcome {
            is_new,
            hit_count,
            queue_depth: self.entries.len(),
            family_queue_depth: self.family_count(family),
        }
    }

    /// Returns the current queue depth for each harvested search family.
    pub fn family_counts(&self) -> SnoopQueueFamilyCounts {
        let mut counts = SnoopQueueFamilyCounts::default();
        for entry in self.entries.values() {
            match entry_family(entry) {
                SnoopFamily::Keyword => counts.keyword += 1,
                SnoopFamily::Source => counts.source += 1,
                SnoopFamily::Notes => counts.notes += 1,
            }
        }
        counts
    }

    /// Selects the next keyword request eligible for passive drain and marks it as drained.
    pub fn select_next_keyword_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchKeyReq>> {
        let family = SnoopFamily::Keyword;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = keyword_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        recent.sort_by(candidate_cmp);
        stale.sort_by(candidate_cmp);
        let selected = recent
            .into_iter()
            .next()
            .or_else(|| stale.into_iter().next())?;
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Selects the next source request eligible for passive drain and marks it as drained.
    pub fn select_next_source_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchSourceReq>> {
        let family = SnoopFamily::Source;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = source_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        let selected = select_best_source_candidate(recent, stale)?;
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Selects the next notes request eligible for passive drain and marks it as drained.
    pub fn select_next_notes_request(
        &mut self,
        now: DateTime<Utc>,
    ) -> Option<ScheduledSnoopRequest<SearchNotesReq>> {
        let family = SnoopFamily::Notes;
        self.prune_recent_drains(now, family);
        if self.recent_drain_len(family) >= self.family_max_queries_per_600s(family) as usize {
            return None;
        }

        let dedup_cutoff = now - seconds(self.config.dedup_window_secs);
        let cooldown_secs = self.family_drain_cooldown_secs(family);
        let cooldown_cutoff = now - seconds(cooldown_secs);
        let mut recent = Vec::new();
        let mut stale = Vec::new();

        for entry in self.entries.values() {
            let Some(request) = notes_request(entry) else {
                continue;
            };
            let logical_key = entry.logical_key().to_string();
            let feedback = self
                .replay_feedback
                .get(&logical_key)
                .copied()
                .unwrap_or_default();
            if entry.last_drained_at().is_some_and(|last_drained_at| {
                last_drained_at
                    > replay_cooldown_cutoff(cooldown_cutoff, now, cooldown_secs, entry, feedback)
            }) {
                continue;
            }
            let candidate = ReplayCandidate {
                scheduled: ScheduledSnoopRequest {
                    logical_key,
                    request,
                },
                hit_count: entry.hit_count(),
                last_seen: entry.last_seen(),
                zero_result_streak: feedback.zero_result_streak,
                last_result_count: feedback.last_result_count,
                observed_after_outcome: feedback
                    .last_outcome_at
                    .is_none_or(|last_outcome_at| entry.last_seen() > last_outcome_at),
            };
            if entry.last_seen() >= dedup_cutoff {
                recent.push(candidate);
            } else {
                stale.push(candidate);
            }
        }

        recent.sort_by(notes_candidate_cmp);
        stale.sort_by(notes_candidate_cmp);
        let selected = recent
            .into_iter()
            .next()
            .or_else(|| stale.into_iter().next())?;
        if let Some(entry) = self.entries.get_mut(&selected.scheduled.logical_key) {
            entry.set_last_drained_at(Some(now));
        }
        self.recent_drains_mut(family).push_back(now);
        Some(selected.scheduled)
    }

    /// Records the result density of one completed passive replay cycle.
    pub fn record_replay_outcome(
        &mut self,
        logical_key: &str,
        completed_at: DateTime<Utc>,
        result_count: usize,
    ) {
        if result_count > 0 {
            // Successful passive replays are demand-driven one-shots. Remove the drained
            // shape so fresh observations immediately reclaim scheduling priority instead of
            // keeping a growing backlog of already-served requests across sessions.
            self.entries.remove(logical_key);
            self.replay_feedback.remove(logical_key);
            return;
        }
        let feedback = self
            .replay_feedback
            .entry(logical_key.to_string())
            .or_default();
        feedback.last_result_count = result_count as u32;
        feedback.last_outcome_at = Some(completed_at);
        if result_count == 0 {
            feedback.zero_result_streak = feedback.zero_result_streak.saturating_add(1);
            if feedback.zero_result_streak >= 2
                && self
                    .entries
                    .get(logical_key)
                    .is_some_and(should_evict_zero_yield_source_entry)
            {
                self.entries.remove(logical_key);
                self.replay_feedback.remove(logical_key);
            }
        } else {
            feedback.zero_result_streak = 0;
        }
    }

    fn merge_entry(&mut self, entry: SnoopEntry) -> (bool, u32) {
        let logical_key = entry.logical_key().to_string();
        if let Some(existing) = self.entries.get_mut(&logical_key) {
            let next_hit_count = existing.hit_count().saturating_add(entry.hit_count());
            existing.set_hit_count(next_hit_count);
            existing.set_last_seen(existing.last_seen().max(entry.last_seen()));
            existing.set_first_seen(existing.first_seen().min(entry.first_seen()));
            existing.set_last_drained_at(
                match (existing.last_drained_at(), entry.last_drained_at()) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (Some(left), None) => Some(left),
                    (None, right) => right,
                },
            );
            return (false, next_hit_count);
        }
        self.entries.insert(logical_key, entry);
        (true, 1)
    }

    fn prune_recent_drains(&mut self, now: DateTime<Utc>, family: SnoopFamily) {
        let cutoff = now - TimeDelta::minutes(10);
        let recent_drains = self.recent_drains_mut(family);
        while recent_drains
            .front()
            .is_some_and(|drained_at| drained_at < &cutoff)
        {
            recent_drains.pop_front();
        }
    }

    fn family_count(&self, family: SnoopFamily) -> usize {
        self.entries
            .values()
            .filter(|entry| entry_family(entry) == family)
            .count()
    }

    fn family_max_queries_per_600s(&self, family: SnoopFamily) -> u32 {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.config.general_max_queries_per_600s,
            SnoopFamily::Source => self.config.source_max_queries_per_600s,
        }
    }

    fn family_drain_cooldown_secs(&self, family: SnoopFamily) -> u64 {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.config.general_drain_cooldown_secs,
            SnoopFamily::Source => self.config.source_drain_cooldown_secs,
        }
    }

    fn recent_drain_len(&self, family: SnoopFamily) -> usize {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => self.recent_general_drains.len(),
            SnoopFamily::Source => self.recent_source_drains.len(),
        }
    }

    fn recent_drains_mut(&mut self, family: SnoopFamily) -> &mut VecDeque<DateTime<Utc>> {
        match family {
            SnoopFamily::Keyword | SnoopFamily::Notes => &mut self.recent_general_drains,
            SnoopFamily::Source => &mut self.recent_source_drains,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnoopFamily {
    Keyword,
    Source,
    Notes,
}

fn entry_family(entry: &SnoopEntry) -> SnoopFamily {
    match entry {
        SnoopEntry::Keyword { .. } => SnoopFamily::Keyword,
        SnoopEntry::Source { .. } => SnoopFamily::Source,
        SnoopEntry::Notes { .. } => SnoopFamily::Notes,
    }
}

fn keyword_request(entry: &SnoopEntry) -> Option<SearchKeyReq> {
    let SnoopEntry::Keyword {
        target,
        start_position,
        restrictive_payload_hex,
        ..
    } = entry
    else {
        return None;
    };
    let target = NodeId::from_str(target).ok()?;
    let restrictive_payload = restrictive_payload_hex
        .as_deref()
        .map(decode_hex_bytes)
        .transpose()
        .ok()?
        .unwrap_or_default();
    Some(SearchKeyReq {
        target,
        start_position: *start_position,
        restrictive_payload,
    })
}

fn source_request(entry: &SnoopEntry) -> Option<SearchSourceReq> {
    let SnoopEntry::Source {
        target,
        start_position,
        size,
        ..
    } = entry
    else {
        return None;
    };
    if *size == 0 {
        return None;
    }
    Some(SearchSourceReq {
        target: NodeId::from_str(target).ok()?,
        start_position: *start_position,
        size: *size,
    })
}

fn notes_request(entry: &SnoopEntry) -> Option<SearchNotesReq> {
    let SnoopEntry::Notes { target, size, .. } = entry else {
        return None;
    };
    if *size == 0 {
        return None;
    }
    Some(SearchNotesReq {
        target: NodeId::from_str(target).ok()?,
        size: *size,
    })
}

fn seconds(value: u64) -> TimeDelta {
    TimeDelta::seconds(i64::try_from(value).unwrap_or(i64::MAX))
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, ()> {
    let clean = value.trim();
    if !clean.len().is_multiple_of(2) {
        return Err(());
    }
    let mut output = Vec::with_capacity(clean.len() / 2);
    for index in (0..clean.len()).step_by(2) {
        output.push(u8::from_str_radix(&clean[index..index + 2], 16).map_err(|_| ())?);
    }
    Ok(output)
}

fn candidate_cmp(
    left: &ReplayCandidate<SearchKeyReq>,
    right: &ReplayCandidate<SearchKeyReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn source_candidate_cmp(
    left: &ReplayCandidate<SearchSourceReq>,
    right: &ReplayCandidate<SearchSourceReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| {
            source_candidate_is_high_quality(right).cmp(&source_candidate_is_high_quality(left))
        })
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn source_candidate_is_high_quality(candidate: &ReplayCandidate<SearchSourceReq>) -> bool {
    candidate.hit_count >= 2 || candidate.last_result_count > 0
}

fn select_best_source_candidate(
    recent: Vec<ReplayCandidate<SearchSourceReq>>,
    stale: Vec<ReplayCandidate<SearchSourceReq>>,
) -> Option<ReplayCandidate<SearchSourceReq>> {
    // Prefer repeated or previously successful source demand, but do not let the
    // source worker go idle while fresh one-off requests accumulate on the real network.
    let promoted = recent
        .iter()
        .chain(stale.iter())
        .any(source_candidate_is_high_quality);
    let mut recent = recent;
    let mut stale = stale;
    if promoted {
        recent.retain(source_candidate_is_high_quality);
        stale.retain(source_candidate_is_high_quality);
    }
    recent.sort_by(source_candidate_cmp);
    stale.sort_by(source_candidate_cmp);
    recent
        .into_iter()
        .next()
        .or_else(|| stale.into_iter().next())
}

fn notes_candidate_cmp(
    left: &ReplayCandidate<SearchNotesReq>,
    right: &ReplayCandidate<SearchNotesReq>,
) -> std::cmp::Ordering {
    right
        .observed_after_outcome
        .cmp(&left.observed_after_outcome)
        .then_with(|| left.zero_result_streak.cmp(&right.zero_result_streak))
        .then_with(|| right.last_result_count.cmp(&left.last_result_count))
        .then_with(|| right.hit_count.cmp(&left.hit_count))
        .then_with(|| right.last_seen.cmp(&left.last_seen))
        .then_with(|| left.scheduled.logical_key.cmp(&right.scheduled.logical_key))
}

fn replay_cooldown_cutoff(
    default_cutoff: DateTime<Utc>,
    now: DateTime<Utc>,
    drain_cooldown_secs: u64,
    entry: &SnoopEntry,
    feedback: ReplayFeedback,
) -> DateTime<Utc> {
    let Some(last_outcome_at) = feedback.last_outcome_at else {
        return default_cutoff;
    };
    if feedback.zero_result_streak == 0 || entry.last_seen() > last_outcome_at {
        return default_cutoff;
    }
    let zero_backoff_multiplier = u64::from(feedback.zero_result_streak.saturating_add(1)).min(4);
    let cooldown_secs = drain_cooldown_secs.saturating_mul(zero_backoff_multiplier);
    now - seconds(cooldown_secs)
}

fn should_skip_restored_entry(entry: &SnoopEntry) -> bool {
    match entry {
        SnoopEntry::Source { .. } => {
            entry
                .last_drained_at()
                .is_some_and(|last_drained_at| entry.last_seen() <= last_drained_at)
                || entry.hit_count() <= 1
        }
        _ => false,
    }
}

fn should_evict_zero_yield_source_entry(entry: &SnoopEntry) -> bool {
    matches!(entry, SnoopEntry::Source { .. })
        && entry
            .last_drained_at()
            .is_some_and(|last_drained_at| entry.last_seen() <= last_drained_at)
}

#[cfg(test)]
mod tests;
