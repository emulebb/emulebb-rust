//! Bounded live management pages in the scheduler's existing waiting order.
use std::collections::BinaryHeap;

use super::*;

struct ActiveCandidate<'a> {
    key: &'a Ed2kUploadSessionKey,
    session: &'a Ed2kUploadSessionEntry,
}
impl PartialEq for ActiveCandidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.session.public_id == other.session.public_id
    }
}
impl Eq for ActiveCandidate<'_> {}
impl PartialOrd for ActiveCandidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ActiveCandidate<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.session.public_id.cmp(&other.session.public_id)
    }
}

/// A live page, independent of previous requests. Requester bitmaps are detail
/// evidence and are not copied into its entries. Ranks are current at selection.
#[derive(Debug)]
pub struct Ed2kUploadQueuePage {
    pub entries: Vec<Ed2kUploadQueueSnapshotEntry>,
    pub next_after: Option<uuid::Uuid>,
    pub has_more: bool,
    pub total: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kUploadQueuePageError {
    InvalidLimit,
    CursorExpired,
    RowTooLarge,
}
impl std::fmt::Display for Ed2kUploadQueuePageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "upload queue page limit must be between 1 and 200",
            Self::CursorExpired => "upload queue cursor expired; refresh from the first page",
            Self::RowTooLarge => "upload queue row exceeds read allowance",
        })
    }
}
impl std::error::Error for Ed2kUploadQueuePageError {}

impl Ed2kUploadQueueState {
    /// Live active sessions in immutable management-ID order. Keep only a
    /// borrowed page-sized heap; do not run maintenance or clone part bitmaps.
    pub(in crate::ed2k_transfer) fn active_page(
        &self,
        after: Option<uuid::Uuid>,
        limit: usize,
        count_total: bool,
        now: Instant,
    ) -> Result<Ed2kUploadQueuePage, Ed2kUploadQueuePageError> {
        if !(1..=200).contains(&limit) {
            return Err(Ed2kUploadQueuePageError::InvalidLimit);
        }
        let mut found = after.is_none();
        let mut total = 0usize;
        let mut best = BinaryHeap::with_capacity(limit + 1);
        for (key, session) in &self.sessions {
            if session.phase == Ed2kUploadSessionPhase::Waiting {
                continue;
            }
            total += 1;
            found |= after == Some(session.public_id);
            if after.is_some_and(|after| session.public_id <= after) {
                continue;
            }
            let candidate = ActiveCandidate { key, session };
            if best.len() < limit + 1 {
                best.push(candidate);
            } else if best.peek().is_some_and(|worst| candidate < *worst) {
                *best.peek_mut().expect("full active candidate heap") = candidate;
            }
        }
        if !found {
            return Err(Ed2kUploadQueuePageError::CursorExpired);
        }
        let selected = best.into_sorted_vec();
        let mut has_more = selected.len() > limit;
        let mut entries = Vec::with_capacity(selected.len().min(limit));
        let mut bytes = entries.capacity() * std::mem::size_of::<Ed2kUploadQueueSnapshotEntry>();
        for candidate in selected.into_iter().take(limit) {
            let text = candidate.key.file_hash.len()
                + candidate
                    .key
                    .peer
                    .client_software
                    .as_ref()
                    .map_or(0, String::len);
            if bytes.saturating_add(text) > 512 * 1024 {
                if entries.is_empty() {
                    return Err(Ed2kUploadQueuePageError::RowTooLarge);
                }
                has_more = true;
                break;
            }
            bytes += text;
            entries.push(self.project_snapshot_entry(
                candidate.key,
                candidate.session,
                now,
                None,
                false,
            ));
        }
        let next_after = has_more.then(|| {
            entries
                .last()
                .expect("nonempty active page with continuation")
                .id
        });
        Ok(Ed2kUploadQueuePage {
            entries,
            next_after,
            has_more,
            total: count_total.then_some(total),
        })
    }

    /// Count only currently visible waiters, preserving the scheduler's stable
    /// ties without sorting or cloning the complete waiting queue for a detail.
    pub(super) fn visible_waiting_rank(
        &self,
        key: &Ed2kUploadSessionKey,
        session: &Ed2kUploadSessionEntry,
        now: Instant,
    ) -> Option<usize> {
        let target = self.waiting_sort_key(key, session, now);
        let mut ahead = 0usize;
        let mut found = false;
        for queued in &self.waiting_order {
            if queued == key {
                found = true;
                continue;
            }
            let Some(other) = self.sessions.get(queued).filter(|entry| {
                entry.phase == Ed2kUploadSessionPhase::Waiting
                    && now.saturating_duration_since(entry.last_activity)
                        <= self.config.waiting_timeout
            }) else {
                continue;
            };
            let order = self.waiting_sort_key(queued, other, now).cmp(&target);
            if order.is_lt() || (order.is_eq() && !found) {
                ahead += 1;
            }
        }
        found.then_some(ahead + 1)
    }
    pub(in crate::ed2k_transfer) fn waiting_page(
        &self,
        after: Option<uuid::Uuid>,
        limit: usize,
        count_total: bool,
        now: Instant,
    ) -> Result<Ed2kUploadQueuePage, Ed2kUploadQueuePageError> {
        if !(1..=200).contains(&limit) {
            return Err(Ed2kUploadQueuePageError::InvalidLimit);
        }
        // Read projection must not invoke maintenance that collects expired
        // queue keys. Apply the same waiting timeout without mutating sessions;
        // existing protocol maintenance owns physical retirement and promotion.
        let visible = |session: &Ed2kUploadSessionEntry| {
            session.phase == Ed2kUploadSessionPhase::Waiting
                && now.saturating_duration_since(session.last_activity)
                    <= self.config.waiting_timeout
        };
        let anchor = after
            .map(|id| {
                self.waiting_order
                    .iter()
                    .enumerate()
                    .find_map(|(position, key)| {
                        self.sessions
                            .get(key)
                            .filter(|session| visible(session) && session.public_id == id)
                            .map(|session| (self.waiting_sort_key(key, session, now), position))
                    })
                    .ok_or(Ed2kUploadQueuePageError::CursorExpired)
            })
            .transpose()?;

        // WHY: ranking is runtime state. Keep only the best page and lookahead,
        // not a cloned/sorted queue or a retained per-caller collection snapshot.
        // The waiting-order position preserves stable ties at sequence saturation.
        let capacity = limit + 1;
        let mut best = BinaryHeap::with_capacity(capacity);
        let mut total = 0usize;
        let mut preceding = 0usize;
        for (position, key) in self.waiting_order.iter().enumerate() {
            let Some(session) = self.sessions.get(key).filter(|session| visible(session)) else {
                continue;
            };
            total += 1;
            let order = (self.waiting_sort_key(key, session, now), position);
            if anchor.is_some_and(|anchor| order <= anchor) {
                preceding += 1;
                continue;
            }
            if best.len() < capacity {
                best.push(order);
            } else if best.peek().is_some_and(|worst| order < *worst) {
                *best
                    .peek_mut()
                    .expect("full candidate heap has a worst row") = order;
            }
        }
        let selected = best.into_sorted_vec();
        let mut has_more = selected.len() > limit;
        let mut entries = Vec::with_capacity(selected.len().min(limit));
        let mut retained_bytes =
            entries.capacity() * std::mem::size_of::<Ed2kUploadQueueSnapshotEntry>();
        for (offset, (_, position)) in selected.into_iter().take(limit).enumerate() {
            let key = &self.waiting_order[position];
            let session = &self.sessions[key];
            let row_bytes =
                key.file_hash.len() + key.peer.client_software.as_ref().map_or(0, String::len);
            if retained_bytes.saturating_add(row_bytes) > 512 * 1024 {
                if entries.is_empty() {
                    return Err(Ed2kUploadQueuePageError::RowTooLarge);
                }
                has_more = true;
                break;
            }
            retained_bytes += row_bytes;
            let rank = u16::try_from(preceding + offset + 1).unwrap_or(u16::MAX);
            let mut entry = self.project_snapshot_entry(key, session, now, Some(rank), false);
            entry.management_rank = Some(preceding + offset + 1);
            entries.push(entry);
        }
        let next_after =
            has_more.then(|| entries.last().expect("lookahead requires a full page").id);
        Ok(Ed2kUploadQueuePage {
            entries,
            next_after,
            has_more,
            total: count_total.then_some(total),
        })
    }
}

#[cfg(test)]
mod tests;
