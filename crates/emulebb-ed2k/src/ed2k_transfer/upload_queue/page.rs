//! Bounded live management pages in the scheduler's existing waiting order.
use std::collections::BinaryHeap;

use super::*;

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
}
impl std::fmt::Display for Ed2kUploadQueuePageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "upload queue page limit must be between 1 and 200",
            Self::CursorExpired => "upload queue cursor expired; refresh from the first page",
        })
    }
}
impl std::error::Error for Ed2kUploadQueuePageError {}

impl Ed2kUploadQueueState {
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
        let has_more = selected.len() > limit;
        let mut entries = Vec::with_capacity(selected.len().min(limit));
        for (offset, (_, position)) in selected.into_iter().take(limit).enumerate() {
            let key = &self.waiting_order[position];
            let session = &self.sessions[key];
            let rank = u16::try_from(preceding + offset + 1).unwrap_or(u16::MAX);
            entries.push(self.project_snapshot_entry(key, session, now, Some(rank), false));
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
