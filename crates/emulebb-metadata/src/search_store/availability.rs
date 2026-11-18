//! Incremental session availability, independent of raw observation history.
use crate::{MetadataContentObservationEvent, MetadataObservationOrigin};
use anyhow::Result;
use rusqlite::{OptionalExtension, Transaction, params};

const REPORTER_SQL: &str =
    "SELECT source_count,complete_source_count FROM search_ed2k_reporter_maxima
             WHERE session_id=?1 AND claim_id=?2 AND reporter_endpoint=?3 AND unknown_origin=?4";

pub(super) fn apply(
    tx: &Transaction<'_>,
    session: i64,
    claim: i64,
    events: &[MetadataContentObservationEvent],
) -> Result<(u32, u32)> {
    let (mut ed2k, mut ed2k_complete, mut kad, mut kad_complete): (u32,u32,u32,u32) = tx.query_row(
        "SELECT ed2k_source_count,ed2k_complete_source_count,kad_source_count,kad_complete_source_count
         FROM search_results WHERE session_id=?1 AND claim_id=?2",
        params![session,claim], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    for event in events {
        let sources = event.metadata.source_count.unwrap_or(0);
        let complete = event.metadata.complete_source_count.unwrap_or(0);
        if event.origin == MetadataObservationOrigin::Kad {
            kad = kad.max(sources);
            kad_complete = kad_complete.max(complete);
            continue;
        }
        if event.metadata.source_count.is_none() && event.metadata.complete_source_count.is_none() {
            continue;
        }
        let endpoint = event
            .reporter_endpoint
            .map(|value| value.to_string())
            .unwrap_or_default();
        let origin = if endpoint.is_empty() {
            event.origin.as_str()
        } else {
            ""
        };
        let previous: Option<(u32, u32)> = tx
            .query_row(
                REPORTER_SQL,
                params![session, claim, endpoint, origin],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (old_sources, old_complete) = previous.unwrap_or_default();
        let new_sources = old_sources.max(sources);
        let new_complete = old_complete.max(complete);
        // WHY: the writer transaction keeps reporter maxima and independent
        // eD2K subtotals atomic; a leading Kad estimate must not erase progress.
        ed2k = ed2k.saturating_add(new_sources - old_sources);
        ed2k_complete = ed2k_complete.saturating_add(new_complete - old_complete);
        if previous.is_none() || (old_sources, old_complete) != (new_sources, new_complete) {
            tx.execute(
                "INSERT INTO search_ed2k_reporter_maxima(session_id,claim_id,reporter_endpoint,
                    unknown_origin,source_count,complete_source_count) VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(session_id,claim_id,reporter_endpoint,unknown_origin) DO UPDATE SET
                    source_count=excluded.source_count,complete_source_count=excluded.complete_source_count",
                params![session,claim,endpoint,origin,new_sources,new_complete])?;
        }
    }
    tx.execute(
        "UPDATE search_results SET ed2k_source_count=?3,ed2k_complete_source_count=?4,
            kad_source_count=?5,kad_complete_source_count=?6 WHERE session_id=?1 AND claim_id=?2",
        params![session, claim, ed2k, ed2k_complete, kad, kad_complete],
    )?;
    Ok((ed2k.max(kad), ed2k_complete.max(kad_complete)))
}

#[cfg(test)]
mod tests;
