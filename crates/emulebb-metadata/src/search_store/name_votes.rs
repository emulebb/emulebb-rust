//! Incremental reporter/name voting, committed with raw facts and membership.
use super::*;
use crate::MetadataSearchNameVote;

pub(super) const WINNER_SQL: &str = "SELECT normalized_name FROM search_name_totals
    WHERE session_id=?1 AND claim_id=?2 ORDER BY vote_count DESC,quality_useful DESC,
    quality_sources DESC,quality_complete_sources DESC,quality_rating DESC,normalized_name COLLATE BINARY LIMIT 1";

pub(super) fn apply(
    tx: &rusqlite::Transaction<'_>,
    session: i64,
    claim: i64,
    votes: &[MetadataSearchNameVote],
) -> Result<String> {
    for vote in votes {
        let reporter = vote
            .reporter_endpoint
            .map(|v| v.to_string())
            .unwrap_or_default();
        let unknown = if vote.reporter_endpoint.is_none() {
            vote.origin.as_str()
        } else {
            ""
        };
        let q = vote.quality;
        let useful = i64::from(q.useful);
        let added = tx.execute("INSERT INTO search_name_reporters(session_id,claim_id,normalized_name,reporter_endpoint,unknown_origin,
            quality_useful,quality_sources,quality_complete_sources,quality_rating)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT DO NOTHING",
            params![session,claim,vote.normalized_name,reporter,unknown,useful,q.sources,q.complete_sources,q.rating])? != 0;
        if added {
            tx.execute("INSERT INTO search_name_totals(session_id,claim_id,normalized_name,vote_count,
                quality_useful,quality_sources,quality_complete_sources,quality_rating)
                VALUES(?1,?2,?3,1,?4,?5,?6,?7) ON CONFLICT(session_id,claim_id,normalized_name) DO UPDATE SET
                vote_count=CASE WHEN vote_count<9223372036854775807 THEN vote_count+1 ELSE vote_count END",
                params![session,claim,vote.normalized_name,useful,q.sources,q.complete_sources,q.rating])?;
        } else {
            tx.execute("UPDATE search_name_reporters SET quality_useful=?6,quality_sources=?7,quality_complete_sources=?8,quality_rating=?9
                WHERE session_id=?1 AND claim_id=?2 AND normalized_name=?3 AND reporter_endpoint=?4 AND unknown_origin=?5
                AND (quality_useful,quality_sources,quality_complete_sources,quality_rating)<(?6,?7,?8,?9)",
                params![session,claim,vote.normalized_name,reporter,unknown,useful,q.sources,q.complete_sources,q.rating])?;
        }
        // Update the whole winning tuple, never independent component maxima.
        tx.execute("UPDATE search_name_totals SET quality_useful=?4,quality_sources=?5,quality_complete_sources=?6,quality_rating=?7
            WHERE session_id=?1 AND claim_id=?2 AND normalized_name=?3
            AND (quality_useful,quality_sources,quality_complete_sources,quality_rating)<(?4,?5,?6,?7)",
            params![session,claim,vote.normalized_name,useful,q.sources,q.complete_sources,q.rating])?;
    }
    Ok(tx.query_row(WINNER_SQL, params![session, claim], |row| row.get(0))?)
}

#[cfg(test)]
mod tests;
