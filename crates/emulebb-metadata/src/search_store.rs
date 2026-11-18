mod availability;
mod fields;
mod name_votes;
mod pages;
use crate::{
    MetadataContentObservationReceipt,
    search_model::{
        MetadataSearchData, MetadataSearchProjection, MetadataSearchResultObservation,
        MetadataSearchResultSummary, MetadataSearchSpec,
    },
    text::normalize_search_text,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};

pub(super) const INTERRUPT_COLLECTING_SQL: &str =
    "UPDATE search_sessions SET status='error',status_reason='interrupted-by-restart',
                updated_at_s=max(updated_at_s,?1),completed_at_s=NULL
             WHERE status IN ('queued','running')";

pub(super) const SESSION_HASH_MEMBERSHIP_SQL: &str = "SELECT EXISTS(SELECT 1 FROM search_results INDEXED BY search_results_hash_idx WHERE session_id=?1 AND ed2k_hash=?2)";

impl super::MetadataStore {
    /// Allocate a never-reused session identity and commit its initial contents.
    /// Failed transactions publish neither the record nor its identity.
    pub fn create_search(&self, search: &MetadataSearchData) -> Result<i64> {
        Ok(self.write_search(None, search, &[])?.0)
    }

    /// Commit a header transition and resolve only the supplied vote hashes.
    /// Membership and cardinality use the same transaction as the status write.
    pub fn transition_search(
        &self,
        id: i64,
        search: &MetadataSearchData,
        incoming_hashes: &[String],
    ) -> Result<crate::MetadataSearchTransitionReceipt> {
        ensure!(id > 0, "search id must be positive");
        Ok(self.write_search(Some(id), search, incoming_hashes)?.1)
    }

    fn write_search(
        &self,
        id: Option<i64>,
        search: &MetadataSearchData,
        incoming_hashes: &[String],
    ) -> Result<(i64, crate::MetadataSearchTransitionReceipt)> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // WHY: allocation and updates share the body writer, but a missing
        // update ID must never recreate a deleted session. The statement's
        // existence predicate and mutation belong to one SQLite snapshot.
        let (session_id, result_count): (i64, i64) = tx
            .query_row(
                r#"
            INSERT INTO search_sessions(
                id, query, normalized_query, requested_method, resolved_method,
                file_type_filter, extension_filter, min_size_bytes, max_size_bytes,
                min_availability, min_complete_sources, min_bitrate_kbps,
                min_length_seconds, codec_filter, title_filter, album_filter,
                artist_filter, status, status_reason, created_at_s, updated_at_s,
                completed_at_s
            )
            SELECT
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22
            WHERE ?1 IS NULL OR EXISTS (SELECT 1 FROM search_sessions WHERE id = ?1)
            ON CONFLICT(id) DO UPDATE SET
                query = excluded.query,
                normalized_query = excluded.normalized_query,
                requested_method = excluded.requested_method,
                resolved_method = excluded.resolved_method,
                file_type_filter = excluded.file_type_filter,
                extension_filter = excluded.extension_filter,
                min_size_bytes = excluded.min_size_bytes,
                max_size_bytes = excluded.max_size_bytes,
                min_availability = excluded.min_availability,
                min_complete_sources = excluded.min_complete_sources,
                min_bitrate_kbps = excluded.min_bitrate_kbps,
                min_length_seconds = excluded.min_length_seconds,
                codec_filter = excluded.codec_filter,
                title_filter = excluded.title_filter,
                album_filter = excluded.album_filter,
                artist_filter = excluded.artist_filter,
                status = excluded.status,
                status_reason = excluded.status_reason,
                updated_at_s = excluded.updated_at_s,
                completed_at_s = excluded.completed_at_s
            RETURNING id,result_count
            "#,
                params![
                    id,
                    search.spec.query,
                    search.normalized_query,
                    search.spec.method,
                    search.resolved_method,
                    search.spec.file_type,
                    search.spec.extension,
                    encode_optional_u64(search.spec.min_size_bytes),
                    encode_optional_u64(search.spec.max_size_bytes),
                    search.spec.min_availability.map(i64::from),
                    search.spec.min_complete_sources.map(i64::from),
                    search.spec.min_bitrate_kbps.map(i64::from),
                    search.spec.min_length_seconds.map(i64::from),
                    search.spec.codec,
                    search.spec.title,
                    search.spec.album,
                    search.spec.artist,
                    search.status,
                    search.status_reason,
                    search.created_at_s,
                    search.updated_at_s,
                    search.completed_at_s,
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .context("search no longer exists")?;
        let mut accepted_hashes = Vec::new();
        {
            let mut statement = tx.prepare_cached(SESSION_HASH_MEMBERSHIP_SQL)?;
            for hash in incoming_hashes {
                ensure!(hash.len() == 32, "invalid vote hash length");
                let bytes = data_encoding::HEXLOWER_PERMISSIVE.decode(hash.as_bytes())?;
                let accepted: bool =
                    statement.query_row(params![session_id, bytes], |row| row.get(0))?;
                if accepted {
                    accepted_hashes.push(hash.clone());
                }
            }
        }
        let result_count = result_count.try_into()?;
        tx.commit()?;
        Ok((
            session_id,
            crate::MetadataSearchTransitionReceipt {
                result_count,
                accepted_hashes,
            },
        ))
    }

    /// End collecting sessions once at process startup, without loading history.
    /// Terminal sessions and retained evidence are unchanged.
    pub fn interrupt_collecting_searches(&self, now_s: i64) -> Result<usize> {
        ensure!(now_s >= 0, "negative search interruption timestamp");
        Ok(self
            .connection()?
            .execute(INTERRUPT_COLLECTING_SQL, [now_s])?)
    }

    /// Freeze collection while preserving retained results. Terminal sessions
    /// are idempotent successes; an absent identity returns false.
    pub fn stop_search(&self, id: i64, now_s: i64) -> Result<bool> {
        ensure!(
            id > 0 && now_s >= 0,
            "invalid search stop identity or timestamp"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM search_sessions WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(status) = status else {
            return Ok(false);
        };
        if matches!(status.as_str(), "queued" | "running") {
            tx.execute("UPDATE search_sessions SET status='stopped',status_reason=NULL,updated_at_s=max(updated_at_s,?2),completed_at_s=NULL WHERE id=?1",params![id,now_s])?;
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn delete_search(&self, id: i64) -> Result<bool> {
        ensure!(id > 0, "search id must be positive");
        let deleted = self
            .connection()?
            .execute("DELETE FROM search_sessions WHERE id = ?1", params![id])?;
        Ok(deleted != 0)
    }

    pub fn clear_searches(&self) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM search_sessions", [])?;
        Ok(())
    }
}

pub(crate) fn persist_projection(
    tx: &rusqlite::Transaction<'_>,
    projection: &MetadataSearchProjection,
    receipts: &[MetadataContentObservationReceipt],
    events: &[crate::MetadataContentObservationEvent],
) -> Result<Option<crate::MetadataSearchPublication>> {
    let collecting: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM search_sessions WHERE id=?1 AND status IN ('queued','running'))",
        [projection.session_id], |row| row.get(0))?;
    if !collecting {
        return Ok(None);
    }
    let claim_id = receipts
        .first()
        .context("search projection requires an observation")?
        .claim_id;
    ensure!(
        receipts.iter().all(|r| r.claim_id == claim_id),
        "search projection contains distinct claims"
    );
    tx.execute("INSERT INTO search_results(session_id,claim_id,size_sort_key,ed2k_hash,name,source_client_id,source_client_port,
        file_type,media_artist,media_album,media_title,media_length_seconds,media_bitrate_kbps,media_codec,
        rating,aich_root,complete,directory) SELECT ?1,id,size_sort_key,ed2k_hash,'',NULL,NULL,'Unknown','','','',0,0,'',0,NULL,0,'' FROM content_claims WHERE id=?2
        ON CONFLICT(session_id,claim_id) DO NOTHING",params![projection.session_id,claim_id])?;
    fields::apply(tx, projection.session_id, claim_id, &projection.fields)?;
    for (receipt, event) in receipts.iter().zip(events) {
        tx.execute(
            "INSERT INTO search_result_observations(session_id,claim_id,observation_id,
                first_seen_at_s,last_seen_at_s,observation_count) VALUES(?1,?2,?3,?4,?4,1)
             ON CONFLICT(session_id,claim_id,observation_id) DO UPDATE SET
                first_seen_at_s=min(first_seen_at_s,excluded.first_seen_at_s),
                last_seen_at_s=max(last_seen_at_s,excluded.last_seen_at_s),
                observation_count=CASE WHEN observation_count<9223372036854775807
                    THEN observation_count+1 ELSE observation_count END",
            params![
                projection.session_id,
                claim_id,
                receipt.observation_id,
                event.observed_at_s
            ],
        )?;
    }
    let name = name_votes::apply(tx, projection.session_id, claim_id, &projection.name_votes)?;
    tx.execute(
        "UPDATE search_results SET name=?3 WHERE session_id=?1 AND claim_id=?2",
        params![projection.session_id, claim_id, name],
    )?;
    availability::apply(tx, projection.session_id, claim_id, events)?;
    if let Some(last) = events.iter().map(|event| event.observed_at_s).max() {
        tx.execute(
            "UPDATE search_sessions SET updated_at_s=max(updated_at_s,?2) WHERE id=?1",
            params![projection.session_id, last],
        )?;
    }
    Ok(Some(crate::MetadataSearchPublication {
        claim_id,
        summary: pages::committed_summary(tx, projection.session_id, claim_id)?,
    }))
}

pub(crate) fn encode_aich_root(value: &str) -> Result<Option<Vec<u8>>> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = data_encoding::BASE32_NOPAD.decode(value.as_bytes())?;
    anyhow::ensure!(bytes.len() == 20, "AICH root must contain 20 bytes");
    Ok(Some(bytes))
}

fn encode_optional_u64(value: Option<u64>) -> Option<Vec<u8>> {
    value.map(|value| value.to_be_bytes().to_vec())
}

pub(crate) fn decode_optional_u64(
    value: Option<Vec<u8>>,
    column: usize,
) -> rusqlite::Result<Option<u64>> {
    value
        .map(|value| {
            let bytes: [u8; 8] = value.try_into().map_err(|value: Vec<u8>| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Blob,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "expected 8-byte unsigned integer, got {} bytes",
                            value.len()
                        ),
                    )
                    .into(),
                )
            })?;
            Ok(u64::from_be_bytes(bytes))
        })
        .transpose()
}

fn decode_optional_u32(value: Option<i64>, column: usize) -> rusqlite::Result<Option<u32>> {
    value
        .map(|value| {
            u32::try_from(value).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    column,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })
        })
        .transpose()
}

pub fn normalized_search_query(query: &str) -> String {
    normalize_search_text(query)
}

#[cfg(test)]
mod tests;
