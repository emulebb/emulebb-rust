mod availability;
mod fields;
mod name_votes;
mod pages;
use crate::{
    MetadataContentObservationReceipt,
    search_model::{
        MetadataSearch, MetadataSearchData, MetadataSearchProjection, MetadataSearchResult,
        MetadataSearchResultObservation, MetadataSearchResultSummary, MetadataSearchSpec,
    },
    text::normalize_search_text,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};

impl super::MetadataStore {
    /// Allocate a never-reused session identity and commit its initial contents.
    /// Failed transactions publish neither the record nor its identity.
    pub fn create_search(&self, search: &MetadataSearchData) -> Result<i64> {
        self.write_search(None, search)
    }

    /// Update an existing session without resurrecting a deleted identity.
    pub fn update_search(&self, id: i64, search: &MetadataSearchData) -> Result<()> {
        ensure!(id > 0, "search id must be positive");
        self.write_search(Some(id), search)?;
        Ok(())
    }

    fn write_search(&self, id: Option<i64>, search: &MetadataSearchData) -> Result<i64> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        // WHY: allocation and updates share the body writer, but a missing
        // update ID must never recreate a deleted session. The statement's
        // existence predicate and mutation belong to one SQLite snapshot.
        let session_id: i64 = tx
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
            RETURNING id
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
                |row| row.get(0),
            )
            .optional()?
            .context("search no longer exists")?;
        tx.commit()?;
        Ok(session_id)
    }

    pub fn load_searches(&self) -> Result<Vec<MetadataSearch>> {
        let conn = self.connection()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, query, normalized_query, requested_method,
                   resolved_method, file_type_filter, extension_filter,
                   min_size_bytes, max_size_bytes, min_availability,
                   min_complete_sources, min_bitrate_kbps, min_length_seconds,
                   codec_filter, title_filter, album_filter, artist_filter,
                   status, status_reason, created_at_s, updated_at_s,
                   completed_at_s
            FROM search_sessions
            ORDER BY created_at_s, id
            "#,
        )?;
        let sessions = stmt
            .query_map([], |row| {
                Ok(MetadataSearch {
                    id: row.get(0)?,
                    data: MetadataSearchData {
                        normalized_query: row.get(2)?,
                        spec: MetadataSearchSpec {
                            query: row.get(1)?,
                            method: row.get(3)?,
                            file_type: row.get(5)?,
                            extension: row.get(6)?,
                            min_size_bytes: decode_optional_u64(row.get(7)?, 7)?,
                            max_size_bytes: decode_optional_u64(row.get(8)?, 8)?,
                            min_availability: decode_optional_u32(row.get(9)?, 9)?,
                            min_complete_sources: decode_optional_u32(row.get(10)?, 10)?,
                            min_bitrate_kbps: decode_optional_u32(row.get(11)?, 11)?,
                            min_length_seconds: decode_optional_u32(row.get(12)?, 12)?,
                            codec: row.get(13)?,
                            title: row.get(14)?,
                            album: row.get(15)?,
                            artist: row.get(16)?,
                        },
                        resolved_method: row.get(4)?,
                        status: row.get(17)?,
                        status_reason: row.get(18)?,
                        created_at_s: row.get(19)?,
                        updated_at_s: row.get(20)?,
                        completed_at_s: row.get(21)?,
                    },
                    results: Vec::new(),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut searches = Vec::with_capacity(sessions.len());
        for mut search in sessions {
            search.results = load_search_results(&conn, search.id)?;
            searches.push(search);
        }
        Ok(searches)
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

fn load_search_results(
    conn: &rusqlite::Connection,
    session_id: i64,
) -> Result<Vec<MetadataSearchResult>> {
    let mut stmt = conn.prepare(
        "SELECT r.claim_id,c.ed2k_hash,c.size_bytes,r.name,r.source_count,r.complete_source_count,
            r.source_client_id,r.source_client_port,r.file_type,r.media_artist,r.media_album,
            r.media_title,r.media_length_seconds,r.media_bitrate_kbps,r.media_codec,r.rating,
            r.aich_root,r.complete,r.directory
         FROM search_results r JOIN content_claims c ON c.id=r.claim_id
         WHERE r.session_id=?1 ORDER BY r.claim_id",
    )?;
    let mut rows = stmt.query([session_id])?;
    let mut results = Vec::new();
    while let Some(row) = rows.next()? {
        let root: Option<Vec<u8>> = row.get(16)?;
        results.push(MetadataSearchResult {
            claim_id: row.get(0)?,
            file_hash: hex::encode(row.get::<_, Vec<u8>>(1)?),
            size_bytes: decode_optional_u64(row.get(2)?, 2)?,
            summary: MetadataSearchResultSummary {
                name: row.get(3)?,
                source_count: row.get(4)?,
                complete_source_count: row.get(5)?,
                source_client_id: row.get(6)?,
                source_client_port: row.get(7)?,
                file_type: row.get(8)?,
                media_artist: row.get(9)?,
                media_album: row.get(10)?,
                media_title: row.get(11)?,
                media_length_seconds: row.get(12)?,
                media_bitrate_kbps: row.get(13)?,
                media_codec: row.get(14)?,
                rating: row.get(15)?,
                aich_hash: root
                    .map(|root| data_encoding::BASE32_NOPAD.encode(&root))
                    .unwrap_or_default(),
                complete: row.get(17)?,
                directory: row.get(18)?,
            },
            observations: load_search_observations(conn, session_id, row.get(0)?)?,
        });
    }
    Ok(results)
}

fn load_search_observations(
    conn: &rusqlite::Connection,
    session_id: i64,
    claim_id: i64,
) -> Result<Vec<MetadataSearchResultObservation>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {},m.first_seen_at_s,m.last_seen_at_s,m.observation_count
         FROM search_result_observations m
         JOIN content_claim_observations o ON o.id=m.observation_id AND o.claim_id=m.claim_id
         JOIN content_claims c ON c.id=o.claim_id
         WHERE m.session_id=?1 AND m.claim_id=?2 ORDER BY o.id",
        crate::content_observation_store::COLUMNS
    ))?;
    let mut rows = stmt.query(params![session_id, claim_id])?;
    let mut values = Vec::new();
    while let Some(row) = rows.next()? {
        values.push(MetadataSearchResultObservation {
            observation: crate::content_observation_store::observation_from_row(row)?,
            first_seen_at_s: row.get(25)?,
            last_seen_at_s: row.get(26)?,
            observation_count: row.get(27)?,
        });
    }
    Ok(values)
}

/// Record only collecting-session membership; corpus writes remain independent.
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
    tx.execute("INSERT INTO search_results(session_id,claim_id,name,source_client_id,source_client_port,
        file_type,media_artist,media_album,media_title,media_length_seconds,media_bitrate_kbps,media_codec,
        rating,aich_root,complete,directory) VALUES(?1,?2,'',NULL,NULL,'Unknown','','','',0,0,'',0,NULL,0,'')
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
