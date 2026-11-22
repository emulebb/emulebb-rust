//! Indexed search browsing with independent row and owned-byte bounds.
mod sorted;
use super::*;
use crate::{MetadataSearchHeader, MetadataSearchPage, MetadataSearchResultHeader};
use rusqlite::Row;

const PAGE_ITEMS: usize = 200;
const SMALL_BOUNDS: (usize, usize) = (128 * 1024, 256 * 1024);
// A summary can combine seven long fields from independently bounded packets.
const SUMMARY_BOUNDS: (usize, usize) = (512 * 1024, 1024 * 1024);
const HEADER_COLUMNS: &str = "s.id,s.query,s.normalized_query,s.requested_method,s.resolved_method,
    s.file_type_filter,s.extension_filter,s.min_size_bytes,s.max_size_bytes,s.min_availability,
    s.min_complete_sources,s.min_bitrate_kbps,s.min_length_seconds,s.codec_filter,s.title_filter,
    s.album_filter,s.artist_filter,s.status,s.status_reason,s.created_at_s,s.updated_at_s,s.completed_at_s,s.result_count,s.parent_search_id";
const RESULT_COLUMNS: &str = "r.claim_id,c.ed2k_hash,c.size_bytes,r.name,r.source_count,r.complete_source_count,
    r.source_client_id,r.source_client_port,r.file_type,r.media_artist,r.media_album,r.media_title,
    r.media_length_seconds,r.media_bitrate_kbps,r.media_codec,r.rating,r.aich_root,r.complete,r.directory";

fn header_sql(page: bool) -> String {
    format!(
        "SELECT {HEADER_COLUMNS} FROM search_sessions s WHERE {}",
        if page {
            "s.id<=?1 ORDER BY s.id DESC LIMIT ?2"
        } else {
            "s.id=?1"
        }
    )
}
fn result_sql(page: bool) -> String {
    format!(
        "SELECT {RESULT_COLUMNS} FROM search_results r JOIN content_claims c ON c.id=r.claim_id
        WHERE r.session_id=?1 AND {}",
        if page {
            "r.claim_id>?2 ORDER BY r.claim_id LIMIT ?3"
        } else {
            "r.claim_id=?2"
        }
    )
}
fn observation_sql() -> String {
    format!(
        "SELECT {},m.first_seen_at_s,m.last_seen_at_s,m.observation_count
        FROM search_result_observations m
        JOIN content_claim_observations o ON o.id=m.observation_id AND o.claim_id=m.claim_id
        JOIN content_claims c ON c.id=o.claim_id
        WHERE m.session_id=?1 AND m.claim_id=?2 AND m.observation_id>?3
        ORDER BY m.observation_id LIMIT ?4",
        crate::content_observation_store::COLUMNS
    )
}
fn limit_value(limit: usize) -> Result<i64> {
    ensure!(
        (1..=PAGE_ITEMS).contains(&limit),
        "invalid search page limit"
    );
    Ok(i64::try_from(limit)? + 1)
}
fn row_bytes(row: &Row<'_>, text_columns: &[usize], maximum: usize) -> Result<usize> {
    let mut bytes = 2048usize;
    for column in text_columns {
        let value = row.get_ref(*column)?;
        if !matches!(value, rusqlite::types::ValueRef::Null) {
            bytes = bytes
                .checked_add(
                    value
                        .as_str()?
                        .len()
                        .checked_mul(6)
                        .context("search row size overflow")?,
                )
                .context("search row size overflow")?;
        }
    }
    ensure!(bytes <= maximum, "stored search row exceeds its byte bound");
    Ok(bytes)
}
fn collect_page<T>(
    rows: &mut rusqlite::Rows<'_>,
    limit: usize,
    text_columns: &[usize],
    bounds: (usize, usize),
    decode: impl Fn(&Row<'_>) -> Result<T>,
) -> Result<MetadataSearchPage<T>> {
    let mut items = Vec::with_capacity(limit);
    let mut bytes = 0usize;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        if items.len() == limit {
            has_more = true;
            break;
        }
        let charge = row_bytes(row, text_columns, bounds.0)?;
        if bytes + charge > bounds.1 {
            has_more = true;
            break;
        }
        bytes += charge;
        items.push(decode(row)?);
    }
    Ok(MetadataSearchPage { items, has_more })
}

impl super::super::MetadataStore {
    /// Select exactly one membership and a row/byte bounded initial-evidence page.
    pub fn search_download_seed(
        &self,
        session_id: i64,
        claim_id: i64,
    ) -> Result<Option<crate::MetadataSearchDownloadSeed>> {
        ensure!(
            session_id > 0 && claim_id > 0,
            "invalid search result identity"
        );
        let selected = {
            let conn = self.connection()?;
            let mut statement = conn.prepare("SELECT r.claim_id,c.ed2k_hash,c.size_bytes,r.name,r.source_client_id,r.source_client_port
                FROM search_results r JOIN content_claims c ON c.id=r.claim_id WHERE r.session_id=?1 AND r.claim_id=?2")?;
            let mut rows = statement.query(params![session_id, claim_id])?;
            rows.next()?
                .map(|row| -> Result<_> {
                    row_bytes(row, &[3], SMALL_BOUNDS.0)?;
                    Ok(crate::MetadataSearchDownloadSeed {
                        claim_id: row.get(0)?,
                        file_hash: hex::encode(row.get::<_, Vec<u8>>(1)?),
                        size_bytes: decode_optional_u64(row.get(2)?, 2)?,
                        name: row.get(3)?,
                        source_client_id: row.get(4)?,
                        source_client_port: row.get(5)?,
                        observations: Vec::new(),
                    })
                })
                .transpose()?
        };
        let Some(mut selected) = selected else {
            return Ok(None);
        };
        let Some(observations) =
            self.search_result_observations_page(session_id, claim_id, 0, 100)?
        else {
            return Ok(None);
        };
        selected.observations = observations.items;
        Ok(Some(selected))
    }

    /// Newest numeric session identity first. The next boundary is the last ID.
    pub fn search_headers_page(
        &self,
        before: Option<i64>,
        limit: usize,
    ) -> Result<MetadataSearchPage<MetadataSearchHeader>> {
        let count = limit_value(limit)?;
        ensure!(
            before.is_none_or(|id| id > 0),
            "invalid search cursor identity"
        );
        let boundary = before.map_or(i64::MAX, |id| id - 1);
        let conn = self.connection()?;
        let mut statement = conn.prepare(&header_sql(true))?;
        let mut rows = statement.query(params![boundary, count])?;
        collect_page(
            &mut rows,
            limit,
            &[1, 2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18],
            SMALL_BOUNDS,
            header_from_row,
        )
    }
    pub fn search_header(&self, id: i64) -> Result<Option<MetadataSearchHeader>> {
        ensure!(id > 0, "invalid search identity");
        let conn = self.connection()?;
        let mut statement = conn.prepare(&header_sql(false))?;
        let mut rows = statement.query([id])?;
        rows.next()?
            .map(|row| {
                row_bytes(
                    row,
                    &[1, 2, 3, 4, 5, 6, 13, 14, 15, 16, 17, 18],
                    SMALL_BOUNDS.0,
                )?;
                header_from_row(row)
            })
            .transpose()
    }
    pub fn search_result_headers_page(
        &self,
        session_id: i64,
        after: i64,
        limit: usize,
    ) -> Result<Option<MetadataSearchPage<MetadataSearchResultHeader>>> {
        let count = limit_value(limit)?;
        ensure!(
            session_id > 0 && after >= 0,
            "invalid search result page identity"
        );
        let conn = self.connection()?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM search_sessions WHERE id=?1)",
            [session_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let mut statement = conn.prepare(&result_sql(true))?;
        let mut rows = statement.query(params![session_id, after, count])?;
        Ok(Some(collect_page(
            &mut rows,
            limit,
            &[3, 8, 9, 10, 11, 14, 18],
            SUMMARY_BOUNDS,
            result_from_row,
        )?))
    }
    pub fn search_result_header(
        &self,
        session_id: i64,
        claim_id: i64,
    ) -> Result<Option<MetadataSearchResultHeader>> {
        ensure!(
            session_id > 0 && claim_id > 0,
            "invalid search result identity"
        );
        let conn = self.connection()?;
        let mut statement = conn.prepare(&result_sql(false))?;
        let mut rows = statement.query(params![session_id, claim_id])?;
        rows.next()?
            .map(|row| {
                row_bytes(row, &[3, 8, 9, 10, 11, 14, 18], SUMMARY_BOUNDS.0)?;
                result_from_row(row)
            })
            .transpose()
    }
    pub fn search_result_observations_page(
        &self,
        session_id: i64,
        claim_id: i64,
        after: i64,
        limit: usize,
    ) -> Result<Option<MetadataSearchPage<MetadataSearchResultObservation>>> {
        let count = limit_value(limit)?;
        ensure!(
            session_id > 0 && claim_id > 0 && after >= 0,
            "invalid search observation page identity"
        );
        let conn = self.connection()?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM search_results WHERE session_id=?1 AND claim_id=?2)",
            params![session_id, claim_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let mut statement = conn.prepare(&observation_sql())?;
        let mut rows = statement.query(params![session_id, claim_id, after, count])?;
        Ok(Some(collect_page(
            &mut rows,
            limit,
            &[9, 14, 15, 16, 17, 20, 24, 25],
            SMALL_BOUNDS,
            |row| {
                Ok(MetadataSearchResultObservation {
                    observation: crate::content_observation_store::observation_from_row(row)?,
                    first_seen_at_s: row.get(27)?,
                    last_seen_at_s: row.get(28)?,
                    observation_count: row.get(29)?,
                })
            },
        )?))
    }
}

fn header_from_row(row: &Row<'_>) -> Result<MetadataSearchHeader> {
    Ok(MetadataSearchHeader {
        id: row.get(0)?,
        result_count: u64::try_from(row.get::<_, i64>(22)?)
            .context("invalid search result count")?,
        data: MetadataSearchData {
            parent_search_id: row.get(23)?,
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
    })
}
fn result_from_row(row: &Row<'_>) -> Result<MetadataSearchResultHeader> {
    let root: Option<Vec<u8>> = row.get(16)?;
    Ok(MetadataSearchResultHeader {
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
    })
}

#[cfg(test)]
mod tests;

/// Read the bounded receipt in the committing transaction, without another connection.
pub(super) fn committed_summary(
    tx: &rusqlite::Transaction<'_>,
    session: i64,
    claim: i64,
) -> Result<crate::MetadataSearchResultSummary> {
    let mut statement = tx.prepare(&result_sql(false))?;
    let mut rows = statement.query(params![session, claim])?;
    let row = rows.next()?.context("missing committed search result")?;
    row_bytes(row, &[3, 8, 9, 10, 11, 14, 18], SUMMARY_BOUNDS.0)?;
    Ok(result_from_row(row)?.summary)
}
