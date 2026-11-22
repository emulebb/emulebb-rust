//! Indexed catalog reads and path-ordered library pagination.
use crate::{
    MetadataSharedFileCursor, MetadataSharedFilePage, MetadataSharedFileQuery, MetadataStore,
    MetadataTransferCatalogEntry, MetadataTransferMediaMetadata,
    local_file_store::local_share_from_catalog, native_path::path_from_row,
    store::decode_fixed_hex,
};
use anyhow::Result;
use rusqlite::{Row, params};

const CATALOG_COUNT_SQL: &str = "SELECT count(*) FROM temp.session_library_catalog";

/// Normalize a filename substring without interpreting wildcard or query syntax.
/// Count Unicode characters before lowercasing, which can expand a character.
pub fn normalize_library_search(query: Option<&str>) -> Result<Option<String>> {
    query
        .map(|query| {
            let query = query.trim();
            anyhow::ensure!(
                query.chars().count() >= 3,
                "q must contain at least 3 characters"
            );
            Ok(query.to_lowercase())
        })
        .transpose()
}

/// Ordered complete-share eligibility and optional partial offers from one SQL snapshot.
pub type MetadataVerifiedShareBatch = Vec<(bool, Option<MetadataPartialOffer>)>;

// All eligible-copy readers compare both actual identity observations. This
// fragment accepts only a source-code SQL alias, never request input.
macro_rules! unexcluded_identity_sql {
    ($instance:literal) => {
        concat!(
            "NOT EXISTS(SELECT 1 FROM download_delivery_exclusions exclusion WHERE ",
            "exclusion.output_identity IN (",
            $instance,
            ".native_identity,",
            $instance,
            ".secondary_identity) OR ",
            "exclusion.secondary_identity IN (",
            $instance,
            ".native_identity,",
            $instance,
            ".secondary_identity))"
        )
    };
}
pub(crate) use unexcluded_identity_sql;

pub(crate) const VERIFIED_SHARE_EXISTS_SQL: &str = concat!(
    "SELECT EXISTS(SELECT 1 FROM known_files k JOIN verified_local_content c ON c.known_file_id=k.id JOIN local_file_instances i INDEXED BY local_file_instances_content_idx ON i.known_file_id=k.id JOIN temp.session_verified_local_paths v ON v.path_id=i.path_id AND v.verified_fingerprint=i.verified_fingerprint WHERE k.ed2k_hash=?1 AND ",
    crate::local_catalog::unexcluded_identity_sql!("i"),
    " AND EXISTS(SELECT 1 FROM shared_file_memberships m JOIN shared_directory_roots r ON r.id=m.root_id WHERE m.path_id=i.path_id AND m.removed_at_s IS NULL AND r.enabled=1 AND r.deleted_at_s IS NULL AND r.accessible=1 AND r.shareable=1))"
);
const PARTIAL_SHARE_OFFER_SQL: &str = "SELECT length(CAST(t.display_name AS BLOB)),length(CAST(k.upload_priority AS BLOB)),t.display_name,t.expected_size_bytes,k.upload_priority,k.rating,t.id,t.execution_generation FROM known_files k JOIN download_jobs t ON t.known_file_id=k.id WHERE k.ed2k_hash=?1 AND t.expected_size_bytes IS NOT NULL AND t.completed=0 AND t.final_rehash_pending=0 AND t.md4_hashset_acquired=1 AND t.removed_at_s IS NULL AND t.terminal_completed_at_s IS NULL AND t.delete_requested_at_s IS NULL AND EXISTS(SELECT 1 FROM download_job_verified_ranges r WHERE r.job_id=t.id)";

/// Compact, bounded fields needed to advertise an independent partial source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPartialOffer {
    pub job_token: crate::JobToken,
    pub name: String,
    pub size: u64,
    pub priority: String,
    pub rating: u8,
}

pub(crate) const COLUMNS: &str = r#"lower(hex(known_files.ed2k_hash)), known_files.size_bytes,
                    verified_local_content.part_count,
                    CASE WHEN verified_local_content.aich_root IS NULL THEN NULL
                         ELSE lower(hex(verified_local_content.aich_root)) END,
                    known_files.upload_priority,
                    known_files.auto_upload_priority,
                    known_files.comment, known_files.rating,
                    known_files.all_time_uploaded_bytes,
                    known_files.all_time_upload_requests,
                    known_files.all_time_upload_accepts,
                    known_files.last_upload_requested_at_s,
                    local_paths.platform, local_paths.native_path,
                    known_files.media_artist, known_files.media_album,
                    known_files.media_title, known_files.media_length_seconds,
                    known_files.media_bitrate_kbps, known_files.media_codec,
                    known_files.media_extractor_version
"#;

pub(crate) fn representative_path(verified_only: bool) -> String {
    let verified = if verified_only {
        "AND EXISTS (SELECT 1 FROM temp.session_verified_local_paths v
         WHERE v.path_id = candidate.path_id AND v.verified_fingerprint = candidate.verified_fingerprint)"
    } else {
        ""
    };
    format!(concat!("SELECT candidate.path_id FROM local_file_instances candidate
        JOIN local_paths candidate_paths ON candidate_paths.id = candidate.path_id
        WHERE candidate.known_file_id = known_files.id
          AND ", crate::local_catalog::unexcluded_identity_sql!("candidate"), "
          AND EXISTS (SELECT 1 FROM shared_file_memberships m
              JOIN shared_directory_roots r ON r.id = m.root_id
              WHERE m.path_id = candidate.path_id AND m.removed_at_s IS NULL
                AND r.enabled = 1 AND r.deleted_at_s IS NULL AND r.accessible = 1 AND r.shareable = 1)
          {verified}
        ORDER BY candidate_paths.platform, candidate_paths.native_path LIMIT 1"), verified=verified)
}

pub(crate) fn catalog_sql(exact: bool, verified_only: bool, instances: bool) -> String {
    let selection = if exact { "=" } else { ">" };
    let columns = if instances {
        "local_paths.platform, local_paths.native_path, lower(hex(known_files.ed2k_hash)), local_file_instances.size_bytes, local_file_instances.verified_fingerprint,local_file_instances.secondary_identity"
    } else {
        COLUMNS
    };
    let representative = representative_path(verified_only);
    let content = if instances {
        ""
    } else {
        "CROSS JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id"
    };
    // WHY: start from the hash index so a page limit bounds work by content,
    // rather than ranking and sorting every path in the remaining library.
    format!(
        "SELECT {columns} FROM known_files
        {content}
        CROSS JOIN local_file_instances ON local_file_instances.path_id = ({representative})
        CROSS JOIN local_paths ON local_paths.id = local_file_instances.path_id
        WHERE known_files.ed2k_hash {selection} ?2
        ORDER BY known_files.ed2k_hash LIMIT ?1"
    )
}

pub(crate) fn catalog_entry(row: &Row<'_>) -> rusqlite::Result<MetadataTransferCatalogEntry> {
    let path = path_from_row(row, 12, 13)?;
    let display_name = crate::NativePath::from(path.as_path())
        .display_file_name()
        .unwrap_or_default();
    Ok(MetadataTransferCatalogEntry {
        file_hash: row.get(0)?,
        display_name,
        file_size: crate::sql_value::unsigned::<u64>(row, 1)?,
        part_count: row.get::<_, u32>(2)?,
        aich_root: row.get(3)?,
        upload_priority: row.get(4)?,
        auto_upload_priority: row.get::<_, i64>(5)? != 0,
        comment: row.get(6)?,
        rating: row.get::<_, u8>(7)?,
        all_time_uploaded_bytes: crate::sql_value::unsigned::<u64>(row, 8)?,
        all_time_upload_requests: crate::sql_value::unsigned::<u64>(row, 9)?,
        all_time_upload_accepts: crate::sql_value::unsigned::<u64>(row, 10)?,
        last_upload_requested_at_s: row.get(11)?,
        media_path: Some(path),
        media: MetadataTransferMediaMetadata {
            artist: row.get(14)?,
            album: row.get(15)?,
            title: row.get(16)?,
            length_seconds: row.get::<_, u32>(17)?,
            bitrate_kbps: row.get::<_, u32>(18)?,
            codec: row.get(19)?,
            extractor_version: row.get::<_, u32>(20)?,
        },
    })
}

impl MetadataStore {
    /// Read one bounded batch from a single connection snapshot without waiting
    /// for a category writer; `None` signals that the connection is busy.
    pub fn try_verified_share_batch(
        &self,
        hashes: &[[u8; 16]],
    ) -> Result<Option<MetadataVerifiedShareBatch>> {
        anyhow::ensure!(
            hashes.len() <= 200,
            "shared eligibility batch exceeds 200 hashes"
        );
        let Some(mut conn) = self.try_connection()? else {
            return Ok(None);
        };
        let tx = conn.transaction()?;
        let mut stmt = tx.prepare_cached(VERIFIED_SHARE_EXISTS_SQL)?;
        // WHY: sharing policy gates new protocol admissions, while the physical
        // copy projection remains valid for library browsing and accepted reads.
        // Both decisions use this same bounded batch's SQLite snapshot.
        let mut sharing = tx.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM known_files WHERE ed2k_hash=?1 AND sharing_enabled=1)",
        )?;
        let mut partial = tx.prepare_cached(PARTIAL_SHARE_OFFER_SQL)?;
        let mut result = Vec::with_capacity(hashes.len());
        let mut text_bytes = 0usize;
        for hash in hashes {
            let complete = stmt.query_row([hash.as_slice()], |row| row.get::<_, bool>(0))?
                && sharing.query_row([hash.as_slice()], |row| row.get::<_, bool>(0))?;
            let mut rows = partial.query([hash.as_slice()])?;
            let incomplete = if let Some(row) = rows.next()? {
                let name_len: i64 = row.get(0)?;
                let priority_len: i64 = row.get(1)?;
                let name_len = usize::try_from(name_len)?;
                let priority_len = usize::try_from(priority_len)?;
                anyhow::ensure!(
                    name_len <= 65_536 && priority_len <= 65_536,
                    "partial offer text exceeds per-entry bound"
                );
                let next = text_bytes
                    .checked_add(name_len)
                    .and_then(|n| n.checked_add(priority_len))
                    .ok_or_else(|| anyhow::anyhow!("partial offer batch exceeds bound"))?;
                if next > 192 * 1024 {
                    break;
                }
                text_bytes = next;
                Some(MetadataPartialOffer {
                    job_token: crate::JobToken {
                        job_id: row.get(6)?,
                        generation: crate::sql_value::unsigned::<u64>(row, 7)?,
                    },
                    name: row.get(2)?,
                    size: crate::sql_value::unsigned::<u64>(row, 3)?,
                    priority: row.get(4)?,
                    rating: row.get(5)?,
                })
            } else {
                None
            };
            result.push((complete, incomplete));
        }
        drop(partial);
        drop(sharing);
        drop(stmt);
        tx.commit()?;
        Ok(Some(result))
    }

    pub fn query_active_local_share_entries(
        &self,
        query: &MetadataSharedFileQuery,
    ) -> Result<MetadataSharedFilePage> {
        let search = normalize_library_search(query.search.as_deref())?;
        let priority = query
            .priority
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        let (cursor_path, cursor_hash) = if let Some(cursor) = &query.after {
            (
                cursor.sort_path.as_str(),
                decode_fixed_hex(&cursor.file_hash, 16, "ED2K shared-file cursor hash")?,
            )
        } else {
            ("", Vec::new())
        };
        let from = "FROM temp.session_library_catalog cache
            CROSS JOIN local_paths ON local_paths.id = cache.path_id
            CROSS JOIN known_files ON known_files.id = cache.known_file_id
            CROSS JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
            WHERE (?3 IS NULL OR instr(local_paths.file_name_search_key, ?3) > 0)
              AND (?4 IS NULL OR known_files.upload_priority = ?4)";
        let started = std::time::Instant::now();
        tracing::debug!(phase = "connectionWait", "catalog read");
        let mut guard = self.connection()?;
        tracing::debug!(
            phase = "connectionAcquired",
            elapsed_ms = started.elapsed().as_millis(),
            "catalog read"
        );
        let tx = guard.transaction()?;
        crate::library_projection::refresh(&tx)?;
        tracing::debug!(
            phase = "projectionRefreshed",
            elapsed_ms = started.elapsed().as_millis(),
            "catalog read"
        );
        let conn = &tx;
        let total = if !query.count_total {
            0
        } else if search.is_none() && priority.is_none() {
            // WHY: the refreshed projection already contains exactly eligible
            // contents. Joining every content again makes even a one-row poll
            // scan the library and hold its metadata connection during writes.
            conn.query_row(CATALOG_COUNT_SQL, [], |r| {
                crate::sql_value::unsigned::<usize>(r, 0)
            })?
        } else {
            let sql = format!("SELECT count(*) {from}");
            conn.query_row(
                &sql,
                params![
                    rusqlite::types::Null,
                    rusqlite::types::Null,
                    search,
                    priority
                ],
                |r| crate::sql_value::unsigned::<usize>(r, 0),
            )?
        };
        let sql = format!(
            "SELECT {COLUMNS}, cache.sort_key {from}
            AND cache.sort_key >= ?1
            AND (cache.sort_key, cache.ed2k_hash) > (?1, ?2)
            ORDER BY cache.sort_key, cache.ed2k_hash LIMIT ?5"
        );
        tracing::debug!(
            phase = "counted",
            elapsed_ms = started.elapsed().as_millis(),
            "catalog read"
        );
        let mut stmt = conn.prepare(&sql)?;
        let limit = i64::try_from(query.limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut rows = stmt.query(params![cursor_path, cursor_hash, search, priority, limit])?;
        let mut entries = Vec::new();
        let mut last_key = None;
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if entries.len() == query.limit {
                has_more = true;
                break;
            }
            let entry = local_share_from_catalog(catalog_entry(row)?)?;
            last_key = Some(MetadataSharedFileCursor {
                sort_path: row.get(21)?,
                file_hash: entry.file_hash.clone(),
            });
            entries.push(entry);
        }
        drop(rows);
        drop(stmt);
        tx.commit()?;
        Ok(MetadataSharedFilePage {
            entries,
            total,
            next_cursor: if has_more { last_key } else { None },
        })
    }
}

#[cfg(test)]
mod tests;
