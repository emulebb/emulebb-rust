//! Indexed catalog reads and path-ordered library pagination.
use crate::{
    MetadataSharedFileCursor, MetadataSharedFilePage, MetadataSharedFileQuery, MetadataStore,
    MetadataTransferCatalogEntry, MetadataTransferMediaMetadata,
    local_file_store::local_share_from_catalog, native_path::path_from_row,
    store::decode_fixed_hex,
};
use anyhow::Result;
use rusqlite::{Row, params};

const COLUMNS: &str = r#"lower(hex(known_files.ed2k_hash)), known_files.size_bytes,
                    verified_local_content.part_count,
                    CASE WHEN verified_local_content.aich_root IS NULL THEN NULL
                         ELSE lower(hex(verified_local_content.aich_root)) END,
                    verified_local_content.upload_priority,
                    verified_local_content.auto_upload_priority,
                    verified_local_content.comment, verified_local_content.rating,
                    known_files.all_time_uploaded_bytes,
                    known_files.all_time_upload_requests,
                    known_files.all_time_upload_accepts,
                    known_files.last_upload_requested_at_ms,
                    local_paths.platform, local_paths.native_path,
                    known_files.media_artist, known_files.media_album,
                    known_files.media_title, known_files.media_length_seconds,
                    known_files.media_bitrate_kbps, known_files.media_codec,
                    known_files.media_extractor_version
"#;

fn representative_path(verified_only: bool) -> String {
    let verified = if verified_only {
        "AND EXISTS (SELECT 1 FROM temp.session_verified_local_paths v
         WHERE v.path_id = candidate.path_id AND v.verified_fingerprint = candidate.verified_fingerprint)"
    } else {
        ""
    };
    format!("SELECT candidate.path_id FROM local_file_instances candidate
        JOIN local_paths candidate_paths ON candidate_paths.id = candidate.path_id
        WHERE candidate.known_file_id = known_files.id
          AND EXISTS (SELECT 1 FROM shared_file_memberships m
              JOIN shared_directory_roots r ON r.id = m.root_id
              WHERE m.path_id = candidate.path_id AND m.removed_at_ms IS NULL
                AND r.enabled = 1 AND r.deleted_at_ms IS NULL AND r.accessible = 1 AND r.shareable = 1)
          {verified}
        ORDER BY candidate_paths.platform, candidate_paths.native_path LIMIT 1")
}

pub(crate) fn catalog_sql(exact: bool, verified_only: bool, instances: bool) -> String {
    let selection = if exact { "=" } else { ">" };
    let columns = if instances {
        "local_paths.platform, local_paths.native_path, lower(hex(known_files.ed2k_hash)), local_file_instances.size_bytes, local_file_instances.verified_fingerprint"
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
        last_upload_request_ms: row.get(11)?,
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
    pub fn query_active_local_share_entries(
        &self,
        query: &MetadataSharedFileQuery,
    ) -> Result<MetadataSharedFilePage> {
        let search = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
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
        let representative = representative_path(true);
        let from = format!("FROM local_paths
            CROSS JOIN local_file_instances ON local_file_instances.path_id = local_paths.id
            CROSS JOIN known_files ON known_files.id = local_file_instances.known_file_id
            CROSS JOIN verified_local_content ON verified_local_content.known_file_id = known_files.id
            WHERE local_file_instances.path_id = ({representative})
              AND (?3 IS NULL OR instr(local_paths.file_name_search_key, ?3) > 0
                  OR instr(local_paths.sort_key, ?3) > 0 OR instr(lower(hex(known_files.ed2k_hash)), ?3) > 0)
              AND (?4 IS NULL OR verified_local_content.upload_priority = ?4)");
        let conn = self.connection()?;
        let total = if query.count_total {
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
        } else {
            0
        };
        let sql = format!(
            "SELECT {COLUMNS}, local_paths.sort_key {from}
            AND local_paths.sort_key >= ?1
            AND (local_paths.sort_key, known_files.ed2k_hash) > (?1, ?2)
            ORDER BY local_paths.sort_key, known_files.ed2k_hash LIMIT ?5"
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
        Ok(MetadataSharedFilePage {
            entries,
            total,
            next_cursor: if has_more { last_key } else { None },
        })
    }
}

#[cfg(test)]
mod tests;
