//! Bounded, cached library evidence reads; these never authorize file serving.

use std::path::PathBuf;

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{MetadataStore, native_path::path_from_row, store::decode_fixed_hex};

/// Resident allowance for a single metadata library read, independent of downloads.
pub const LIBRARY_READ_MAX_BYTES: usize = 1024 * 1024;

/// One retained path observation. Facts describe the last cached observations,
/// not a new filesystem probe or a payload admission.
#[derive(Debug)]
pub struct MetadataLibraryLocation {
    pub path_id: i64,
    pub path: PathBuf,
    pub verified_in_session: bool,
    pub root_configured: bool,
    pub root_accessible: bool,
    pub identity_excluded: bool,
}

#[derive(Debug)]
pub struct MetadataLibraryLocationPage {
    pub locations: Vec<MetadataLibraryLocation>,
    pub next_after: Option<i64>,
    /// Conservative charge including path decoding and response serialization.
    pub resident_bytes: usize,
}

pub(crate) const LOCATION_PAGE_SQL: &str = concat!(
    "SELECT i.path_id,length(p.native_path),p.platform,
        CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
        EXISTS(SELECT 1 FROM temp.session_verified_local_paths v
            WHERE v.path_id=i.path_id AND v.verified_fingerprint=i.verified_fingerprint),
        EXISTS(SELECT 1 FROM shared_file_memberships m INDEXED BY shared_file_memberships_path_content_idx
            CROSS JOIN shared_directory_roots r ON r.id=m.root_id
            WHERE m.path_id=i.path_id AND m.removed_at_ms IS NULL AND r.enabled=1 AND r.deleted_at_ms IS NULL),
        EXISTS(SELECT 1 FROM shared_file_memberships m INDEXED BY shared_file_memberships_path_content_idx
            CROSS JOIN shared_directory_roots r ON r.id=m.root_id
            WHERE m.path_id=i.path_id AND m.removed_at_ms IS NULL AND r.enabled=1 AND r.deleted_at_ms IS NULL
                AND r.accessible=1 AND r.shareable=1),
        NOT (", crate::local_catalog::unexcluded_identity_sql!("i"), ")
     FROM local_file_instances i INDEXED BY local_file_instances_content_idx
     CROSS JOIN local_paths p ON p.id=i.path_id
     WHERE i.known_file_id=?1 AND i.path_id>?2 ORDER BY i.path_id LIMIT ?3"
);

impl MetadataStore {
    /// Enumerate retained copies by a stable internal path key. A missing library
    /// hash returns None; known verified content with no remaining copies returns
    /// an empty page. Search/cache-only observations do not constitute a library.
    /// The caller supplies a pre-reserved result budget; pages stop before decode
    /// when the next path would exceed it, and never silently omit that path.
    pub fn library_locations(
        &self,
        hash: &str,
        after_path_id: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Option<MetadataLibraryLocationPage>> {
        ensure!(after_path_id >= 0, "invalid library location cursor");
        ensure!(
            (1..=200).contains(&limit),
            "invalid library location page size"
        );
        ensure!(
            (1..=LIBRARY_READ_MAX_BYTES).contains(&max_bytes),
            "invalid library read budget"
        );
        let hash = decode_fixed_hex(hash, 16, "ED2K library hash")?;
        let mut guard = self.connection()?;
        let tx = guard.transaction()?;
        let content: Option<i64> = tx.query_row(
            "SELECT k.id FROM known_files k JOIN verified_local_content c ON c.known_file_id=k.id WHERE k.ed2k_hash=?1",
            [&hash], |row| row.get(0),
        ).optional()?;
        let Some(content) = content else {
            return Ok(None);
        };
        let mut statement = tx.prepare_cached(LOCATION_PAGE_SQL)?;
        let mut rows = statement.query(params![content, after_path_id, (limit + 1) as i64])?;
        let mut locations = Vec::new();
        let mut resident_bytes = 0usize;
        let mut has_more = false;
        while let Some(row) = rows.next()? {
            if locations.len() == limit {
                has_more = true;
                break;
            }
            let charge = crate::download_job_store::bounded_row_bytes(row, &[(1, 65_536, 8)])?;
            let next_bytes = resident_bytes.checked_add(charge);
            if !next_bytes.is_some_and(|bytes| bytes <= max_bytes) {
                ensure!(
                    !locations.is_empty(),
                    "library location exceeds result budget"
                );
                has_more = true;
                break;
            }
            let location = MetadataLibraryLocation {
                path_id: row.get(0)?,
                path: path_from_row(row, 2, 3)?,
                verified_in_session: row.get(4)?,
                root_configured: row.get(5)?,
                root_accessible: row.get(6)?,
                identity_excluded: row.get(7)?,
            };
            locations.push(location);
            resident_bytes = next_bytes.expect("checked result charge");
        }
        let next_after =
            has_more.then(|| locations.last().expect("nonempty location page").path_id);
        drop(rows);
        drop(statement);
        tx.commit()?;
        Ok(Some(MetadataLibraryLocationPage {
            locations,
            next_after,
            resident_bytes,
        }))
    }
}

#[cfg(test)]
mod tests;
