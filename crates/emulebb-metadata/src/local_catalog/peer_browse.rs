use std::{ops::RangeInclusive, sync::LazyLock};

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::{MetadataStore, NativePath, native_path::path_from_row};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MetadataPeerBrowseView {
    Flat,
    DirectoryList,
    CompleteDirectory,
    IncompleteDirectory,
}

/// Path-free row used only while constructing a peer response.
pub struct MetadataPeerBrowseFile {
    pub id: i64,
    pub hash: [u8; 16],
    pub name: String,
    pub size: u64,
    pub partial: bool,
}

const COMPLETE: &str = "SELECT c.known_file_id,c.ed2k_hash,k.size_bytes,p.platform,p.native_path
    FROM temp.session_library_catalog c CROSS JOIN known_files k ON k.id=c.known_file_id
    CROSS JOIN local_paths p ON p.id=c.path_id
    WHERE c.known_file_id BETWEEN ?1 AND ?2 AND k.sharing_enabled=1
    AND k.size_bytes<=?3 ORDER BY c.known_file_id";

static PARTIAL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT t.known_file_id,k.ed2k_hash,t.expected_size_bytes,
       CASE WHEN length(CAST(t.display_name AS BLOB))<=65535 THEN t.display_name
            ELSE lower(hex(k.ed2k_hash)) END
     FROM download_jobs t INDEXED BY download_jobs_unremoved_unfinished_content_idx
     CROSS JOIN known_files k ON k.id=t.known_file_id
     WHERE t.known_file_id BETWEEN ?1 AND ?2 AND t.expected_size_bytes<=?3
       AND {} AND (?4=0 OR k.sharing_enabled=0 OR NOT EXISTS(
       SELECT 1 FROM temp.session_library_catalog c WHERE c.known_file_id=k.id))
     ORDER BY t.known_file_id",
        super::SHAREABLE_PARTIAL
    )
});

impl MetadataStore {
    /// Visit a single SQLite snapshot. The directory listing includes both
    /// source kinds. Flat browsing prefers the enabled complete copy per hash.
    /// The return value reports whether stock's incomplete directory exists.
    pub fn visit_verified_peer_files(
        &self,
        view: MetadataPeerBrowseView,
        ids: RangeInclusive<i64>,
        max_file_size: u64,
        mut visit: impl FnMut(MetadataPeerBrowseFile) -> Result<bool>,
    ) -> Result<bool> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        if view != MetadataPeerBrowseView::IncompleteDirectory {
            crate::library_projection::refresh(&tx)?;
        }
        let has_queue = view == MetadataPeerBrowseView::DirectoryList
            && tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM download_jobs WHERE removed_at_s IS NULL
             AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL)",
                [],
                |row| row.get::<_, bool>(0),
            )?;
        let ceiling = i64::try_from(max_file_size).unwrap_or(i64::MAX);
        // Preserve a successful projection refresh even if the client must retry
        // an oversized flat listing through directories.
        let outcome = (|| -> Result<()> {
            if view != MetadataPeerBrowseView::IncompleteDirectory
                && !visit_complete(&tx, &ids, ceiling, &mut visit)?
            {
                return Ok(());
            }
            if view != MetadataPeerBrowseView::CompleteDirectory {
                let mut statement = tx.prepare_cached(&PARTIAL)?;
                let mut rows = statement.query(params![
                    ids.start(),
                    ids.end(),
                    ceiling,
                    view == MetadataPeerBrowseView::Flat
                ])?;
                while let Some(row) = rows.next()? {
                    if !visit(MetadataPeerBrowseFile {
                        id: row.get(0)?,
                        hash: row.get(1)?,
                        size: crate::sql_value::unsigned(row, 2)?,
                        name: row.get(3)?,
                        partial: true,
                    })? {
                        break;
                    }
                }
            }
            Ok(())
        })();
        tx.commit()?;
        outcome.map(|()| has_queue)
    }
}

fn visit_complete(
    conn: &Connection,
    ids: &RangeInclusive<i64>,
    ceiling: i64,
    visit: &mut impl FnMut(MetadataPeerBrowseFile) -> Result<bool>,
) -> Result<bool> {
    let mut statement = conn.prepare_cached(COMPLETE)?;
    let mut rows = statement.query(params![ids.start(), ids.end(), ceiling])?;
    while let Some(row) = rows.next()? {
        if let Some(name) = NativePath::from(path_from_row(row, 3, 4)?).display_file_name()
            && !visit(MetadataPeerBrowseFile {
                id: row.get(0)?,
                hash: row.get(1)?,
                size: crate::sql_value::unsigned(row, 2)?,
                name,
                partial: false,
            })?
        {
            return Ok(false);
        }
    }
    Ok(true)
}
