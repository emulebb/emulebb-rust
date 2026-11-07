//! Admission rules shared by every writer of accepted content identity.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

use crate::MetadataContentConflict;

/// Network observations may enrich accepted content, but cannot redefine it.
pub(crate) fn check_accepted_identity(
    conn: &Connection,
    hash: &[u8],
    size_bytes: i64,
    aich_root: Option<&[u8]>,
) -> Result<()> {
    let existing = conn
        .query_row(
            "SELECT f.size_bytes, coalesce(c.aich_root, f.aich_root)
             FROM known_files f
             LEFT JOIN verified_local_content c ON c.known_file_id = f.id
             WHERE f.ed2k_hash = ?1
               AND (c.known_file_id IS NOT NULL
                    OR EXISTS (SELECT 1 FROM transfers t WHERE t.known_file_id = f.id))",
            params![hash],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?;
    if let Some((stored_size, stored_root)) = existing {
        ensure!(
            stored_size == size_bytes,
            MetadataContentConflict("ED2K identity has conflicting file size")
        );
        ensure!(
            stored_root
                .as_deref()
                .zip(aich_root)
                .is_none_or(|(a, b)| a == b),
            MetadataContentConflict("ED2K identity has conflicting AICH root")
        );
    }
    Ok(())
}
