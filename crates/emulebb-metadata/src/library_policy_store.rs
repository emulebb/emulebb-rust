//! Durable hash policy and immutable tags, independent of local copy lifetime.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{MetadataStore, store::decode_fixed_hex, valid_category_name};

/// Predictable domain failures; database/commit failures retain their own errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryTagError {
    InvalidName,
    AlreadyExists,
    NotFound,
    UnknownFile,
}

impl std::fmt::Display for LibraryTagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "invalid tag name",
            Self::AlreadyExists => "tag name already exists",
            Self::NotFound => "tag does not exist",
            Self::UnknownFile => "library file does not exist",
        })
    }
}
impl std::error::Error for LibraryTagError {}

/// The name is the public identity. The SQL key is for internal associations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLibraryTag {
    pub id: i64,
    pub name: String,
}

#[derive(Debug)]
pub struct MetadataLibraryTagPage {
    pub tags: Vec<MetadataLibraryTag>,
    pub next_after: Option<String>,
    pub has_more: bool,
}

fn validate_name(name: &str) -> Result<()> {
    // Category and tag identities deliberately share the same ASCII grammar.
    if !valid_category_name(name) {
        return Err(LibraryTagError::InvalidName.into());
    }
    Ok(())
}

fn tag_page(
    conn: &Connection,
    known_file_id: Option<i64>,
    after: Option<&str>,
    limit: usize,
) -> Result<MetadataLibraryTagPage> {
    ensure!((1..=200).contains(&limit), "invalid tag page size");
    if let Some(name) = after {
        validate_name(name)?;
    }
    let mut statement = conn.prepare_cached(
        "SELECT t.id,t.name FROM library_tags t
         WHERE t.name > ?1 COLLATE NOCASE
           AND (?3 IS NULL OR EXISTS(SELECT 1 FROM known_file_tags a
                WHERE a.known_file_id=?3 AND a.tag_id=t.id))
         ORDER BY t.name COLLATE NOCASE LIMIT ?2",
    )?;
    let mut tags = statement
        .query_map(
            params![after.unwrap_or(""), (limit + 1) as i64, known_file_id],
            |row| {
                Ok(MetadataLibraryTag {
                    id: row.get(0)?,
                    name: row.get(1)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = tags.len() > limit;
    tags.truncate(limit);
    let next_after = has_more.then(|| tags.last().expect("nonempty tag page").name.clone());
    Ok(MetadataLibraryTagPage {
        tags,
        next_after,
        has_more,
    })
}

impl MetadataStore {
    /// Explicit creation never rewrites a name or creates a case variant.
    pub fn create_library_tag(&self, name: &str) -> Result<MetadataLibraryTag> {
        validate_name(name)?;
        let conn = self.connection()?;
        if conn.execute(
            "INSERT INTO library_tags(name) VALUES(?1) ON CONFLICT(name) DO NOTHING",
            [name],
        )? == 0
        {
            return Err(LibraryTagError::AlreadyExists.into());
        }
        Ok(MetadataLibraryTag {
            id: conn.last_insert_rowid(),
            name: name.to_owned(),
        })
    }

    pub fn library_tag(&self, name: &str) -> Result<Option<MetadataLibraryTag>> {
        validate_name(name)?;
        self.connection()?
            .query_row(
                "SELECT id,name FROM library_tags WHERE name=?1",
                [name],
                |row| {
                    Ok(MetadataLibraryTag {
                        id: row.get(0)?,
                        name: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Seek names in ASCII case-insensitive order; retain at most 200 rows.
    pub fn library_tags_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<MetadataLibraryTagPage> {
        let conn = self.connection()?;
        tag_page(&conn, None, after, limit)
    }

    /// Deletion cascades only tag associations, never content or policy.
    pub fn delete_library_tag(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        Ok(self
            .connection()?
            .execute("DELETE FROM library_tags WHERE name=?1", [name])?
            != 0)
    }

    /// Set one association explicitly. Unknown tags/files are never created.
    pub fn set_library_file_tag(&self, hash: &str, name: &str, assigned: bool) -> Result<bool> {
        validate_name(name)?;
        let hash = decode_fixed_hex(hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let tag_id: i64 = tx
            .query_row("SELECT id FROM library_tags WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or(LibraryTagError::NotFound)?;
        let file_id: i64 = tx
            .query_row(
                "SELECT id FROM known_files WHERE ed2k_hash=?1",
                [hash],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(LibraryTagError::UnknownFile)?;
        let changed = if assigned {
            tx.execute("INSERT INTO known_file_tags(known_file_id,tag_id) VALUES(?1,?2) ON CONFLICT DO NOTHING", params![file_id,tag_id])?
        } else {
            tx.execute(
                "DELETE FROM known_file_tags WHERE known_file_id=?1 AND tag_id=?2",
                params![file_id, tag_id],
            )?
        } != 0;
        tx.commit()?;
        Ok(changed)
    }

    /// Read only the requested tag window for a known hash, including absent files.
    pub fn library_file_tags_page(
        &self,
        hash: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Option<MetadataLibraryTagPage>> {
        let hash = decode_fixed_hex(hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let file_id: Option<i64> = tx
            .query_row(
                "SELECT id FROM known_files WHERE ed2k_hash=?1",
                [hash],
                |r| r.get(0),
            )
            .optional()?;
        let page = file_id
            .map(|id| tag_page(&tx, Some(id), after, limit))
            .transpose()?;
        tx.commit()?;
        Ok(page)
    }

    pub fn library_sharing_enabled(&self, hash: &str) -> Result<Option<bool>> {
        let hash = decode_fixed_hex(hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                "SELECT sharing_enabled FROM known_files WHERE ed2k_hash=?1",
                [hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Set the hash policy; None means unknown content, Some(false) is unchanged.
    /// Runtime publication/request admission belongs to the calling domain owner.
    pub fn set_library_sharing_enabled(&self, hash: &str, enabled: bool) -> Result<Option<bool>> {
        let hash = decode_fixed_hex(hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<bool> = tx
            .query_row(
                "SELECT sharing_enabled FROM known_files WHERE ed2k_hash=?1",
                [&hash],
                |row| row.get(0),
            )
            .optional()?;
        let Some(previous) = previous else {
            return Ok(None);
        };
        if previous != enabled {
            tx.execute(
                "UPDATE known_files SET sharing_enabled=?1 WHERE ed2k_hash=?2",
                params![enabled, hash],
            )?;
        }
        tx.commit()?;
        Ok(Some(previous != enabled))
    }
}

#[cfg(test)]
mod tests;
