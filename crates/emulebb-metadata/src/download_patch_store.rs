//! Atomic scalar edits, independent of payload allocation and progress writes.
use crate::{
    JobToken, MetadataStore,
    content_identity::check_accepted_identity,
    download_job_store::{MAX_JOB_TEXT_BYTES, bounded_row_bytes, unix_s},
    store::decode_fixed_hex,
};
use anyhow::Result;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

#[derive(Debug, Clone, Default)]
pub struct MetadataDownloadPatch {
    pub name: Option<String>,
    /// Omission retains assignment; Some(None) clears it.
    pub category_id: Option<Option<i64>>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadPatchError {
    InvalidName,
    InvalidSize,
    InvalidCategory,
    CategoryNotFound,
    NameFixed,
    SizeConflict,
    Stale,
}
impl std::fmt::Display for DownloadPatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidName => {
                "download name must be nonempty, NUL-free and at most 65536 UTF-8 bytes"
            }
            Self::InvalidSize => "download size must be a positive supported integer",
            Self::InvalidCategory => "invalid download category",
            Self::CategoryNotFound => "category does not exist",
            Self::NameFixed => {
                "download name is fixed after completion or delivery-attempt selection"
            }
            Self::SizeConflict => "download has conflicting expected or accepted content size",
            Self::Stale => "download execution changed before the edit",
        })
    }
}
impl std::error::Error for DownloadPatchError {}

#[derive(Debug)]
pub struct MetadataDownloadPatched {
    pub token: JobToken,
    pub file_hash: String,
    pub name: String,
    pub category_id: Option<i64>,
    pub size_bytes: Option<u64>,
    pub changed: bool,
    pub size_changed: bool,
}

impl MetadataDownloadPatch {
    pub fn validate(&self) -> std::result::Result<(), DownloadPatchError> {
        Self::validate_fields(self.name.as_deref(), self.category_id, self.size_bytes)
    }

    pub fn validate_fields(
        name: Option<&str>,
        category_id: Option<Option<i64>>,
        size_bytes: Option<u64>,
    ) -> std::result::Result<(), DownloadPatchError> {
        if name.is_some_and(|name| {
            name.trim().is_empty() || name.len() > MAX_JOB_TEXT_BYTES || name.contains('\0')
        }) {
            return Err(DownloadPatchError::InvalidName);
        }
        if size_bytes.is_some_and(|size| size == 0 || i64::try_from(size).is_err()) {
            return Err(DownloadPatchError::InvalidSize);
        }
        if category_id.flatten().is_some_and(|id| id <= 0) {
            return Err(DownloadPatchError::InvalidCategory);
        }
        Ok(())
    }
}

impl MetadataStore {
    /// Validate the complete candidate and commit all supplied scalar fields
    /// together. The caller retains native publication guards through its reply.
    pub fn patch_download_job(
        &self,
        token: JobToken,
        patch: &MetadataDownloadPatch,
    ) -> Result<Option<MetadataDownloadPatched>> {
        patch.validate()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                "SELECT j.execution_generation,lower(hex(k.ed2k_hash)),
            CASE WHEN length(CAST(j.display_name AS BLOB))<=65536 THEN j.display_name END,
            j.expected_size_bytes,j.category_id,j.terminal_completed_at_s,j.delivery_state,
            EXISTS(SELECT 1 FROM download_delivery_attempts d WHERE d.job_id=j.id),
            length(CAST(j.display_name AS BLOB))
            FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
            WHERE j.id=?1 AND j.removed_at_s IS NULL AND j.delete_requested_at_s IS NULL",
                [token.job_id],
                |row| {
                    bounded_row_bytes(row, &[(8, MAX_JOB_TEXT_BYTES, 2)])?;
                    Ok((
                        crate::sql_value::unsigned::<u64>(row, 0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        crate::sql_value::optional_unsigned::<u64>(row, 3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            generation,
            hash,
            old_name,
            old_size,
            old_category,
            completed,
            delivery,
            attempt,
        )) = row
        else {
            return Ok(None);
        };
        if generation != token.generation {
            return Err(DownloadPatchError::Stale.into());
        }
        let name = patch.name.as_deref().unwrap_or(&old_name);
        let category = patch.category_id.unwrap_or(old_category);
        let size = patch.size_bytes.or(old_size);
        if name != old_name && (completed.is_some() || delivery != "pending" || attempt) {
            return Err(DownloadPatchError::NameFixed.into());
        }
        if let Some(size) = patch.size_bytes {
            if old_size.is_some_and(|old| old != size) {
                return Err(DownloadPatchError::SizeConflict.into());
            }
            let raw = decode_fixed_hex(&hash, 16, "ED2K hash")?;
            if let Err(error) = check_accepted_identity(&tx, &raw, i64::try_from(size)?, None) {
                if error.is::<crate::MetadataContentConflict>() {
                    return Err(DownloadPatchError::SizeConflict.into());
                }
                return Err(error);
            }
        }
        if let Some(category) = category {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM categories WHERE id=?1)",
                [category],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(DownloadPatchError::CategoryNotFound.into());
            }
        }
        let changed = name != old_name || category != old_category || size != old_size;
        if changed {
            tx.execute("UPDATE download_jobs SET display_name=?2,category_id=?3,expected_size_bytes=?4,updated_at_s=?5 WHERE id=?1",
                params![token.job_id, name, category, size.map(i64::try_from).transpose()?, unix_s()])?;
        }
        let result = MetadataDownloadPatched {
            token,
            file_hash: hash,
            name: name.to_owned(),
            category_id: category,
            size_bytes: size,
            changed,
            size_changed: size != old_size,
        };
        tx.commit()?;
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests;
