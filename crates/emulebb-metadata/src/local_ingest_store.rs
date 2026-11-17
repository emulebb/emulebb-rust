//! Conditional local path binding and its same-transaction publication view.

use crate::{
    MetadataAichRecoverySet, MetadataIndexedFile, MetadataIndexedFileOrigin,
    MetadataLocalFileInstance, MetadataPartialShare, MetadataStore, MetadataTransferAichIdentity,
    MetadataTransferCatalogEntry, MetadataTransferMediaMetadata, MetadataVerifiedLocalContent,
    NativePath, ObservedRootChanged,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

#[cfg(test)]
std::thread_local! {
    static FALLBACK_GATE: std::cell::RefCell<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>
        = const { std::cell::RefCell::new(None) };
}
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone)]
pub struct MetadataIngestRoot {
    pub root: PathBuf,
    pub relative: PathBuf,
}

#[derive(Debug)]
pub struct MetadataIngestPathChanged;
impl std::fmt::Display for MetadataIngestPathChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local path binding changed during preparation")
    }
}
impl std::error::Error for MetadataIngestPathChanged {}

#[derive(Debug)]
pub struct MetadataIngestCommitUncertain;
impl std::fmt::Display for MetadataIngestCommitUncertain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local ingest commit outcome is uncertain")
    }
}
impl std::error::Error for MetadataIngestCommitUncertain {}

#[derive(Debug)]
pub struct MetadataIngestProjection {
    pub file_hash: String,
    pub job_token: Option<crate::JobToken>,
    pub complete: Option<MetadataTransferCatalogEntry>,
    pub partial: Option<MetadataPartialShare>,
    pub aich: Option<MetadataTransferAichIdentity>,
}

/// Short post-preparation snapshot of the only unfinished job for content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataIngestJob {
    pub file_hash: String,
    pub token: Option<crate::JobToken>,
}

#[derive(Debug)]
pub struct MetadataIngestJobChanged;
impl std::fmt::Display for MetadataIngestJobChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ingest job generation changed before binding")
    }
}
impl std::error::Error for MetadataIngestJobChanged {}

fn current_job(conn: &Connection, hash: &str) -> Result<Option<crate::JobToken>> {
    let raw = crate::store::decode_fixed_hex(hash, 16, "ED2K hash")?;
    Ok(conn
        .query_row(
            "SELECT j.id,j.execution_generation FROM known_files k
        JOIN download_jobs j ON j.known_file_id=k.id WHERE k.ed2k_hash=?1
        AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL
        AND j.delete_requested_at_s IS NULL",
            [raw],
            |row| {
                Ok(crate::JobToken {
                    job_id: row.get(0)?,
                    generation: crate::sql_value::unsigned::<u64>(row, 1)?,
                })
            },
        )
        .optional()?)
}

#[derive(Debug)]
pub struct MetadataIngestCommit {
    pub projections: Vec<MetadataIngestProjection>,
    pub recovery_error: Option<anyhow::Error>,
}

fn check_binding(
    conn: &Connection,
    content: &MetadataVerifiedLocalContent,
    expected: Option<&MetadataLocalFileInstance>,
) -> Result<()> {
    let native = NativePath::from(content.path.as_path());
    let current = conn
        .query_row(
            "SELECT lower(hex(k.ed2k_hash)),i.verified_fingerprint FROM local_paths p
         JOIN local_file_instances i ON i.path_id=p.id JOIN known_files k ON k.id=i.known_file_id
         WHERE p.platform=?1 AND p.native_path=?2",
            params![NativePath::platform(), native.storage_bytes()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let matches = match (current, expected) {
        (None, None) => true,
        (Some((hash, fingerprint)), Some(expected)) => {
            hash == expected.file_hash
                && fingerprint == expected.verified_fingerprint.storage_bytes()
        }
        _ => false,
    };
    ensure!(matches, MetadataIngestPathChanged);
    Ok(())
}

fn project(conn: &Connection, hash: &str) -> Result<MetadataIngestProjection> {
    let raw = crate::store::decode_fixed_hex(hash, 16, "ED2K hash")?;
    // One verified copy by path key, never an unverified representative and
    // never a materialized list of all copies. Bounds apply before decoding.
    let sql = format!(
        concat!(
            "SELECT {} FROM known_files
        JOIN verified_local_content ON verified_local_content.known_file_id=known_files.id
        JOIN local_file_instances ON local_file_instances.known_file_id=known_files.id
        JOIN local_paths ON local_paths.id=local_file_instances.path_id
        JOIN temp.session_verified_local_paths v ON v.path_id=local_paths.id
            AND v.verified_fingerprint=local_file_instances.verified_fingerprint
        WHERE known_files.ed2k_hash=?1 AND known_files.sharing_enabled=1
        AND ",
            crate::local_catalog::unexcluded_identity_sql!("local_file_instances"),
            "
        AND EXISTS(SELECT 1 FROM shared_file_memberships m
            JOIN shared_directory_roots r ON r.id=m.root_id WHERE m.path_id=local_paths.id
            AND m.removed_at_ms IS NULL AND r.enabled=1 AND r.deleted_at_ms IS NULL
            AND r.accessible=1 AND r.shareable=1)
        ORDER BY local_file_instances.path_id LIMIT 1"
        ),
        crate::local_catalog::COLUMNS
    );
    // Validate the selected row before catalog_entry allocates text/path buffers.
    let complete = conn
        .query_row(&sql, [&raw], |row| {
            for column in [4, 6, 13, 14, 15, 16, 19] {
                let bytes = match row.get_ref(column)? {
                    rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes) => bytes,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                if bytes.len() > 65_536 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            crate::local_catalog::catalog_entry(row)
        })
        .optional()?;
    Ok(MetadataIngestProjection {
        file_hash: hash.to_owned(),
        job_token: current_job(conn, hash)?,
        complete,
        partial: MetadataStore::partial_share_on_connection(conn, hash)?,
        aich: crate::transfer_store::read_transfer_aich_identity(conn, &raw)?,
    })
}

impl MetadataStore {
    /// Capture at most two current executions after hashing, before waiting on
    /// their job guards. Binding rechecks this exact snapshot in every transaction.
    pub fn capture_local_ingest_jobs(&self, hashes: &[String]) -> Result<Vec<MetadataIngestJob>> {
        ensure!(
            !hashes.is_empty() && hashes.len() <= 2,
            "invalid ingest identity count"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut jobs = Vec::with_capacity(hashes.len());
        for hash in hashes {
            jobs.push(MetadataIngestJob {
                file_hash: hash.clone(),
                token: current_job(&tx, hash)?,
            });
        }
        tx.commit()?;
        Ok(jobs)
    }

    /// Re-read at most two affected identities without replaying committed SQL.
    pub fn local_ingest_projections(
        &self,
        hashes: &[String],
    ) -> Result<Vec<MetadataIngestProjection>> {
        ensure!(
            !hashes.is_empty() && hashes.len() <= 2,
            "invalid ingest identity count"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut projections = Vec::with_capacity(hashes.len());
        for hash in hashes {
            projections.push(project(&tx, hash)?);
        }
        tx.commit()?;
        Ok(projections)
    }

    /// Bind prepared bytes only to the path generation whose hash locks the
    /// caller owns. Optional recovery rollback repeats this entire conditional
    /// transaction, including root, index and projection checks.
    pub fn commit_local_ingest(
        &self,
        content: &MetadataVerifiedLocalContent,
        recovery: &MetadataAichRecoverySet,
        media: &MetadataTransferMediaMetadata,
        expected: Option<&MetadataLocalFileInstance>,
        expected_jobs: &[MetadataIngestJob],
        roots: &[MetadataIngestRoot],
        index_type: Option<&str>,
        root_epoch: (&AtomicU64, u64),
    ) -> Result<MetadataIngestCommit> {
        ensure!(
            content.file_size == recovery.size
                && content.aich_root.as_deref() == Some(hex::encode(recovery.root).as_str()),
            "recovery set differs from verified content"
        );
        let mut affected = vec![content.file_hash.as_str()];
        if let Some(old) = expected.filter(|old| old.file_hash != content.file_hash) {
            affected.push(old.file_hash.as_str());
        }
        ensure!(
            expected_jobs.len() == affected.len()
                && affected.iter().all(|hash| expected_jobs
                    .iter()
                    .filter(|job| job.file_hash == *hash)
                    .count()
                    == 1),
            "ingest job snapshot does not cover exactly the affected content"
        );
        let mut recovery_error = None;
        // Only a transaction-wide optional-cache abort gets one fallback.
        for with_recovery in [true, false] {
            let mut conn = self.connection()?;
            let mut tx = conn.transaction()?;
            check_binding(&tx, content, expected)?;
            for job in expected_jobs {
                ensure!(
                    current_job(&tx, &job.file_hash)? == job.token,
                    MetadataIngestJobChanged
                );
            }
            ensure!(
                root_epoch.1 % 2 == 0 && root_epoch.0.load(Ordering::Acquire) == root_epoch.1,
                ObservedRootChanged
            );
            Self::upsert_verified_local_content_tx(&tx, content, crate::store::unix_ms())?;
            Self::update_transfer_media_on_connection(&tx, &content.file_hash, media)?;
            for root in roots {
                ensure!(
                    Self::admit_local_path_on_connection(
                        &tx,
                        &root.root,
                        &content.path,
                        &root.relative,
                        &content.fingerprint,
                        false
                    )?,
                    "required ingest root is no longer eligible"
                );
            }
            if let Some(content_type) = index_type {
                Self::upsert_indexed_file_on_connection(
                    &tx,
                    &MetadataIndexedFile {
                        ed2k_hash: content.file_hash.clone(),
                        name: content.display_name.clone(),
                        size_bytes: content.file_size,
                        content_type: content_type.to_owned(),
                        availability_score: 1,
                    },
                    MetadataIndexedFileOrigin::LocalShare,
                )?;
            }
            if with_recovery {
                let mut save = tx.savepoint()?;
                match crate::aich_recovery_store::write_set(
                    &save,
                    &recovery.root,
                    recovery.size,
                    &recovery.parts,
                    &recovery.part_roots,
                ) {
                    Ok(()) => save.commit()?,
                    Err(error) => {
                        recovery_error = Some(error);
                        if save.is_autocommit() {
                            drop(save);
                            drop(tx);
                            drop(conn);
                            #[cfg(test)]
                            if let Some((reached, release)) =
                                FALLBACK_GATE.with(|gate| gate.borrow_mut().take())
                            {
                                reached.send(()).expect("fallback test receiver");
                                release.recv().expect("fallback test release");
                            }
                            continue;
                        }
                        save.rollback()?;
                    }
                }
            }
            let mut projections = Vec::with_capacity(2);
            if let Some(old) = expected.filter(|old| old.file_hash != content.file_hash) {
                projections.push(project(&tx, &old.file_hash)?);
            }
            projections.push(project(&tx, &content.file_hash)?);
            ensure!(
                root_epoch.0.load(Ordering::Acquire) == root_epoch.1,
                ObservedRootChanged
            );
            tx.commit().map_err(|error| {
                anyhow::Error::new(error).context(MetadataIngestCommitUncertain)
            })?;
            return Ok(MetadataIngestCommit {
                projections,
                recovery_error,
            });
        }
        unreachable!("fallback transaction does not write recovery")
    }
}

#[cfg(test)]
mod tests;
