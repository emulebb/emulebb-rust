//! Root membership is the durable sharing intent for verified local paths.

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{MetadataStore, NativeFileFingerprint, NativePath, store::unix_ms};

#[derive(Debug)]
pub struct ObservedRootChanged;
impl std::fmt::Display for ObservedRootChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("observed root changed")
    }
}
impl std::error::Error for ObservedRootChanged {}

impl MetadataStore {
    pub fn shared_root_last_scan_ms(&self, root: &Path) -> Result<Option<i64>> {
        let native = NativePath::from(root);
        self.connection()?
            .query_row(
                "SELECT shared_directory_roots.last_scanned_at_ms
                 FROM shared_directory_roots
                 JOIN local_paths ON local_paths.id = shared_directory_roots.path_id
                 WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2",
                params![NativePath::platform(), native.storage_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(Into::into)
    }

    /// Admit one newly verified path from a live watcher without replacing the
    /// rest of the root's membership set.
    pub fn admit_local_path_to_root(
        &self,
        root: &Path,
        path: &Path,
        relative: &Path,
        current: &NativeFileFingerprint,
    ) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let admitted =
            Self::admit_local_path_on_connection(&tx, root, path, relative, current, false)?;
        tx.commit()?;
        Ok(admitted)
    }

    pub(crate) fn admit_local_path_on_connection(
        tx: &rusqlite::Connection,
        root: &Path,
        path: &Path,
        relative: &Path,
        current: &NativeFileFingerprint,
        observed_root: bool,
    ) -> Result<bool> {
        ensure!(
            !relative.as_os_str().is_empty()
                && !relative.is_absolute()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "shared member must have a safe relative path"
        );
        let native_root = NativePath::from(root);
        let native_path = NativePath::from(path);
        if crate::delivery_exclusion_store::identity_is_excluded(tx, current.identity)?
            || crate::delivery_exclusion_store::is_excluded(tx, path)?
        {
            return Ok(false);
        }
        let found = tx.query_row(
            "SELECT shared_directory_roots.id, local_file_instances.path_id,
                    local_file_instances.verified_fingerprint,local_file_instances.secondary_identity
             FROM shared_directory_roots
             JOIN local_paths root_paths ON root_paths.id = shared_directory_roots.path_id
             JOIN local_paths file_paths ON file_paths.platform = root_paths.platform
             JOIN local_file_instances ON local_file_instances.path_id = file_paths.id
             WHERE root_paths.platform = ?1 AND root_paths.native_path = ?2
               AND file_paths.native_path = ?3
               AND shared_directory_roots.enabled = 1
               AND shared_directory_roots.deleted_at_ms IS NULL
               AND (?4 = 1 OR shared_directory_roots.accessible = 1)
               AND shared_directory_roots.shareable = 1",
            params![
                NativePath::platform(),
                native_root.storage_bytes(),
                native_path.storage_bytes(),
                i64::from(observed_root)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,crate::native_file::optional_identity_from_row(row,3)?,
                ))
            },
        );
        let (root_id, path_id, stored, secondary) = match found {
            Ok(found) => found,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !NativeFileFingerprint::from_storage_bytes(&stored)
            .is_some_and(|fingerprint| fingerprint.safely_matches(current))
        {
            return Ok(false);
        }
        let evidence = crate::NativeFileIdentityEvidence::new(current.identity, secondary)?;
        if crate::delivery_exclusion_store::evidence_is_excluded(tx, evidence)? {
            return Ok(false);
        }
        let now = unix_ms();
        if observed_root {
            tx.execute(
                "UPDATE shared_directory_roots SET accessible=1 WHERE id=?1",
                [root_id],
            )?;
            tx.execute("UPDATE shared_directory_root_origins SET accessible=1 WHERE root_id=?1 AND shareable=1", [root_id])?;
        }
        tx.execute(
            "INSERT INTO shared_file_memberships(
                root_id, path_id, known_file_id, relative_path, first_seen_at_ms, last_seen_at_ms, removed_at_ms
             ) VALUES (?1, ?2, (SELECT known_file_id FROM local_file_instances WHERE path_id=?2), ?3, ?4, ?4, NULL)
             ON CONFLICT(root_id, path_id) DO UPDATE SET
                relative_path = excluded.relative_path,
                last_seen_at_ms = excluded.last_seen_at_ms,
                removed_at_ms = NULL",
            params![
                root_id,
                path_id,
                NativePath::from(relative).display_path(),
                now
            ],
        )?;
        // WHY: replacing unchanged evidence fires the projection's INSERT
        // trigger and makes a later read rebuild otherwise unchanged content.
        tx.execute(
            "INSERT INTO temp.session_verified_local_paths(path_id, verified_fingerprint)
             VALUES (?1, ?2)
             ON CONFLICT(path_id) DO UPDATE SET verified_fingerprint = excluded.verified_fingerprint
             WHERE session_verified_local_paths.verified_fingerprint IS NOT excluded.verified_fingerprint",
            params![path_id, stored],
        )?;
        Ok(true)
    }

    /// Atomically admit a particular verified copy and prepare its bounded
    /// catalog projection before committing the membership change.
    pub fn admit_shared_path_with_projection(
        &self,
        root: &Path,
        path: &Path,
        relative: &Path,
        current: &NativeFileFingerprint,
        file_hash: &str,
        observed_root: Option<(&std::sync::atomic::AtomicU64, u64)>,
    ) -> Result<
        Option<(
            crate::MetadataTransferCatalogEntry,
            Option<crate::MetadataPartialShare>,
        )>,
    > {
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        if !Self::admit_local_path_on_connection(
            &tx,
            root,
            path,
            relative,
            current,
            observed_root.is_some(),
        )? {
            return Ok(None);
        }
        let native = NativePath::from(path);
        let hash = crate::store::decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let sql = format!(
            "SELECT {} FROM local_paths
             JOIN local_file_instances ON local_file_instances.path_id=local_paths.id
             JOIN known_files ON known_files.id=local_file_instances.known_file_id
             JOIN verified_local_content ON verified_local_content.known_file_id=known_files.id
             WHERE local_paths.platform=?1 AND local_paths.native_path=?2 AND known_files.ed2k_hash=?3
               AND length(CAST(verified_local_content.upload_priority AS BLOB))<=65536
               AND length(CAST(verified_local_content.comment AS BLOB))<=65536
               AND length(CAST(known_files.media_artist AS BLOB))<=65536
               AND length(CAST(known_files.media_album AS BLOB))<=65536
               AND length(CAST(known_files.media_title AS BLOB))<=65536
               AND length(CAST(known_files.media_codec AS BLOB))<=65536",
            crate::local_catalog::COLUMNS
        );
        let entry = tx.query_row(
            &sql,
            params![NativePath::platform(), native.storage_bytes(), hash],
            crate::local_catalog::catalog_entry,
        )?;
        let partial = Self::partial_share_on_connection(&tx, file_hash)?;
        if let Some((epoch, expected)) = observed_root {
            if epoch.load(std::sync::atomic::Ordering::Acquire) != expected {
                return Err(ObservedRootChanged.into());
            }
        }
        tx.commit()?;
        Ok(Some((entry, partial)))
    }

    /// Whether a verified path has ever been governed by a shared root.
    pub fn local_file_has_root_membership(&self, path: &Path) -> Result<bool> {
        let native = NativePath::from(path);
        let exists: i64 = self.connection()?.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM shared_file_memberships
                JOIN local_paths ON local_paths.id = shared_file_memberships.path_id
                WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2
             )",
            params![NativePath::platform(), native.storage_bytes()],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }

    /// Withdraw a changed local path from every root while retaining its
    /// path-to-hash cache for later reconciliation.
    pub fn withdraw_local_file_path(&self, path: &Path) -> Result<usize> {
        let native = NativePath::from(path);
        let changed = self.connection()?.execute(
            "UPDATE shared_file_memberships SET removed_at_ms = ?3
             WHERE path_id = (SELECT id FROM local_paths WHERE platform = ?1 AND native_path = ?2)
               AND removed_at_ms IS NULL",
            params![NativePath::platform(), native.storage_bytes(), unix_ms()],
        )?;
        Ok(changed)
    }

    /// Withdraw memberships only while the path still names the observed
    /// verified generation. A watcher may replace and re-admit it between an
    /// upload's snapshot and its failed file open.
    pub fn withdraw_local_file_path_if_verified(
        &self,
        path: &Path,
        file_hash: &str,
        expected: &NativeFileFingerprint,
    ) -> Result<usize> {
        let native = NativePath::from(path);
        let hash = crate::store::decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let changed = self.connection()?.execute(
            "UPDATE shared_file_memberships SET removed_at_ms = ?5
             WHERE path_id IN (
                 SELECT local_file_instances.path_id
                 FROM local_file_instances
                 JOIN local_paths ON local_paths.id = local_file_instances.path_id
                 JOIN known_files ON known_files.id = local_file_instances.known_file_id
                 WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2
                   AND known_files.ed2k_hash = ?3
                   AND local_file_instances.verified_fingerprint = ?4
             ) AND removed_at_ms IS NULL",
            params![
                NativePath::platform(),
                native.storage_bytes(),
                hash,
                expected.storage_bytes(),
                unix_ms()
            ],
        )?;
        Ok(changed)
    }

    /// Withdraw the observed path and validate its bounded catalog projection
    /// in the same transaction, so projection failures roll the mutation back.
    pub fn withdraw_shared_path_with_projection(
        &self,
        path: &Path,
        file_hash: &str,
        expected: Option<&NativeFileFingerprint>,
    ) -> Result<(usize, bool, Option<crate::MetadataPartialShare>)> {
        let native = NativePath::from(path);
        let hash = crate::store::decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let fingerprint = expected.map(NativeFileFingerprint::storage_bytes);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE shared_file_memberships SET removed_at_ms=?5 WHERE path_id IN (SELECT i.path_id FROM local_file_instances i JOIN local_paths p ON p.id=i.path_id JOIN known_files k ON k.id=i.known_file_id WHERE p.platform=?1 AND p.native_path=?2 AND k.ed2k_hash=?3 AND (?4 IS NULL OR i.verified_fingerprint=?4)) AND removed_at_ms IS NULL",
            params![NativePath::platform(), native.storage_bytes(), hash, fingerprint, unix_ms()],
        )?;
        let complete = tx.query_row(
            crate::local_catalog::VERIFIED_SHARE_EXISTS_SQL,
            [&hash],
            |row| row.get::<_, bool>(0),
        )?;
        let partial = Self::partial_share_on_connection(&tx, file_hash)?;
        tx.commit()?;
        Ok((changed, complete, partial))
    }

    /// Re-read a bounded projection without replaying a previously committed mutation.
    pub fn shared_path_projection(
        &self,
        file_hash: &str,
    ) -> Result<(bool, Option<crate::MetadataPartialShare>)> {
        let hash = crate::store::decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let complete = tx.query_row(
            crate::local_catalog::VERIFIED_SHARE_EXISTS_SQL,
            [&hash],
            |row| row.get::<_, bool>(0),
        )?;
        let partial = Self::partial_share_on_connection(&tx, file_hash)?;
        tx.commit()?;
        Ok((complete, partial))
    }

    /// Commit one successful full scan of a root. The caller supplies only
    /// scanned local paths with their live fingerprints; a failed or incomplete
    /// scan must never call this. Only safely matched cache entries are admitted.
    pub fn replace_root_memberships(
        &self,
        root: &Path,
        paths: &[(PathBuf, PathBuf, NativeFileFingerprint)],
    ) -> Result<()> {
        let started = std::time::Instant::now();
        tracing::debug!(
            phase = "connectionWait",
            paths = paths.len(),
            "root admission"
        );
        let native_root = NativePath::from(root);
        let mut conn = self.connection()?;
        tracing::debug!(
            phase = "connectionAcquired",
            elapsed_ms = started.elapsed().as_millis(),
            "root admission"
        );
        let tx = conn.transaction()?;
        let root_id: i64 = tx.query_row(
            "SELECT shared_directory_roots.id
             FROM shared_directory_roots
             JOIN local_paths ON local_paths.id = shared_directory_roots.path_id
             WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2
               AND shared_directory_roots.enabled = 1
               AND shared_directory_roots.deleted_at_ms IS NULL",
            params![NativePath::platform(), native_root.storage_bytes()],
            |row| row.get(0),
        )?;
        let now = unix_ms();
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS scanned_membership_paths(path_id INTEGER PRIMARY KEY);
            DELETE FROM temp.scanned_membership_paths;",
        )?;
        for (path, relative, current_fingerprint) in paths {
            if crate::delivery_exclusion_store::identity_is_excluded(
                &tx,
                current_fingerprint.identity,
            )? || crate::delivery_exclusion_store::is_excluded(&tx, path)?
            {
                continue;
            }
            ensure!(
                !relative.as_os_str().is_empty()
                    && !relative.is_absolute()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "shared member must have a safe relative path"
            );
            let native_path = NativePath::from(path.as_path());
            // WHY: one atomic scan repeats these point operations for every
            // path. Reuse compiled statements while holding the metadata lock.
            let cached: (i64, Vec<u8>,Option<crate::NativeFileIdentity>) = match tx.prepare_cached(
                "SELECT local_file_instances.path_id, local_file_instances.verified_fingerprint,local_file_instances.secondary_identity
                 FROM local_file_instances
                 JOIN local_paths ON local_paths.id = local_file_instances.path_id
                 WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2")?.query_row(
                params![NativePath::platform(), native_path.storage_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?,crate::native_file::optional_identity_from_row(row,2)?)),
            ) {
                Ok(cached) => cached,
                Err(rusqlite::Error::QueryReturnedNoRows) => continue,
                Err(error) => return Err(error.into()),
            };
            let Some(stored_fingerprint) = NativeFileFingerprint::from_storage_bytes(&cached.1)
            else {
                continue;
            };
            if !stored_fingerprint.safely_matches(current_fingerprint) {
                continue;
            }
            let evidence =
                crate::NativeFileIdentityEvidence::new(current_fingerprint.identity, cached.2)?;
            if crate::delivery_exclusion_store::evidence_is_excluded(&tx, evidence)? {
                continue;
            }
            let path_id = cached.0;
            tx.prepare_cached("INSERT OR IGNORE INTO temp.scanned_membership_paths VALUES(?1)")?
                .execute([path_id])?;
            tx.prepare_cached(
                "INSERT INTO shared_file_memberships(
                    root_id, path_id, known_file_id, relative_path, first_seen_at_ms, last_seen_at_ms, removed_at_ms
                 ) VALUES (?1, ?2, (SELECT known_file_id FROM local_file_instances WHERE path_id=?2), ?3, ?4, ?4, NULL)
                 ON CONFLICT(root_id, path_id) DO UPDATE SET
                    relative_path = excluded.relative_path,
                    last_seen_at_ms = excluded.last_seen_at_ms,
                    removed_at_ms = NULL")?.execute(
                params![
                    root_id,
                    path_id,
                    NativePath::from(relative.as_path()).display_path(),
                    now
                ],
            )?;
            tx.prepare_cached(
                "INSERT INTO temp.session_verified_local_paths(path_id, verified_fingerprint)
                 VALUES (?1, ?2)
                 ON CONFLICT(path_id) DO UPDATE SET verified_fingerprint = excluded.verified_fingerprint
                 WHERE session_verified_local_paths.verified_fingerprint IS NOT excluded.verified_fingerprint")?.execute(
                params![path_id, cached.1],
            )?;
        }
        tx.execute(
            "UPDATE shared_file_memberships SET removed_at_ms = ?2
            WHERE root_id = ?1 AND removed_at_ms IS NULL
              AND path_id NOT IN (SELECT path_id FROM temp.scanned_membership_paths)",
            params![root_id, now],
        )?;
        tx.execute("DELETE FROM temp.scanned_membership_paths", [])?;
        tracing::debug!(
            phase = "membershipsBound",
            elapsed_ms = started.elapsed().as_millis(),
            "root admission"
        );
        tx.execute(
            "UPDATE shared_directory_roots SET accessible = 1, last_scanned_at_ms = ?2
             WHERE id = ?1",
            params![root_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Withdraw a root immediately without losing cached path/hash identities.
    pub fn set_shared_root_accessible(&self, root: &Path, accessible: bool) -> Result<bool> {
        let native = NativePath::from(root);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let changed = tx.execute(
            "UPDATE shared_directory_roots SET accessible = ?3
             WHERE path_id = (SELECT id FROM local_paths WHERE platform = ?1 AND native_path = ?2)
               AND enabled = 1 AND deleted_at_ms IS NULL AND accessible != ?3",
            params![
                NativePath::platform(),
                native.storage_bytes(),
                i64::from(accessible)
            ],
        )?;
        let removed = if accessible {
            0
        } else {
            tx.execute(
                "UPDATE shared_file_memberships SET removed_at_ms = ?3
                 WHERE root_id = (
                     SELECT shared_directory_roots.id FROM shared_directory_roots
                     JOIN local_paths ON local_paths.id = shared_directory_roots.path_id
                     WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2
                 ) AND removed_at_ms IS NULL",
                params![NativePath::platform(), native.storage_bytes(), unix_ms()],
            )?
        };
        tx.commit()?;
        Ok(changed != 0 || removed != 0)
    }

    /// Count distinct complete files eligible by persisted root membership.
    /// The runtime still checks the open file's fingerprint before serving.
    pub fn active_shared_content_count(&self) -> Result<usize> {
        let count: i64 = self.connection()?.query_row(
            concat!("SELECT count(DISTINCT local_file_instances.known_file_id)
             FROM shared_file_memberships
             JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
             JOIN local_file_instances ON local_file_instances.path_id = shared_file_memberships.path_id
             WHERE shared_file_memberships.removed_at_ms IS NULL
               AND ", crate::local_catalog::unexcluded_identity_sql!("local_file_instances"), "
               AND shared_directory_roots.enabled = 1
               AND shared_directory_roots.deleted_at_ms IS NULL
               AND shared_directory_roots.accessible = 1
               AND shared_directory_roots.shareable = 1"),
            [], |row| row.get(0),
        )?;
        Ok(usize::try_from(count)?)
    }
}

#[cfg(test)]
mod tests;
