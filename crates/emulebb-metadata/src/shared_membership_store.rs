//! Root membership is the durable sharing intent for verified local paths.

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{MetadataStore, NativeFileFingerprint, NativePath, store::unix_ms};

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
        let conn = self.connection()?;
        let found = conn.query_row(
            "SELECT shared_directory_roots.id, local_file_instances.path_id,
                    local_file_instances.verified_fingerprint
             FROM shared_directory_roots
             JOIN local_paths root_paths ON root_paths.id = shared_directory_roots.path_id
             JOIN local_paths file_paths ON file_paths.platform = root_paths.platform
             JOIN local_file_instances ON local_file_instances.path_id = file_paths.id
             WHERE root_paths.platform = ?1 AND root_paths.native_path = ?2
               AND file_paths.native_path = ?3
               AND shared_directory_roots.enabled = 1
               AND shared_directory_roots.deleted_at_ms IS NULL
               AND shared_directory_roots.accessible = 1
               AND shared_directory_roots.shareable = 1",
            params![
                NativePath::platform(),
                native_root.storage_bytes(),
                native_path.storage_bytes()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        );
        let (root_id, path_id, stored) = match found {
            Ok(found) => found,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !NativeFileFingerprint::from_storage_bytes(&stored)
            .is_some_and(|fingerprint| fingerprint.safely_matches(current))
        {
            return Ok(false);
        }
        let now = unix_ms();
        conn.execute(
            "INSERT INTO shared_file_memberships(
                root_id, path_id, relative_path, first_seen_at_ms, last_seen_at_ms, removed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?4, NULL)
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
        conn.execute(
            "INSERT OR REPLACE INTO temp.session_verified_local_paths(path_id, verified_fingerprint)
             VALUES (?1, ?2)",
            params![path_id, stored],
        )?;
        Ok(true)
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

    /// Commit one successful full scan of a root. The caller supplies only
    /// scanned local paths with their live fingerprints; a failed or incomplete
    /// scan must never call this. Only safely matched cache entries are admitted.
    pub fn replace_root_memberships(
        &self,
        root: &Path,
        paths: &[(PathBuf, PathBuf, NativeFileFingerprint)],
    ) -> Result<()> {
        let native_root = NativePath::from(root);
        let mut conn = self.connection()?;
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
            ensure!(
                !relative.as_os_str().is_empty()
                    && !relative.is_absolute()
                    && relative
                        .components()
                        .all(|part| matches!(part, std::path::Component::Normal(_))),
                "shared member must have a safe relative path"
            );
            let native_path = NativePath::from(path.as_path());
            let cached: (i64, Vec<u8>) = match tx.query_row(
                "SELECT local_file_instances.path_id, local_file_instances.verified_fingerprint
                 FROM local_file_instances
                 JOIN local_paths ON local_paths.id = local_file_instances.path_id
                 WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2",
                params![NativePath::platform(), native_path.storage_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
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
            let path_id = cached.0;
            tx.execute(
                "INSERT OR IGNORE INTO temp.scanned_membership_paths VALUES(?1)",
                [path_id],
            )?;
            tx.execute(
                "INSERT INTO shared_file_memberships(
                    root_id, path_id, relative_path, first_seen_at_ms, last_seen_at_ms, removed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?4, NULL)
                 ON CONFLICT(root_id, path_id) DO UPDATE SET
                    relative_path = excluded.relative_path,
                    last_seen_at_ms = excluded.last_seen_at_ms,
                    removed_at_ms = NULL",
                params![
                    root_id,
                    path_id,
                    NativePath::from(relative.as_path()).display_path(),
                    now
                ],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO temp.session_verified_local_paths(path_id, verified_fingerprint)
                 VALUES (?1, ?2)",
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
            "SELECT count(DISTINCT local_file_instances.known_file_id)
             FROM shared_file_memberships
             JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
             JOIN local_file_instances ON local_file_instances.path_id = shared_file_memberships.path_id
             WHERE shared_file_memberships.removed_at_ms IS NULL
               AND shared_directory_roots.enabled = 1
               AND shared_directory_roots.deleted_at_ms IS NULL
               AND shared_directory_roots.accessible = 1
               AND shared_directory_roots.shareable = 1",
            [], |row| row.get(0),
        )?;
        Ok(usize::try_from(count)?)
    }
}

#[cfg(test)]
mod tests;
