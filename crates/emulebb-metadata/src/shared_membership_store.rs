//! Root membership is the durable sharing intent for verified local paths.

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use rusqlite::params;

use crate::{MetadataStore, NativeFileFingerprint, NativePath, store::unix_ms};

impl MetadataStore {
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
                root_id, path_id, relative_path, first_seen_ms, last_seen_ms, removed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?4, NULL)
             ON CONFLICT(root_id, path_id) DO UPDATE SET
                relative_path = excluded.relative_path,
                last_seen_ms = excluded.last_seen_ms,
                removed_at_ms = NULL",
            params![
                root_id,
                path_id,
                NativePath::from(relative).display_path(),
                now
            ],
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
        tx.execute(
            "UPDATE shared_file_memberships SET removed_at_ms = ?2
             WHERE root_id = ?1 AND removed_at_ms IS NULL",
            params![root_id, now],
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
                "INSERT INTO shared_file_memberships(
                    root_id, path_id, relative_path, first_seen_ms, last_seen_ms, removed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?4, NULL)
                 ON CONFLICT(root_id, path_id) DO UPDATE SET
                    relative_path = excluded.relative_path,
                    last_seen_ms = excluded.last_seen_ms,
                    removed_at_ms = NULL",
                params![
                    root_id,
                    path_id,
                    NativePath::from(relative.as_path()).display_path(),
                    now
                ],
            )?;
        }
        tx.execute(
            "UPDATE shared_directory_roots SET accessible = 1, last_scan_ms = ?2
             WHERE id = ?1",
            params![root_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Withdraw a root immediately without losing cached path/hash identities.
    pub fn set_shared_root_accessible(&self, root: &Path, accessible: bool) -> Result<bool> {
        let native = NativePath::from(root);
        let changed = self.connection()?.execute(
            "UPDATE shared_directory_roots SET accessible = ?3
             WHERE path_id = (SELECT id FROM local_paths WHERE platform = ?1 AND native_path = ?2)
               AND enabled = 1 AND deleted_at_ms IS NULL",
            params![
                NativePath::platform(),
                native.storage_bytes(),
                i64::from(accessible)
            ],
        )?;
        Ok(changed != 0)
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
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MetadataSharedDirectoryRoot, NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp,
    };

    #[test]
    fn overlapping_roots_withdraw_independently_and_keep_hash_cache() {
        let mut store = MetadataStore::in_memory().unwrap();
        let root = std::env::temp_dir().join("emulebb-membership-root");
        let nested = root.join("nested");
        let file = nested.join("Sample.bin");
        let roots = [&root, &nested].map(|path| MetadataSharedDirectoryRoot {
            path: path.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        });
        store.replace_shared_directory_roots(&roots).unwrap();
        let hash = "00112233445566778899aabbccddeeff";
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO known_files(ed2k_hash, size_bytes, display_name,
                first_seen_ms, last_seen_ms, updated_at_ms)
             VALUES (?1, 32, 'Sample.bin', 1, 1, 1)",
                params![crate::store::decode_fixed_hex(hash, 16, "ED2K hash").unwrap()],
            )
            .unwrap();
        let fingerprint = NativeFileFingerprint {
            identity: NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            size_bytes: 32,
            modified: NativeFileTimestamp::new(1_700_000_000, 123_456_789).unwrap(),
            changed: Some(NativeFileTimestamp::new(1_700_000_001, 234_567_890).unwrap()),
        };
        store
            .upsert_local_file_instance(&file, hash, &fingerprint)
            .unwrap();
        let verified_file = (
            file.clone(),
            PathBuf::from("nested/Sample.bin"),
            fingerprint.clone(),
        );
        let nested_file = (
            file.clone(),
            PathBuf::from("Sample.bin"),
            fingerprint.clone(),
        );
        store
            .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
            .unwrap();
        store
            .replace_root_memberships(&nested, std::slice::from_ref(&nested_file))
            .unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 1);
        assert_eq!(store.withdraw_local_file_path(&file).unwrap(), 2);
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
        assert!(store.local_file_instance(&file).unwrap().is_some());
        store
            .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
            .unwrap();
        store
            .replace_root_memberships(&nested, std::slice::from_ref(&nested_file))
            .unwrap();
        let page = store.active_local_share_page(None, 10).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].file_hash, hash);
        assert_eq!(
            store.active_local_file_by_hash(hash).unwrap().unwrap().path,
            file
        );
        assert!(
            store
                .active_local_share_page(Some(hash), 10)
                .unwrap()
                .is_empty()
        );
        store.set_shared_root_accessible(&root, false).unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 1);
        store.set_shared_root_accessible(&nested, false).unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
        assert!(store.active_local_share_page(None, 10).unwrap().is_empty());
        assert!(store.active_local_file_by_hash(hash).unwrap().is_none());
        assert!(store.local_file_instance(&file).unwrap().is_some());
        store
            .replace_root_memberships(&root, std::slice::from_ref(&verified_file))
            .unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 1);
        let mut changed = fingerprint.clone();
        changed.size_bytes = 33;
        store
            .replace_root_memberships(
                &root,
                &[(file.clone(), PathBuf::from("nested/Sample.bin"), changed)],
            )
            .unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
        store
            .replace_root_memberships(&root, &[verified_file])
            .unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 1);
        store.replace_root_memberships(&root, &[]).unwrap();
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
    }
}
