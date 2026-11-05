//! Durable path-to-content identities, independent of download jobs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};

use crate::{
    MetadataStore, NativeFileFingerprint, NativePath,
    native_path::path_from_row,
    store::{decode_fixed_hex, unix_ms, upsert_local_path},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLocalFileInstance {
    pub path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub verified_fingerprint: NativeFileFingerprint,
}

/// Hashsets produced by a full, stable read of a local file.
#[derive(Debug, Clone)]
pub struct MetadataVerifiedLocalContent {
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub part_size: u64,
    pub md4_hashset: Vec<String>,
    pub aich_root: String,
    pub aich_hashset: Vec<String>,
    pub path: PathBuf,
    pub fingerprint: NativeFileFingerprint,
}

impl MetadataStore {
    /// Retire a legacy share-in-place transfer only after a verified local
    /// instance and active root membership independently authorize the file.
    pub fn retire_synthetic_local_transfer(&self, file_hash: &str) -> Result<bool> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let changed = self.connection()?.execute(
            "DELETE FROM transfers WHERE id IN (
                SELECT transfers.id FROM transfers
                JOIN known_files ON known_files.id = transfers.known_file_id
                WHERE known_files.ed2k_hash = ?1
                  AND transfers.source_path_id IS NOT NULL
                  AND transfers.delete_requested_at_ms IS NULL
                  AND EXISTS (
                    SELECT 1 FROM local_file_instances
                    JOIN shared_file_memberships ON shared_file_memberships.path_id = local_file_instances.path_id
                    JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
                    WHERE local_file_instances.known_file_id = known_files.id
                      AND shared_file_memberships.removed_at_ms IS NULL
                      AND shared_directory_roots.enabled = 1
                      AND shared_directory_roots.deleted_at_ms IS NULL
                      AND shared_directory_roots.accessible = 1
                  )
             )",
            params![hash],
        )?;
        Ok(changed != 0)
    }

    /// Store verified local content and its path atomically, without a download
    /// transfer. Existing content-level display metadata remains stable when a
    /// second path to the same hash is discovered.
    pub fn upsert_verified_local_content(
        &self,
        content: &MetadataVerifiedLocalContent,
    ) -> Result<()> {
        ensure!(
            content.path.is_absolute(),
            "local file path must be absolute"
        );
        ensure!(
            content.file_size > 0 && content.part_size > 0,
            "local content geometry is invalid"
        );
        ensure!(
            content.file_size == content.fingerprint.size_bytes,
            "local content fingerprint size differs"
        );
        ensure!(
            !content.display_name.trim().is_empty(),
            "local content name is empty"
        );
        let hash = decode_fixed_hex(&content.file_hash, 16, "ED2K hash")?;
        let aich_root = decode_fixed_hex(&content.aich_root, 20, "AICH root")?;
        let size = i64::try_from(content.file_size)?;
        let part_size = i64::try_from(content.part_size)?;
        let part_count = i64::try_from(content.md4_hashset.len())?;
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO known_files(
                ed2k_hash, size_bytes, display_name, part_size, part_count,
                completed, md4_hashset_acquired, aich_hashset_acquired, aich_root,
                first_seen_ms, last_seen_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 1, ?6, ?7, ?7, ?7)
             ON CONFLICT(ed2k_hash) DO UPDATE SET
                last_seen_ms = excluded.last_seen_ms,
                updated_at_ms = excluded.updated_at_ms",
            params![
                hash,
                size,
                content.display_name,
                part_size,
                part_count,
                aich_root,
                now
            ],
        )?;
        let (known_file_id, stored_size): (i64, i64) = tx.query_row(
            "SELECT id, size_bytes FROM known_files WHERE ed2k_hash = ?1",
            params![hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        ensure!(
            stored_size == size,
            "ED2K identity has conflicting file size"
        );
        tx.execute(
            "INSERT INTO known_file_origins(
                known_file_id, origin, size_bytes, first_seen_ms, last_seen_ms
             ) VALUES (?1, 'local_share', ?2, ?3, ?3)
             ON CONFLICT(known_file_id, origin) DO UPDATE SET
                last_seen_ms = excluded.last_seen_ms",
            params![known_file_id, size, now],
        )?;
        tx.execute(
            "DELETE FROM ed2k_part_hashes WHERE known_file_id = ?1",
            params![known_file_id],
        )?;
        tx.execute(
            "DELETE FROM aich_part_hashes WHERE known_file_id = ?1",
            params![known_file_id],
        )?;
        for (part_index, part_hash) in content.md4_hashset.iter().enumerate() {
            tx.execute(
                "INSERT INTO ed2k_part_hashes(known_file_id, part_index, md4_hash) VALUES (?1, ?2, ?3)",
                params![known_file_id, i64::try_from(part_index)?, decode_fixed_hex(part_hash, 16, "MD4 part hash")?],
            )?;
        }
        for (part_index, part_hash) in content.aich_hashset.iter().enumerate() {
            tx.execute(
                "INSERT INTO aich_part_hashes(known_file_id, part_index, aich_hash) VALUES (?1, ?2, ?3)",
                params![known_file_id, i64::try_from(part_index)?, decode_fixed_hex(part_hash, 20, "AICH part hash")?],
            )?;
        }
        let path_id = upsert_local_path(&tx, &content.path)?;
        tx.execute(
            "INSERT INTO local_file_instances(
                path_id, known_file_id, file_size, native_identity,
                verified_fingerprint, verified_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(path_id) DO UPDATE SET
                known_file_id = excluded.known_file_id,
                file_size = excluded.file_size,
                native_identity = excluded.native_identity,
                verified_fingerprint = excluded.verified_fingerprint,
                verified_at_ms = excluded.verified_at_ms",
            params![
                path_id,
                known_file_id,
                size,
                content.fingerprint.identity.storage_bytes(),
                content.fingerprint.storage_bytes(),
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Cache a content identity after the file bytes have been verified.
    /// This record alone never authorizes serving or publication.
    pub fn upsert_local_file_instance(
        &self,
        path: &Path,
        file_hash: &str,
        fingerprint: &NativeFileFingerprint,
    ) -> Result<()> {
        ensure!(path.is_absolute(), "local file path must be absolute");
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let (known_file_id, known_size): (i64, i64) = tx
            .query_row(
                "SELECT id, size_bytes FROM known_files WHERE ed2k_hash = ?1",
                params![hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .with_context(|| "verified content is absent from known_files")?;
        ensure!(
            known_size >= 0 && known_size as u64 == fingerprint.size_bytes,
            "verified local file size differs from known content"
        );
        let path_id = upsert_local_path(&tx, path)?;
        tx.execute(
            "INSERT INTO local_file_instances(path_id, known_file_id, file_size, native_identity, verified_fingerprint, verified_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(path_id) DO UPDATE SET
                 known_file_id = excluded.known_file_id,
                 file_size = excluded.file_size,
                 native_identity = excluded.native_identity,
                 verified_fingerprint = excluded.verified_fingerprint,
                 verified_at_ms = excluded.verified_at_ms",
            params![path_id, known_file_id, known_size, fingerprint.identity.storage_bytes(), fingerprint.storage_bytes(), unix_ms()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Return a verified cache entry for an exact native path, including one
    /// currently absent from disk. The caller must stat and compare before use.
    pub fn local_file_instance(&self, path: &Path) -> Result<Option<MetadataLocalFileInstance>> {
        let native = NativePath::from(path);
        self.connection()?
            .query_row(
                "SELECT local_paths.platform, local_paths.native_path,
                        lower(hex(known_files.ed2k_hash)), local_file_instances.file_size,
                        local_file_instances.verified_fingerprint
                 FROM local_file_instances
                 JOIN local_paths ON local_paths.id = local_file_instances.path_id
                 JOIN known_files ON known_files.id = local_file_instances.known_file_id
                 WHERE local_paths.platform = ?1 AND local_paths.native_path = ?2",
                params![NativePath::platform(), native.storage_bytes()],
                |row| {
                    let bytes: Vec<u8> = row.get(4)?;
                    let fingerprint = NativeFileFingerprint::from_storage_bytes(&bytes)
                        .ok_or_else(|| {
                            rusqlite::Error::InvalidColumnType(
                                4,
                                "verified_fingerprint".to_string(),
                                rusqlite::types::Type::Blob,
                            )
                        })?;
                    Ok(MetadataLocalFileInstance {
                        path: path_from_row(row, 0, 1)?,
                        file_hash: row.get(2)?,
                        file_size: row.get::<_, i64>(3)? as u64,
                        verified_fingerprint: fingerprint,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Find a verified prior path after a rename or hard link. A matching
    /// native identity alone is insufficient: the full safe fingerprint must
    /// match, and conflicting remembered content identities force a rehash.
    pub fn reusable_local_file_by_identity(
        &self,
        current: &NativeFileFingerprint,
    ) -> Result<Option<MetadataLocalFileInstance>> {
        let size =
            i64::try_from(current.size_bytes).context("local file exceeds SQLite size range")?;
        let conn = self.connection()?;
        let mut statement = conn.prepare(
            "SELECT local_paths.platform, local_paths.native_path,
                    lower(hex(known_files.ed2k_hash)), local_file_instances.file_size,
                    local_file_instances.verified_fingerprint
             FROM local_file_instances
             JOIN local_paths ON local_paths.id = local_file_instances.path_id
             JOIN known_files ON known_files.id = local_file_instances.known_file_id
             WHERE local_file_instances.native_identity = ?1
               AND local_file_instances.file_size = ?2
             ORDER BY local_paths.platform, local_paths.native_path",
        )?;
        let rows = statement.query_map(params![current.identity.storage_bytes(), size], |row| {
            let bytes: Vec<u8> = row.get(4)?;
            let fingerprint =
                NativeFileFingerprint::from_storage_bytes(&bytes).ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        4,
                        "verified_fingerprint".to_string(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
            Ok(MetadataLocalFileInstance {
                path: path_from_row(row, 0, 1)?,
                file_hash: row.get(2)?,
                file_size: row.get::<_, i64>(3)? as u64,
                verified_fingerprint: fingerprint,
            })
        })?;
        let mut chosen: Option<MetadataLocalFileInstance> = None;
        for row in rows {
            let candidate = row?;
            if !candidate.verified_fingerprint.safely_matches(current) {
                continue;
            }
            if chosen
                .as_ref()
                .is_some_and(|prior| prior.file_hash != candidate.file_hash)
            {
                return Ok(None);
            }
            if chosen.is_none() {
                chosen = Some(candidate);
            }
        }
        Ok(chosen)
    }

    /// Page distinct complete-file candidates from eligible roots. The first
    /// native path supplies the network name; callers still validate the open
    /// file fingerprint before serving and withdraw stale candidates.
    pub fn active_local_share_page(
        &self,
        after_hash: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MetadataLocalFileInstance>> {
        let after_hash = after_hash
            .map(|hash| decode_fixed_hex(hash, 16, "ED2K hash"))
            .transpose()?;
        let limit = i64::try_from(limit).context("local share page limit exceeds SQLite range")?;
        let conn = self.connection()?;
        let mut statement = conn.prepare(
            "WITH eligible AS (
                SELECT local_paths.platform, local_paths.native_path,
                       known_files.ed2k_hash, local_file_instances.file_size,
                       local_file_instances.verified_fingerprint,
                       row_number() OVER (
                           PARTITION BY known_files.id
                           ORDER BY local_paths.platform, local_paths.native_path
                       ) AS path_rank
                FROM shared_file_memberships
                JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
                JOIN local_file_instances ON local_file_instances.path_id = shared_file_memberships.path_id
                JOIN local_paths ON local_paths.id = local_file_instances.path_id
                JOIN known_files ON known_files.id = local_file_instances.known_file_id
                WHERE shared_file_memberships.removed_at_ms IS NULL
                  AND (?1 IS NULL OR known_files.ed2k_hash > ?1)
                  AND shared_directory_roots.enabled = 1
                  AND shared_directory_roots.deleted_at_ms IS NULL
                  AND shared_directory_roots.accessible = 1
                  AND shared_directory_roots.shareable = 1
             )
             SELECT platform, native_path, lower(hex(ed2k_hash)), file_size,
                    verified_fingerprint
             FROM eligible
             WHERE path_rank = 1
             ORDER BY ed2k_hash LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_hash, limit], |row| {
            let bytes: Vec<u8> = row.get(4)?;
            let fingerprint =
                NativeFileFingerprint::from_storage_bytes(&bytes).ok_or_else(|| {
                    rusqlite::Error::InvalidColumnType(
                        4,
                        "verified_fingerprint".to_string(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
            Ok(MetadataLocalFileInstance {
                path: path_from_row(row, 0, 1)?,
                file_hash: row.get(2)?,
                file_size: row.get::<_, i64>(3)? as u64,
                verified_fingerprint: fingerprint,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Resolve one currently eligible complete-file path for upload. The
    /// caller must validate this fingerprint against the opened file handle.
    pub fn active_local_file_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataLocalFileInstance>> {
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        self.connection()?
            .query_row(
                "SELECT local_paths.platform, local_paths.native_path,
                        lower(hex(known_files.ed2k_hash)), local_file_instances.file_size,
                        local_file_instances.verified_fingerprint
                 FROM local_file_instances
                 JOIN local_paths ON local_paths.id = local_file_instances.path_id
                 JOIN known_files ON known_files.id = local_file_instances.known_file_id
                 JOIN shared_file_memberships ON shared_file_memberships.path_id = local_file_instances.path_id
                 JOIN shared_directory_roots ON shared_directory_roots.id = shared_file_memberships.root_id
                 WHERE known_files.ed2k_hash = ?1
                   AND shared_file_memberships.removed_at_ms IS NULL
                   AND shared_directory_roots.enabled = 1
                   AND shared_directory_roots.deleted_at_ms IS NULL
                   AND shared_directory_roots.accessible = 1
                   AND shared_directory_roots.shareable = 1
                 ORDER BY local_paths.platform, local_paths.native_path LIMIT 1",
                params![hash],
                |row| {
                    let bytes: Vec<u8> = row.get(4)?;
                    let fingerprint = NativeFileFingerprint::from_storage_bytes(&bytes)
                        .ok_or_else(|| rusqlite::Error::InvalidColumnType(
                            4, "verified_fingerprint".to_string(), rusqlite::types::Type::Blob,
                        ))?;
                    Ok(MetadataLocalFileInstance {
                        path: path_from_row(row, 0, 1)?,
                        file_hash: row.get(2)?,
                        file_size: row.get::<_, i64>(3)? as u64,
                        verified_fingerprint: fingerprint,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Read hashsets and the first eligible verified path without consulting
    /// download transfers. Used to hydrate complete-file protocol responses.
    pub fn active_local_content_by_hash(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataVerifiedLocalContent>> {
        let Some(instance) = self.active_local_file_by_hash(file_hash)? else {
            return Ok(None);
        };
        let hash = decode_fixed_hex(file_hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let (name, size, part_size, aich_root): (String, i64, Option<i64>, Option<String>) = conn
            .query_row(
            "SELECT display_name, size_bytes, part_size,
                        CASE WHEN aich_root IS NULL THEN NULL ELSE lower(hex(aich_root)) END
                 FROM known_files WHERE ed2k_hash = ?1",
            params![hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        let Some(part_size) = part_size.filter(|size| *size > 0) else {
            return Ok(None);
        };
        let Some(aich_root) = aich_root else {
            return Ok(None);
        };
        ensure!(
            size >= 0 && size as u64 == instance.file_size,
            "active local file size differs from known content"
        );
        let mut md4_stmt = conn.prepare(
            "SELECT lower(hex(ed2k_part_hashes.md4_hash))
             FROM ed2k_part_hashes JOIN known_files ON known_files.id = ed2k_part_hashes.known_file_id
             WHERE known_files.ed2k_hash = ?1 ORDER BY part_index",
        )?;
        let md4_hashset = md4_stmt
            .query_map(params![hash], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut aich_stmt = conn.prepare(
            "SELECT lower(hex(aich_part_hashes.aich_hash))
             FROM aich_part_hashes JOIN known_files ON known_files.id = aich_part_hashes.known_file_id
             WHERE known_files.ed2k_hash = ?1 ORDER BY part_index",
        )?;
        let aich_hashset = aich_stmt
            .query_map(params![hash], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Some(MetadataVerifiedLocalContent {
            file_hash: instance.file_hash,
            display_name: name,
            file_size: instance.file_size,
            part_size: part_size as u64,
            md4_hashset,
            aich_root,
            aich_hashset,
            path: instance.path,
            fingerprint: instance.verified_fingerprint,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeFileIdentity, NativeFileTimestamp};

    fn fingerprint(inode_number: u64) -> NativeFileFingerprint {
        NativeFileFingerprint {
            identity: NativeFileIdentity::Unix {
                device_id: 7,
                inode_number,
            },
            size_bytes: 32,
            modified: NativeFileTimestamp::new(1_700_000_000, 123_456_789).unwrap(),
            changed: Some(NativeFileTimestamp::new(1_700_000_001, 234_567_890).unwrap()),
        }
    }

    #[test]
    fn verified_path_cache_needs_no_transfer_and_retains_identity() {
        let store = MetadataStore::in_memory().unwrap();
        let hash = "00112233445566778899aabbccddeeff";
        store
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO known_files(ed2k_hash, size_bytes, display_name,
                first_seen_ms, last_seen_ms, updated_at_ms)
             VALUES (?1, 32, 'Sample.bin', 1, 1, 1)",
                params![decode_fixed_hex(hash, 16, "ED2K hash").unwrap()],
            )
            .unwrap();
        let path = std::env::temp_dir().join("emulebb-verified-library-sample.bin");
        let first = fingerprint(11);
        store
            .upsert_local_file_instance(&path, hash, &first)
            .unwrap();
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT count(*) FROM transfers", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store.local_file_instance(&path).unwrap(),
            Some(MetadataLocalFileInstance {
                path: path.clone(),
                file_hash: hash.to_string(),
                file_size: 32,
                verified_fingerprint: first,
            })
        );
        let changed = fingerprint(12);
        store
            .upsert_local_file_instance(&path, hash, &changed)
            .unwrap();
        assert_eq!(
            store
                .local_file_instance(&path)
                .unwrap()
                .unwrap()
                .verified_fingerprint,
            changed
        );
        assert!(
            store
                .upsert_local_file_instance(
                    &path,
                    hash,
                    &NativeFileFingerprint {
                        size_bytes: 31,
                        ..changed
                    }
                )
                .is_err()
        );
        assert_eq!(
            store
                .reusable_local_file_by_identity(&changed)
                .unwrap()
                .unwrap()
                .file_hash,
            hash
        );
        assert!(
            store
                .reusable_local_file_by_identity(&fingerprint(13))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn verified_content_writes_hashsets_and_paths_without_download_rows() {
        let mut store = MetadataStore::in_memory().unwrap();
        let first_path = std::env::temp_dir().join("emulebb-local-content-first.bin");
        let second_path = std::env::temp_dir().join("emulebb-local-content-second.bin");
        let mut content = MetadataVerifiedLocalContent {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "First.bin".to_string(),
            file_size: 32,
            part_size: 32,
            md4_hashset: vec!["11111111111111111111111111111111".to_string()],
            aich_root: "2222222222222222222222222222222222222222".to_string(),
            aich_hashset: vec!["3333333333333333333333333333333333333333".to_string()],
            path: first_path.clone(),
            fingerprint: fingerprint(41),
        };
        store.upsert_verified_local_content(&content).unwrap();
        content.path = second_path.clone();
        content.display_name = "Second.bin".to_string();
        content.fingerprint = fingerprint(42);
        store.upsert_verified_local_content(&content).unwrap();
        let conn = store.connection().unwrap();
        let (name, transfers, md4, aich, paths): (String, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT known_files.display_name,
                (SELECT count(*) FROM transfers),
                (SELECT count(*) FROM ed2k_part_hashes),
                (SELECT count(*) FROM aich_part_hashes),
                (SELECT count(*) FROM local_file_instances)
             FROM known_files WHERE ed2k_hash = ?1",
                params![decode_fixed_hex(&content.file_hash, 16, "ED2K hash").unwrap()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            (name.as_str(), transfers, md4, aich, paths),
            ("First.bin", 0, 1, 1, 2)
        );
        drop(conn);
        assert!(
            store
                .active_local_content_by_hash(&content.file_hash)
                .unwrap()
                .is_none()
        );
        let root = std::env::temp_dir();
        store
            .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
                path: root.to_string_lossy().into_owned(),
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
        store
            .replace_root_memberships(
                &root,
                &[
                    (
                        first_path.clone(),
                        "emulebb-local-content-first.bin".into(),
                        fingerprint(41),
                    ),
                    (
                        second_path.clone(),
                        "emulebb-local-content-second.bin".into(),
                        fingerprint(42),
                    ),
                ],
            )
            .unwrap();
        let active = store
            .active_local_content_by_hash(&content.file_hash)
            .unwrap()
            .unwrap();
        assert_eq!(active.display_name, "First.bin");
        assert_eq!(active.md4_hashset, content.md4_hashset);
        assert_eq!(active.aich_hashset, content.aich_hashset);
    }
}
