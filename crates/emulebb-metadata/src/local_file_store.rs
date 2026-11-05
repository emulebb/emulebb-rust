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

impl MetadataStore {
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
            "INSERT INTO local_file_instances(path_id, known_file_id, file_size, verified_fingerprint, verified_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path_id) DO UPDATE SET
                 known_file_id = excluded.known_file_id,
                 file_size = excluded.file_size,
                 verified_fingerprint = excluded.verified_fingerprint,
                 verified_at_ms = excluded.verified_at_ms",
            params![path_id, known_file_id, known_size, fingerprint.storage_bytes(), unix_ms()],
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
    }
}
