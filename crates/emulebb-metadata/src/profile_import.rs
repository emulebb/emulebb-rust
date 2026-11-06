use std::path::{Path, PathBuf};

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    MetadataImportedKnownFileEntry, MetadataSharedDirectoryRoot, MetadataStore,
    MetadataVerifiedLocalContent, NativeFileFingerprint,
    store::{bool_to_i64, decode_fixed_hex, unix_ms, upsert_local_path},
    transfer_store::upsert_imported_known_file_tx,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataProfileImport {
    pub known_files: Vec<MetadataImportedKnownFileEntry>,
    pub shared_roots: Vec<MetadataSharedDirectoryRoot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataProfileImportSummary {
    pub imported_known_files: usize,
    pub skipped_native_known_files: usize,
    pub merged_shared_roots: usize,
}

impl MetadataStore {
    /// Accept a stock hash cache for an unchanged file without reading its bytes.
    /// The caller resolves one unambiguous stock identity and captures the
    /// target-native fingerprint from an opened regular file.
    pub fn accept_imported_local_files(
        &self,
        files: &[(
            MetadataImportedKnownFileEntry,
            PathBuf,
            NativeFileFingerprint,
        )],
    ) -> Result<()> {
        if files.is_empty() {
            return Ok(());
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let now = unix_ms();
        for (entry, path, fingerprint) in files {
            anyhow::ensure!(
                entry.file_size == fingerprint.size_bytes
                    && entry.modified_s == fingerprint.modified.seconds,
                "imported file metadata differs from the current file"
            );
            // WHY: stock has already hashed these bytes. Rebind its accepted
            // content identity to this platform's fingerprint instead of scheduling
            // a full payload read merely because Rust has not seen the file before.
            Self::upsert_verified_local_content_tx(
                &tx,
                &MetadataVerifiedLocalContent {
                    file_hash: entry.file_hash.clone(),
                    display_name: entry.display_name.clone(),
                    file_size: entry.file_size,
                    part_size: 9_728_000,
                    md4_hashset: entry.md4_hashset.clone(),
                    aich_root: entry.aich_root.clone(),
                    aich_hashset: entry.aich_hashset.clone(),
                    path: path.to_path_buf(),
                    fingerprint: fingerprint.clone(),
                    upload_priority: entry.upload_priority.clone(),
                    auto_upload_priority: entry.auto_upload_priority,
                    comment: String::new(),
                    rating: 0,
                },
                now,
            )?;
            let hash = decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?;
            tx.execute(
                "UPDATE known_files SET
                all_time_uploaded_bytes = max(all_time_uploaded_bytes, ?2),
                all_time_upload_requests = max(all_time_upload_requests, ?3),
                all_time_upload_accepts = max(all_time_upload_accepts, ?4),
                last_upload_request_ms = max(last_upload_request_ms, ?5)
             WHERE ed2k_hash = ?1",
                params![
                    hash,
                    i64::try_from(entry.all_time_uploaded_bytes)?,
                    i64::try_from(entry.all_time_upload_requests)?,
                    i64::try_from(entry.all_time_upload_accepts)?,
                    entry.last_upload_request_ms
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Merge validated legacy eMule hash metadata and roots in one transaction.
    pub fn merge_profile_import(
        &self,
        profile_import: &MetadataProfileImport,
    ) -> Result<MetadataProfileImportSummary> {
        let now = unix_ms();
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut imported_known_files = 0;
        let mut skipped_native_known_files = 0;

        for entry in &profile_import.known_files {
            let hash = decode_fixed_hex(&entry.file_hash, 16, "ED2K hash")?;
            let already_native = tx
                .query_row(
                    "SELECT 1 FROM known_files WHERE ed2k_hash = ?1 LIMIT 1",
                    params![hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            // Retain pathless stock aliases even when this hash is already
            // native, so a newly mapped second path can reuse the same hashes.
            upsert_imported_known_file_tx(&tx, entry, now)?;
            if already_native {
                if let Some(root) = entry.aich_root.as_deref() {
                    let root = decode_fixed_hex(root, 20, "AICH root")?;
                    let (id, size, old, verified): (i64, i64, Option<Vec<u8>>,Option<Vec<u8>>) = tx.query_row(
                        "SELECT f.id,f.size_bytes,f.aich_root,c.aich_root FROM known_files f LEFT JOIN verified_local_content c ON c.known_file_id=f.id WHERE f.ed2k_hash=?1",
                        params![hash],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?,row.get(3)?)),
                    )?;
                    anyhow::ensure!(
                        size == entry.file_size as i64,
                        "imported identity size conflicts with native content"
                    );
                    anyhow::ensure!(
                        old.as_ref().is_none_or(|old| old == &root)
                            && verified.as_ref().is_none_or(|old| old == &root),
                        "imported AICH conflicts with native content"
                    );
                    tx.execute(
                        "UPDATE known_files SET aich_root=coalesce(aich_root,?2) WHERE id=?1",
                        params![id, root],
                    )?;
                    tx.execute("UPDATE verified_local_content SET aich_root=coalesce(aich_root,?2) WHERE known_file_id=?1",params![id,root])?;
                }
                skipped_native_known_files += 1;
                continue;
            }
            imported_known_files += 1;
        }

        for root in &profile_import.shared_roots {
            let path_id = upsert_local_path(&tx, Path::new(&root.path))?;
            tx.execute(
                r#"
                INSERT INTO shared_directory_roots(
                    path_id, monitor_owned, shareable, accessible,
                    enabled, created_at_ms, deleted_at_ms
                )
                VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL)
                ON CONFLICT(path_id) DO UPDATE SET
                    monitor_owned = excluded.monitor_owned,
                    shareable = excluded.shareable,
                    accessible = excluded.accessible,
                    enabled = 1,
                    deleted_at_ms = NULL
                "#,
                params![
                    path_id,
                    bool_to_i64(root.monitor_owned),
                    bool_to_i64(root.shareable),
                    bool_to_i64(root.accessible),
                    now,
                ],
            )?;
            tx.execute(
                "INSERT INTO shared_directory_root_origins(
                    root_id, origin, monitor_owned, shareable, accessible
                 ) VALUES (
                    (SELECT id FROM shared_directory_roots WHERE path_id = ?1),
                    'explicit', ?2, ?3, ?4
                 ) ON CONFLICT(root_id, origin) DO UPDATE SET
                    monitor_owned = excluded.monitor_owned,
                    shareable = excluded.shareable,
                    accessible = excluded.accessible",
                params![
                    path_id,
                    bool_to_i64(root.monitor_owned),
                    bool_to_i64(root.shareable),
                    bool_to_i64(root.accessible),
                ],
            )?;
        }

        tx.execute(
            "UPDATE shared_directory_roots SET
                monitor_owned = coalesce((SELECT max(monitor_owned) FROM shared_directory_root_origins WHERE root_id = shared_directory_roots.id), 0),
                shareable = coalesce((SELECT max(shareable) FROM shared_directory_root_origins WHERE root_id = shared_directory_roots.id), 0),
                accessible = coalesce((SELECT max(shareable * accessible) FROM shared_directory_root_origins WHERE root_id = shared_directory_roots.id), 0)
             WHERE id IN (SELECT root_id FROM shared_directory_root_origins WHERE origin = 'explicit')",
            [],
        )?;

        tx.commit()?;
        Ok(MetadataProfileImportSummary {
            imported_known_files,
            skipped_native_known_files,
            merged_shared_roots: profile_import.shared_roots.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enriches_missing_identity_root_but_preserves_verified_content_on_conflict() {
        let store = MetadataStore::in_memory().unwrap();
        let mut file = imported_file("00112233445566778899aabbccddeeff");
        file.aich_root = Some("11".repeat(20));
        let fingerprint = NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: 2,
            },
            size_bytes: file.file_size,
            modified: crate::NativeFileTimestamp::new(file.modified_s, 0).unwrap(),
            changed: None,
        };
        store
            .accept_imported_local_files(&[(
                file.clone(),
                std::env::temp_dir().join("aich-enrichment-sample.bin"),
                fingerprint,
            )])
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute("UPDATE known_files SET aich_root=NULL", [])
            .unwrap();
        let mut conflict = file.clone();
        conflict.aich_root = Some("22".repeat(20));
        assert!(
            store
                .merge_profile_import(&MetadataProfileImport {
                    known_files: vec![conflict],
                    shared_roots: Vec::new()
                })
                .is_err()
        );
        assert!(store.imported_known_file_entries().unwrap().is_empty());
        store
            .merge_profile_import(&MetadataProfileImport {
                known_files: vec![file],
                shared_roots: Vec::new(),
            })
            .unwrap();
        assert_eq!(store.table_count("local_file_instances").unwrap(), 1);
        let root: String = store
            .connection()
            .unwrap()
            .query_row("SELECT lower(hex(aich_root)) FROM known_files", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(root, "11".repeat(20));
    }

    fn imported_file(hash: &str) -> MetadataImportedKnownFileEntry {
        MetadataImportedKnownFileEntry {
            file_hash: hash.to_string(),
            display_name: "sample.bin".to_string(),
            file_size: 1024,
            modified_s: 1_700_000_000,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
        }
    }

    #[test]
    fn merge_is_idempotent_and_preserves_existing_roots() {
        let mut store = MetadataStore::in_memory().unwrap();
        store
            .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
                path: "/existing".to_string(),
                monitor_owned: false,
                shareable: false,
                accessible: false,
            }])
            .unwrap();
        let profile_import = MetadataProfileImport {
            known_files: vec![imported_file("00112233445566778899aabbccddeeff")],
            shared_roots: vec![MetadataSharedDirectoryRoot {
                path: "/imported".to_string(),
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }],
        };

        store.merge_profile_import(&profile_import).unwrap();
        store.merge_profile_import(&profile_import).unwrap();

        assert_eq!(store.imported_known_file_entries().unwrap().len(), 1);
        assert_eq!(store.shared_directory_roots().unwrap().len(), 2);
    }

    #[test]
    fn invalid_late_entry_rolls_back_the_whole_import() {
        let store = MetadataStore::in_memory().unwrap();
        let profile_import = MetadataProfileImport {
            known_files: vec![
                imported_file("00112233445566778899aabbccddeeff"),
                imported_file("not-a-hash"),
            ],
            shared_roots: Vec::new(),
        };

        assert!(store.merge_profile_import(&profile_import).is_err());
        assert!(store.imported_known_file_entries().unwrap().is_empty());
    }

    #[test]
    fn accepted_stock_batch_is_atomic_and_requires_matching_file_metadata() {
        let store = MetadataStore::in_memory().unwrap();
        let file = imported_file("00112233445566778899aabbccddeeff");
        let fingerprint = NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 7,
                inode_number: 11,
            },
            size_bytes: file.file_size,
            modified: crate::NativeFileTimestamp::new(file.modified_s, 0).unwrap(),
            changed: None,
        };
        let mut changed = fingerprint.clone();
        changed.size_bytes += 1;
        let path = std::env::temp_dir().join("stock-cache-sample.bin");
        assert!(
            store
                .accept_imported_local_files(&[
                    (file.clone(), path.clone(), fingerprint.clone()),
                    (file.clone(), path.clone(), changed),
                ])
                .is_err()
        );
        assert_eq!(store.table_count("known_files").unwrap(), 0);
        // No file at this synthetic path is needed: the caller supplies stat
        // evidence and the metadata layer never opens the payload.
        store
            .accept_imported_local_files(&[(file, path, fingerprint)])
            .unwrap();
        assert_eq!(store.table_count("local_file_instances").unwrap(), 1);
        assert_eq!(store.table_count("transfers").unwrap(), 0);
    }
}
