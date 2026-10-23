use std::path::Path;

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::{
    MetadataImportedKnownFileEntry, MetadataSharedDirectoryRoot, MetadataStore,
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
            if already_native {
                skipped_native_known_files += 1;
                continue;
            }
            upsert_imported_known_file_tx(&tx, entry, now)?;
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
        }

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
}
