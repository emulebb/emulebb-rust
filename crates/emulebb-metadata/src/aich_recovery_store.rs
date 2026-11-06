//! Content-owned, packed AICH recovery leaves. No native paths enter this cache.
use crate::{
    MetadataStore, MetadataVerifiedLocalContent,
    store::{decode_fixed_hex, unix_ms},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};

/// One complete, protocol-validated recovery set for a bounded import batch.
#[derive(Debug)]
pub struct MetadataAichRecoverySet {
    pub root: [u8; 20],
    pub size: u64,
    pub parts: Vec<Vec<u8>>,
    pub part_roots: Vec<[u8; 20]>,
}

impl MetadataStore {
    /// Commit native verified content and successful recovery caching together.
    /// The inner error reports optional caching failure; the outer error means
    /// verified content could not commit. A crash cannot split successful writes.
    pub fn upsert_verified_local_content_with_recovery(
        &self,
        content: &MetadataVerifiedLocalContent,
        recovery: &MetadataAichRecoverySet,
    ) -> Result<Option<anyhow::Error>> {
        ensure!(
            content.file_size == recovery.size
                && content
                    .aich_root
                    .as_deref()
                    .map(|r| decode_fixed_hex(r, 20, "AICH root"))
                    .transpose()?
                    .as_deref()
                    == Some(recovery.root.as_slice()),
            "recovery set differs from verified local content"
        );
        let mut connection = self.connection()?;
        let mut tx = connection.transaction()?;
        Self::upsert_verified_local_content_tx(&tx, content, unix_ms())?;
        let mut save = tx.savepoint()?;
        let recovery_error = match write_set(
            &save,
            &recovery.root,
            recovery.size,
            &recovery.parts,
            &recovery.part_roots,
        ) {
            Ok(()) => {
                save.commit()?;
                None
            }
            Err(error) => {
                // WHY: SQLITE_FULL/IO errors may abort the entire transaction,
                // removing the savepoint and staged MD4 rows together. While
                // this process is alive, retry only the small verified metadata
                // write; the successful path remains one atomic transaction.
                if save.is_autocommit() {
                    drop(save);
                    drop(tx);
                    drop(connection);
                    self.upsert_verified_local_content(content).context(
                        "failed to retain verified MD4 after recovery transaction abort",
                    )?;
                    return Ok(Some(error));
                }
                save.rollback()?;
                drop(save);
                Some(error)
            }
        };
        tx.commit()?;
        Ok(recovery_error)
    }

    /// Count accepted live contents with an AICH master but no saved full tree.
    /// Missing rows are durable coverage state, never a request to read payloads.
    pub fn missing_live_aich_recovery_count(&self) -> Result<u64> {
        let count: i64 = self.connection()?.query_row(
            "SELECT count(*) FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE c.aich_root IS NOT NULL AND f.size_bytes>184320 AND NOT EXISTS (SELECT 1 FROM aich_recovery_sets r WHERE r.root=c.aich_root AND r.size_bytes=f.size_bytes)",
            [], |row| row.get(0),
        )?;
        Ok(count.try_into()?)
    }

    /// Recovery imports only enrich live accepted content, never unmatched staging rows.
    pub fn has_live_aich_content(&self, root: &[u8], size: i64) -> Result<bool> {
        Ok(self.connection()?.query_row(
            "SELECT 1 FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE c.aich_root=?1 AND f.size_bytes=?2 LIMIT 1",
            params![root,size], |_|Ok(()),
        ).optional()?.is_some())
    }
    /// Atomically retain a complete set whose tree was validated by the protocol layer.
    /// Repeated imports must agree byte-for-byte; paths and aliases share this set.
    pub fn store_aich_recovery_set(
        &self,
        root: &str,
        size: u64,
        parts: &[Vec<u8>],
        part_roots: &[[u8; 20]],
    ) -> Result<()> {
        let root = decode_fixed_hex(root, 20, "AICH root")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        write_set(&tx, &root, size, parts, part_roots)?;
        tx.commit()?;
        Ok(())
    }

    /// Commit bounded batches while rolling back only an individual rejected set.
    pub fn store_aich_recovery_batch(
        &self,
        sets: &[MetadataAichRecoverySet],
    ) -> Result<Vec<Result<()>>> {
        let mut conn = self.connection()?;
        let mut tx = conn.transaction()?;
        let mut results = Vec::with_capacity(sets.len());
        for set in sets {
            let save = tx.savepoint()?;
            let result = write_set(&save, &set.root, set.size, &set.parts, &set.part_roots);
            if result.is_ok() {
                save.commit()?;
            } else {
                drop(save);
            }
            results.push(result);
        }
        tx.commit()?;
        Ok(results)
    }

    /// Fetch at most one part (53 SHA-1 hashes), independent of library size.
    pub fn aich_recovery_part(&self, root: &str, size: u64, part: u16) -> Result<Option<Vec<u8>>> {
        let root = decode_fixed_hex(root, 20, "AICH root")?;
        Ok(self.connection()?.query_row("SELECT leaves FROM aich_recovery_parts WHERE root=?1 AND size_bytes=?2 AND part_index=?3", params![root,i64::try_from(size)?,part], |row|row.get(0)).optional()?)
    }

    /// Indexed upper-tree input, bounded by this file's part count.
    pub fn aich_recovery_roots(&self, root: &str, size: u64) -> Result<Vec<[u8; 20]>> {
        let root = decode_fixed_hex(root, 20, "AICH root")?;
        let conn = self.connection()?;
        let mut query=conn.prepare("SELECT part_root FROM aich_recovery_parts WHERE root=?1 AND size_bytes=?2 ORDER BY part_index")?;
        let rows = query.query_map(params![root, i64::try_from(size)?], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| Ok(row?.as_slice().try_into()?)).collect()
    }
}

fn write_set(
    conn: &rusqlite::Connection,
    root: &[u8],
    size: u64,
    parts: &[Vec<u8>],
    part_roots: &[[u8; 20]],
) -> Result<()> {
    const PART: u64 = 9_728_000;
    const BLOCK: u64 = 184_320;
    ensure!(
        size > 0 && size <= 0x4000000000,
        "invalid recovery file size"
    );
    ensure!(
        parts.len() as u64 == size.div_ceil(PART),
        "incomplete recovery set"
    );
    ensure!(
        part_roots.len() == parts.len(),
        "missing recovery part roots"
    );
    conn.execute(
        "INSERT OR IGNORE INTO aich_recovery_sets(root, size_bytes) VALUES (?1, ?2)",
        params![root, size as i64],
    )?;
    for (index, leaves) in parts.iter().enumerate() {
        let part_size = (size - index as u64 * PART).min(PART);
        ensure!(
            leaves.len() as u64 == part_size.div_ceil(BLOCK) * 20,
            "invalid recovery leaf count"
        );
        let old: Option<(Vec<u8>,Vec<u8>)> = conn.query_row("SELECT leaves,part_root FROM aich_recovery_parts WHERE root=?1 AND size_bytes=?2 AND part_index=?3", params![root,size as i64,index as i64], |row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((old, old_root)) = old {
            ensure!(
                old == *leaves && old_root == part_roots[index],
                "conflicting AICH recovery leaves"
            );
        } else {
            conn.execute("INSERT INTO aich_recovery_parts(root,size_bytes,part_index,leaves,part_root) VALUES (?1,?2,?3,?4,?5)", params![root,size as i64,index as i64,leaves,part_roots[index].as_slice()])?;
        }
    }
    // WHY: recovery imports can arrive after aliases have native bindings.
    // Enrich missing part lists by content, without opening or rebinding paths.
    if size > PART {
        for (query, table, key) in [(
            "SELECT c.known_file_id FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE c.aich_root=?1 AND f.size_bytes=?2",
            "verified_local_aich_hashes",
            "known_file_id",
        )] {
            let mut ids = conn.prepare(query)?;
            let ids = ids
                .query_map(params![root, size as i64], |row| row.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            for id in ids {
                let mut hashes = conn.prepare(&format!(
                    "SELECT aich_hash FROM {table} WHERE {key}=?1 ORDER BY part_index"
                ))?;
                let old = hashes
                    .query_map([id], |row| row.get::<_, Vec<u8>>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                if old.is_empty() {
                    let mut insert = conn.prepare(&format!(
                        "INSERT INTO {table}({key},part_index,aich_hash) VALUES (?1,?2,?3)"
                    ))?;
                    for (index, hash) in part_roots.iter().enumerate() {
                        insert.execute(params![id, index as i64, hash.as_slice()])?;
                    }
                } else {
                    ensure!(
                        old.iter()
                            .map(Vec::as_slice)
                            .eq(part_roots.iter().map(|r| r.as_slice())),
                        "conflicting existing AICH part hashes"
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_content_and_recovery_commit_together_or_preserve_md4_on_optional_failure() {
        let db = MetadataStore::in_memory().unwrap();
        let content = MetadataVerifiedLocalContent {
            file_hash: "11".repeat(16),
            display_name: "Sample.bin".to_string(),
            file_size: 184_321,
            part_size: 9_728_000,
            md4_hashset: Vec::new(),
            aich_root: Some("22".repeat(20)),
            aich_hashset: Vec::new(),
            path: std::env::temp_dir().join("atomic-aich-sample.bin"),
            fingerprint: crate::NativeFileFingerprint {
                identity: crate::NativeFileIdentity::Unix {
                    device_id: 1,
                    inode_number: 2,
                },
                size_bytes: 184_321,
                modified: crate::NativeFileTimestamp::new(1700000000, 0).unwrap(),
                changed: None,
            },
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        };
        let set = MetadataAichRecoverySet {
            root: [0x22; 20],
            size: content.file_size,
            parts: vec![vec![0x33; 40]],
            part_roots: vec![[0x22; 20]],
        };
        // Simulate SQLite aborting the entire transaction during optional
        // cache persistence. The live process can still retain MD4 without
        // rereading bytes, and no partial recovery rows may survive.
        db.connection().unwrap().execute_batch("CREATE TRIGGER abort_cache BEFORE INSERT ON aich_recovery_parts BEGIN SELECT RAISE(ROLLBACK, 'injected cache transaction abort'); END;").unwrap();
        assert!(
            db.upsert_verified_local_content_with_recovery(&content, &set)
                .unwrap()
                .is_some()
        );
        assert_eq!(db.table_count("verified_local_content").unwrap(), 1);
        assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 0);
        assert_eq!(db.table_count("aich_recovery_parts").unwrap(), 0);
        assert_eq!(db.missing_live_aich_recovery_count().unwrap(), 1);
        db.connection()
            .unwrap()
            .execute_batch("DROP TRIGGER abort_cache;")
            .unwrap();
        // A malformed optional tree is recoverable and does not lose valid MD4.
        let malformed = MetadataAichRecoverySet {
            parts: vec![vec![0; 20]],
            ..set
        };
        assert!(
            db.upsert_verified_local_content_with_recovery(&content, &malformed)
                .unwrap()
                .is_some()
        );
        assert_eq!(db.table_count("verified_local_content").unwrap(), 1);
        assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 0);
        assert_eq!(db.missing_live_aich_recovery_count().unwrap(), 1);
        let repaired = MetadataAichRecoverySet {
            parts: vec![vec![0x33; 40]],
            ..malformed
        };
        assert!(
            db.upsert_verified_local_content_with_recovery(&content, &repaired)
                .unwrap()
                .is_none()
        );
        assert_eq!(db.missing_live_aich_recovery_count().unwrap(), 0);
        assert_eq!(db.table_count("aich_recovery_sets").unwrap(), 1);
    }

    #[test]
    fn complete_recovery_enriches_live_content_shared_by_multiple_paths() {
        let db = MetadataStore::in_memory().unwrap();
        let first = crate::MetadataFileImportRecord {
            file_hash: "11".repeat(16),
            display_name: "Sample.bin".to_string(),
            file_size: 9_728_001,
            modified_s: 1700000000,
            md4_hashset: vec!["22".repeat(16), "33".repeat(16)],
            aich_root: Some("55".repeat(20)),
            aich_hashset: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
        };
        let mut alias = first.clone();
        alias.display_name = "Alias.bin".to_string();
        let fingerprint = crate::NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: 2,
            },
            size_bytes: first.file_size,
            modified: crate::NativeFileTimestamp::new(first.modified_s, 0).unwrap(),
            changed: None,
        };
        db.accept_imported_local_files(&[
            (
                first.clone(),
                std::env::temp_dir().join("Sample.bin"),
                fingerprint.clone(),
            ),
            (alias, std::env::temp_dir().join("Alias.bin"), fingerprint),
        ])
        .unwrap();
        db.store_aich_recovery_set(
            &"55".repeat(20),
            9_728_001,
            &[vec![0; 1060], vec![0; 20]],
            &[[0x66; 20], [0x77; 20]],
        )
        .unwrap();
        assert_eq!(
            db.connection()
                .unwrap()
                .query_row("SELECT count(*) FROM verified_local_aich_hashes", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.connection()
                .unwrap()
                .query_row("SELECT count(*) FROM aich_recovery_parts", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn batch_rejects_one_set_without_losing_other_sets_or_partial_rows() {
        let db = MetadataStore::in_memory().unwrap();
        let sets: Vec<_> = (1..=3u8)
            .map(|value| MetadataAichRecoverySet {
                root: [value; 20],
                size: 184_321,
                parts: vec![vec![value; if value == 2 { 20 } else { 40 }]],
                part_roots: vec![[value; 20]],
            })
            .collect();
        let results = db.store_aich_recovery_batch(&sets).unwrap();
        assert!(results[0].is_ok() && results[1].is_err() && results[2].is_ok());
        assert!(
            db.aich_recovery_part(&"01".repeat(20), 184_321, 0)
                .unwrap()
                .is_some()
        );
        assert!(
            db.aich_recovery_part(&"02".repeat(20), 184_321, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            db.aich_recovery_part(&"03".repeat(20), 184_321, 0)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            db.connection()
                .unwrap()
                .query_row("SELECT count(*) FROM aich_recovery_sets", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn sets_are_atomic_deduplicated_and_conflicts_preserve_old_data() {
        let db = MetadataStore::in_memory().unwrap();
        let root = "11".repeat(20);
        let parts = vec![vec![7; 40]];
        db.store_aich_recovery_set(&root, 184_321, &parts, &[[11; 20]])
            .unwrap();
        db.store_aich_recovery_set(&root, 184_321, &parts, &[[11; 20]])
            .unwrap();
        assert!(
            db.store_aich_recovery_set(&root, 184_321, &[vec![8; 40]], &[[11; 20]])
                .is_err()
        );
        assert_eq!(
            db.aich_recovery_part(&root, 184_321, 0).unwrap(),
            Some(parts[0].clone())
        );
        assert!(
            db.store_aich_recovery_set(&root, 184_321, &[vec![7; 20]], &[[11; 20]])
                .is_err()
        );
        assert_eq!(db.aich_recovery_part(&root, 184_321, 1).unwrap(), None);
    }
}
