//! Content-owned, packed AICH recovery leaves. No native paths enter this cache.
use crate::{MetadataStore, store::decode_fixed_hex};
use anyhow::{Result, ensure};
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
        for (query, table, key) in [
            (
                "SELECT id FROM imported_known_files WHERE aich_root=?1 AND size_bytes=?2",
                "imported_known_file_aich_hashes",
                "imported_known_file_id",
            ),
            (
                "SELECT c.known_file_id FROM verified_local_content c JOIN known_files f ON f.id=c.known_file_id WHERE c.aich_root=?1 AND f.size_bytes=?2",
                "verified_local_aich_hashes",
                "known_file_id",
            ),
        ] {
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
