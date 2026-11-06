//! Content-owned, packed AICH recovery leaves. No native paths enter this cache.
use crate::{MetadataStore, store::decode_fixed_hex};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

impl MetadataStore {
    /// Atomically retain a complete set whose tree was validated by the protocol layer.
    /// Repeated imports must agree byte-for-byte; paths and aliases share this set.
    pub fn store_aich_recovery_set(&self, root: &str, size: u64, parts: &[Vec<u8>]) -> Result<()> {
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
        let root = decode_fixed_hex(root, 20, "AICH root")?;
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO aich_recovery_sets(root, size_bytes) VALUES (?1, ?2)",
            params![root, size as i64],
        )?;
        for (index, leaves) in parts.iter().enumerate() {
            let part_size = (size - index as u64 * PART).min(PART);
            ensure!(
                leaves.len() as u64 == part_size.div_ceil(BLOCK) * 20,
                "invalid recovery leaf count"
            );
            let old: Option<Vec<u8>> = tx.query_row("SELECT leaves FROM aich_recovery_parts WHERE root=?1 AND size_bytes=?2 AND part_index=?3", params![root,size as i64,index as i64], |row|row.get(0)).optional()?;
            if let Some(old) = old {
                ensure!(old == *leaves, "conflicting AICH recovery leaves");
            } else {
                tx.execute("INSERT INTO aich_recovery_parts(root,size_bytes,part_index,leaves) VALUES (?1,?2,?3,?4)", params![root,size as i64,index as i64,leaves])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Fetch at most one part (53 SHA-1 hashes), independent of library size.
    pub fn aich_recovery_part(&self, root: &str, size: u64, part: u16) -> Result<Option<Vec<u8>>> {
        let root = decode_fixed_hex(root, 20, "AICH root")?;
        Ok(self.connection()?.query_row("SELECT leaves FROM aich_recovery_parts WHERE root=?1 AND size_bytes=?2 AND part_index=?3", params![root,i64::try_from(size)?,part], |row|row.get(0)).optional()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sets_are_atomic_deduplicated_and_conflicts_preserve_old_data() {
        let db = MetadataStore::in_memory().unwrap();
        let root = "11".repeat(20);
        let parts = vec![vec![7; 40]];
        db.store_aich_recovery_set(&root, 184_321, &parts).unwrap();
        db.store_aich_recovery_set(&root, 184_321, &parts).unwrap();
        assert!(
            db.store_aich_recovery_set(&root, 184_321, &[vec![8; 40]])
                .is_err()
        );
        assert_eq!(
            db.aich_recovery_part(&root, 184_321, 0).unwrap(),
            Some(parts[0].clone())
        );
        assert!(
            db.store_aich_recovery_set(&root, 184_321, &[vec![7; 20]])
                .is_err()
        );
        assert_eq!(db.aich_recovery_part(&root, 184_321, 1).unwrap(), None);
    }
}
