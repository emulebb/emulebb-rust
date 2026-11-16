//! Exact-generation hashset activation without whole-job checkpoint replay.
use crate::{JobToken, MetadataStore};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

// The admitted part size is explicit (small geometries are also used by tests).
// MD4 includes the empty terminal part at exact multiples; AICH never does.
pub(crate) fn expected_md4_hashes(size: u64, part_size: u64) -> u64 {
    let whole_parts = size / part_size;
    whole_parts + u64::from(whole_parts > 0)
}

pub(crate) fn expected_aich_hashes(size: u64, part_size: u64) -> u64 {
    if size <= part_size {
        0
    } else {
        size.div_ceil(part_size)
    }
}

impl MetadataStore {
    /// Store a caller-validated MD4 identity list for the current execution.
    /// Cryptographic reconstruction belongs to the protocol provider; this
    /// transaction enforces current ownership and immutable admitted geometry.
    pub fn activate_download_md4_hashes(
        &self,
        token: JobToken,
        hashes: &[[u8; 16]],
    ) -> Result<bool> {
        ensure!(
            hashes.len() <= 28_259,
            "MD4 hashset exceeds supported geometry"
        );
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let geometry: Option<(u64, u64)> = tx
            .query_row(
                "SELECT expected_size_bytes,part_size_bytes FROM download_jobs
             WHERE id=?1 AND execution_generation=?2 AND intent='started'
               AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL
               AND delete_requested_at_s IS NULL AND delivery_state='pending'
               AND NOT EXISTS(SELECT 1 FROM download_retirements WHERE job_id=?1)",
                params![token.job_id, i64::try_from(token.generation)?],
                |row| {
                    Ok((
                        crate::sql_value::unsigned(row, 0)?,
                        crate::sql_value::unsigned(row, 1)?,
                    ))
                },
            )
            .optional()?;
        let Some((size, part_size)) = geometry else {
            return Ok(false);
        };
        ensure!(
            size > 0 && size <= 0x4000000000 && part_size > 0,
            "unsupported MD4 geometry"
        );
        ensure!(
            u64::try_from(hashes.len())? == expected_md4_hashes(size, part_size),
            "MD4 count differs from admitted geometry"
        );
        tx.execute(
            "DELETE FROM download_job_md4_part_hashes WHERE job_id=?1",
            [token.job_id],
        )?;
        {
            let mut insert=tx.prepare_cached("INSERT INTO download_job_md4_part_hashes(job_id,part_index,md4_hash) VALUES(?1,?2,?3)")?;
            for (index, hash) in hashes.iter().enumerate() {
                insert.execute(params![
                    token.job_id,
                    i64::try_from(index)?,
                    hash.as_slice()
                ])?;
            }
        }
        tx.execute(
            "UPDATE download_jobs SET md4_hashset_acquired=1,updated_at_s=?2 WHERE id=?1",
            params![token.job_id, crate::download_job_store::unix_s()],
        )?;
        tx.commit()?;
        Ok(true)
    }
}

/// Only AICH authority and its dependent part list cross this mutation boundary.
#[derive(Debug)]
pub struct MetadataDownloadAichState {
    pub identity: crate::MetadataTransferAichIdentity,
    pub acquired: bool,
    pub hashes: Vec<String>,
}
impl MetadataStore {
    /// Reconcile accepted canonical authority while fencing the captured trust
    /// generation. Unrelated progress, name and delivery authority are untouched.
    pub fn activate_download_aich(
        &self,
        token: JobToken,
        expected_generation: u64,
        mut state: MetadataDownloadAichState,
    ) -> Result<Option<MetadataDownloadAichState>> {
        ensure!(
            state.hashes.len() <= 28_258,
            "AICH parts exceed supported geometry"
        );
        ensure!(
            state.identity.root.is_some() == state.identity.origin.is_some(),
            "incomplete AICH identity"
        );
        ensure!(
            !state.acquired || state.identity.root.is_some(),
            "AICH parts require authority"
        );
        if let Some(origin) = state.identity.origin.as_deref() {
            ensure!(
                matches!(
                    origin,
                    "local_computed" | "stock_import" | "operator_link" | "network_consensus"
                ),
                "invalid AICH origin"
            );
        }
        for hash in &state.hashes {
            ensure!(
                hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid AICH part hash"
            );
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current:Option<(Vec<u8>,u64,u64)>=tx.query_row(
            "SELECT k.ed2k_hash,j.expected_size_bytes,j.part_size_bytes FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id
             WHERE j.id=?1 AND j.execution_generation=?2 AND j.aich_trust_generation=?3 AND j.intent='started'
             AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL AND j.delete_requested_at_s IS NULL
             AND j.delivery_state='pending' AND NOT EXISTS(SELECT 1 FROM download_retirements WHERE job_id=j.id)",
            params![token.job_id,i64::try_from(token.generation)?,i64::try_from(expected_generation)?],
            |row|Ok((row.get(0)?,crate::sql_value::unsigned(row,1)?,crate::sql_value::unsigned(row,2)?))).optional()?;
        let Some((hash, size, part_size)) = current else {
            return Ok(None);
        };
        ensure!(
            size > 0 && size <= 0x4000000000 && part_size > 0,
            "unsupported AICH geometry"
        );
        ensure!(
            !state.acquired
                || u64::try_from(state.hashes.len())? == expected_aich_hashes(size, part_size),
            "AICH count differs from admitted geometry"
        );
        if crate::transfer_store::reconcile_aich_identity(&tx, token, &hash, &mut state.identity)? {
            state.hashes.clear();
            state.acquired = false;
        }
        let root = state
            .identity
            .root
            .as_deref()
            .map(|value| crate::store::decode_fixed_hex(value, 20, "AICH root"))
            .transpose()?;
        tx.execute(
            "DELETE FROM download_job_aich_part_hashes WHERE job_id=?1",
            [token.job_id],
        )?;
        {
            let mut statement=tx.prepare_cached("INSERT INTO download_job_aich_part_hashes(job_id,part_index,aich_hash) VALUES(?1,?2,?3)")?;
            for (index, hash) in state.hashes.iter().enumerate() {
                let decoded = crate::store::decode_fixed_hex(hash, 20, "AICH part")?;
                statement.execute(params![token.job_id, i64::try_from(index)?, decoded])?;
            }
        }
        tx.execute("UPDATE download_jobs SET aich_root=?2,aich_root_origin=?3,aich_trust_generation=?4,aich_hashset_acquired=?5,updated_at_s=?6 WHERE id=?1",
            params![token.job_id,root,state.identity.origin,i64::try_from(state.identity.generation)?,state.acquired,crate::download_job_store::unix_s()])?;
        tx.commit()?;
        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aich_delta_fences_the_captured_decision_without_replaying_progress() {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "68".repeat(16),
                display_name: "aich-decision.bin".into(),
                expected_size_bytes: Some(8),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let state = || MetadataDownloadAichState {
            identity: crate::MetadataTransferAichIdentity {
                root: Some("11".repeat(20)),
                origin: Some("operator_link".into()),
                generation: 1,
            },
            acquired: true,
            hashes: Vec::new(),
        };
        let stored = store
            .activate_download_aich(job.token, 0, state())
            .unwrap()
            .unwrap();
        assert_eq!(stored.identity.generation, 1);
        assert!(stored.acquired);
        assert!(
            store
                .activate_download_aich(job.token, 0, state())
                .unwrap()
                .is_none()
        );
        let current = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(current.display_name, "aich-decision.bin");
        assert!(current.pieces.is_empty());
        assert_eq!(current.aich_root, Some("11".repeat(20)));
        assert!(store.stop_download_job(job.token).unwrap());
        assert!(
            store
                .activate_download_aich(job.token, 1, state())
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn md4_activation_changes_only_hash_evidence_and_rejects_old_generation() {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "73".repeat(16),
                display_name: "chosen.bin".into(),
                expected_size_bytes: Some(33),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let before = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        assert!(
            store
                .activate_download_md4_hashes(job.token, &[[1; 16]; 2])
                .is_err()
        );
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap(),
            before
        );
        assert!(
            store
                .activate_download_md4_hashes(job.token, &[[1; 16]; 3])
                .unwrap()
        );
        let after = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        assert!(after.md4_hashset_acquired);
        assert_eq!(after.md4_hashset, vec!["01".repeat(16); 3]);
        assert_eq!(after.pieces, before.pieces);
        assert_eq!(after.display_name, before.display_name);
        assert!(store.stop_download_job(job.token).unwrap());
        assert!(
            !store
                .activate_download_md4_hashes(job.token, &[[2; 16]; 3])
                .unwrap()
        );
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .md4_hashset,
            after.md4_hashset
        );
    }
}
