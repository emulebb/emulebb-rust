//! Compact removed-job authority, never a hydrated execution manifest.
use crate::{JobId, JobToken, MetadataStore, NativeFileFingerprint};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::path::PathBuf;

#[derive(Debug)]
pub struct MetadataDownloadCleanupSnapshot {
    pub token: JobToken,
    pub file_hash: String,
    pub delete_output: bool,
    pub delivered: bool,
    pub owned_output: Option<(PathBuf, NativeFileFingerprint)>,
}

impl MetadataStore {
    pub fn removed_download_cleanup_snapshot(
        &self,
        id: JobId,
    ) -> Result<Option<MetadataDownloadCleanupSnapshot>> {
        let mut connection = self.connection()?;
        let conn = connection.transaction()?;
        let bounded: Option<bool> = conn.query_row("SELECT coalesce(length(p.native_path),0)<=65536 AND coalesce(length(j.source_fingerprint),0)<=1024
            FROM download_jobs j LEFT JOIN local_paths p ON p.id=j.delivered_path_id
            WHERE j.id=?1 AND j.removed_at_s IS NOT NULL", [id], |row| row.get(0)).optional()?;
        let Some(bounded) = bounded else {
            return Ok(None);
        };
        ensure!(bounded, "cleanup authority exceeds bounded representation");
        // The same read transaction covers length validation and projection.
        conn.query_row("SELECT j.execution_generation,lower(hex(k.ed2k_hash)),j.delete_requested_at_s IS NOT NULL,
            j.delivery_state='delivered' AND j.delivery_ownership='owned',p.platform,p.native_path,j.source_fingerprint,j.delivery_state='delivered'
            FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id LEFT JOIN local_paths p ON p.id=j.delivered_path_id
            WHERE j.id=?1 AND j.removed_at_s IS NOT NULL", [id], |row| {
            let owned: bool = row.get(3)?;
            let path = crate::native_path::optional_path_from_row(row,4,5)?;
            let fingerprint = crate::transfer_store::optional_fingerprint_from_row(row,6)?;
            Ok(MetadataDownloadCleanupSnapshot {
                token: JobToken { job_id:id, generation:crate::sql_value::unsigned(row,0)? },
                file_hash:row.get(1)?, delete_output:row.get(2)?, delivered:row.get(7)?,
                owned_output: if owned { path.zip(fingerprint) } else { None },
            })
        }).optional().map_err(Into::into)
    }

    pub fn removed_download_jobs_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<Vec<JobId>> {
        ensure!((1..=256).contains(&limit), "invalid removed-job page size");
        let conn = self.connection()?;
        let mut statement=conn.prepare("SELECT id FROM download_jobs WHERE removed_at_s IS NOT NULL AND id>?1 ORDER BY id LIMIT ?2")?;
        Ok(statement
            .query_map(
                params![after.map_or(0, JobId::get), i64::try_from(limit)?],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Physical row deletion follows both internal retirement and explicit
    /// settlement of every independent output journal/barrier.
    pub fn finalize_removed_download_job(&self, token: JobToken) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let eligible:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2 AND removed_at_s IS NOT NULL AND internal_storage_retired=1)",params![token.job_id,i64::try_from(token.generation)?],|row|row.get(0))?;
        if !eligible {
            return Ok(false);
        }
        crate::transfer_store::delete_job_row(&tx, token.job_id)?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sparse_removed_jobs_and_exclusion_authority_use_indexed_seeks() {
        let store = MetadataStore::in_memory().unwrap();
        {
            let conn = store.connection().unwrap();
            conn.execute_batch("BEGIN;
                WITH RECURSIVE ids(id) AS (VALUES(1) UNION ALL SELECT id+1 FROM ids WHERE id<100000)
                INSERT INTO known_files(id,ed2k_hash,display_name,first_seen_at_s,last_seen_at_s,updated_at_s)
                    SELECT id,CAST(printf('%016x',id) AS BLOB),'retained',0,0,0 FROM ids;
                INSERT INTO download_jobs(id,known_file_id,display_name,part_size_bytes,part_count,visible_state,intent,delivery_state,created_at_s,updated_at_s)
                    SELECT id,id,'retained',16,0,'queued','stopped','pending',0,0 FROM known_files;
                UPDATE download_jobs SET removed_at_s=1 WHERE id IN (7,50000,99999);
                WITH RECURSIVE ids(id) AS (VALUES(1) UNION ALL SELECT id+1 FROM ids WHERE id<1000)
                INSERT INTO download_delivery_exclusions(platform,native_path,reservation_id,originating_job_id)
                    SELECT 'test',CAST(printf('/%d',id) AS BLOB),printf('%036d',id),id FROM ids;
                COMMIT;").unwrap();
            for (sql, index) in [
                (
                    "SELECT id FROM download_jobs WHERE removed_at_s IS NOT NULL AND id>49999 ORDER BY id LIMIT 2",
                    "download_jobs_removed_page_idx",
                ),
                (
                    "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE originating_job_id=999)",
                    "download_delivery_exclusion_origin_idx",
                ),
            ] {
                let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
                let plan = statement
                    .query_map([], |row| row.get::<_, String>(3))
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert!(
                    plan.iter()
                        .any(|line| line.contains("SEARCH") && line.contains(index)),
                    "{plan:?}"
                );
                assert!(
                    plan.iter()
                        .all(|line| !line.contains("TEMP B-TREE")
                            && !line.contains("SCAN download_")),
                    "{plan:?}"
                );
            }
        }
        let after = JobId::new(49999).unwrap();
        assert_eq!(
            store
                .removed_download_jobs_after(Some(after), 2)
                .unwrap()
                .into_iter()
                .map(JobId::get)
                .collect::<Vec<_>>(),
            vec![50000, 99999]
        );
    }

    #[test]
    fn removed_cleanup_requires_retirement_and_exact_current_generation() {
        for delete_output in [false, true] {
            let store = MetadataStore::in_memory().unwrap();
            let original = store
                .admit_download_job(&crate::DownloadJobRequest {
                    file_hash: "7a".repeat(16),
                    display_name: "cleanup.bin".into(),
                    expected_size_bytes: Some(8),
                    category_id: None,
                    intent: crate::DownloadIntent::Stopped,
                    piece_size: 16,
                })
                .unwrap()
                .job;
            if delete_output {
                store
                    .request_transfer_deletion(original.token.job_id)
                    .unwrap();
            } else {
                store.remove_download_job(original.token.job_id).unwrap();
            }
            let snapshot = store
                .removed_download_cleanup_snapshot(original.token.job_id)
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.delete_output, delete_output);
            assert!(!snapshot.delivered);
            assert!(snapshot.owned_output.is_none());
            assert!(!store.finalize_removed_download_job(snapshot.token).unwrap());
            assert!(
                store
                    .finalize_transfer_retirement(snapshot.token.job_id)
                    .unwrap()
            );
            assert!(!store.finalize_removed_download_job(original.token).unwrap());
            assert!(store.finalize_removed_download_job(snapshot.token).unwrap());
            assert!(store.download_job(snapshot.token.job_id).unwrap().is_none());
            assert!(
                store
                    .removed_download_jobs_after(None, 256)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}
