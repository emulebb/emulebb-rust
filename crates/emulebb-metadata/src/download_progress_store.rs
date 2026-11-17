//! Exact-generation progress deltas; no metadata or destructive authority replay.
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{JobToken, MetadataStore, MetadataTransferPiece};

impl MetadataStore {
    /// Commit one bounded batch atomically. Missing rows, stale generations or
    /// structural changes reject the entire batch; callers never recreate jobs.
    /// A checkpoint only changes bytes/bitmap on existing piece states.
    pub fn checkpoint_download_progress(
        &self,
        token: JobToken,
        pieces: &[MetadataTransferPiece],
    ) -> Result<bool> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = checkpoint_download_progress_in(&tx, token, pieces)?;
        if changed {
            tx.commit()?;
        }
        Ok(changed)
    }
}

/// Shared transaction-local delta validation and update. The caller owns the
/// transaction so a lifecycle fence and its last progress commit atomically.
pub(crate) fn checkpoint_download_progress_in(
    tx: &rusqlite::Connection,
    token: JobToken,
    pieces: &[MetadataTransferPiece],
) -> Result<bool> {
    ensure!(
        !pieces.is_empty() && pieces.len() <= 28_258,
        "download checkpoint exceeds supported piece geometry"
    );
    let mut previous = None;
    for piece in pieces {
        ensure!(
            previous.is_none_or(|index| index < piece.piece_index),
            "download checkpoint pieces must be distinct and ordered"
        );
        previous = Some(piece.piece_index);
        ensure!(
            matches!(piece.state.as_str(), "Missing" | "Verified"),
            "invalid checkpoint piece state"
        );
        if let Some(bitmap) = piece.block_bitmap.as_deref() {
            ensure!(
                bitmap.len() <= 14
                    && bitmap.len().is_multiple_of(2)
                    && bitmap.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "invalid checkpoint bitmap"
            );
        }
    }
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
    let now = crate::download_job_store::unix_s();
    {
        let mut statement = tx.prepare_cached(
            "UPDATE download_job_pieces SET prefix_bytes=?3,block_bitmap=?4,updated_at_s=?5,present_bytes=?8
                 WHERE job_id=?1 AND piece_index=?2 AND state=?6 AND ich_corrupted=?7
                   AND (state<>'Verified' OR prefix_bytes=?3)",
        )?;
        for piece in pieces {
            let start = u64::from(piece.piece_index)
                .checked_mul(part_size)
                .ok_or_else(|| anyhow::anyhow!("checkpoint offset overflow"))?;
            ensure!(
                part_size > 0
                    && start < size
                    && piece.prefix_bytes <= piece.present_bytes
                    && piece.present_bytes <= part_size.min(size - start)
                    && (piece.block_bitmap.is_some() || piece.present_bytes == piece.prefix_bytes),
                "checkpoint progress lies outside the payload"
            );
            if statement.execute(params![
                token.job_id,
                i64::from(piece.piece_index),
                i64::try_from(piece.prefix_bytes)?,
                piece.block_bitmap,
                now,
                piece.state,
                piece.ich_corrupted,
                i64::try_from(piece.present_bytes)?
            ])? != 1
            {
                // Dropping the transaction rolls back earlier rows too.
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_rolls_back_progress_with_its_fence_and_commits_them_together() {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "45".repeat(16),
                display_name: "Inject-Failure.bin".into(),
                expected_size_bytes: Some(32),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let mut manifest = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        manifest.pieces = (0..2)
            .map(|piece_index| MetadataTransferPiece {
                piece_index,
                state: "Missing".into(),
                prefix_bytes: 0,
                present_bytes: 0,
                block_bitmap: None,
                ich_corrupted: false,
            })
            .collect();
        store.upsert_transfer_manifest(&manifest).unwrap();
        let mut delta = manifest.pieces.clone();
        delta[0].prefix_bytes = 4;
        delta[0].present_bytes = 4;
        delta[1].prefix_bytes = 8;
        delta[1].present_bytes = 8;
        store
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_stop BEFORE UPDATE OF intent ON download_jobs
             WHEN NEW.intent='stopped' AND OLD.display_name='Inject-Failure.bin'
             BEGIN SELECT RAISE(ABORT,'injected stop failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .checkpoint_and_stop_download_job(job.token, &delta)
                .is_err()
        );
        let unchanged = store.download_job(job.token.job_id).unwrap().unwrap();
        assert_eq!(unchanged.intent, crate::DownloadIntent::Started);
        assert_eq!(unchanged.token, job.token);
        assert_eq!(unchanged.checkpointed_bytes, 0);
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces,
            manifest.pieces
        );
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET display_name='Sample.bin' WHERE id=?1",
                [job.token.job_id],
            )
            .unwrap();
        assert!(
            store
                .checkpoint_and_stop_download_job(job.token, &delta)
                .unwrap()
        );
        let stopped = store.download_job(job.token.job_id).unwrap().unwrap();
        assert_eq!(stopped.intent, crate::DownloadIntent::Stopped);
        assert!(stopped.token.generation > job.token.generation);
        assert_eq!(stopped.checkpointed_bytes, 12);
        assert!(
            !store
                .checkpoint_and_stop_download_job(job.token, &delta)
                .unwrap()
        );
        assert_eq!(
            store.download_job(stopped.token.job_id).unwrap().unwrap(),
            stopped
        );
    }
    #[test]
    fn checkpoint_batch_rolls_back_missing_tail_and_fences_stopped_generation() {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "31".repeat(16),
                display_name: "checkpoint.bin".into(),
                expected_size_bytes: Some(32),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let mut manifest = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        manifest.pieces = (0..2)
            .map(|piece_index| MetadataTransferPiece {
                piece_index,
                state: "Missing".into(),
                prefix_bytes: 0,
                present_bytes: 0,
                block_bitmap: None,
                ich_corrupted: false,
            })
            .collect();
        store.upsert_transfer_manifest(&manifest).unwrap();
        let mut delta = manifest.pieces.clone();
        delta[0].prefix_bytes = 4;
        delta[0].present_bytes = 4;
        delta[1].prefix_bytes = 8;
        delta[1].present_bytes = 8;
        store
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM download_job_pieces WHERE job_id=?1 AND piece_index=1",
                [job.token.job_id],
            )
            .unwrap();
        assert!(
            !store
                .checkpoint_download_progress(job.token, &delta)
                .unwrap()
        );
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            0
        );
        store.upsert_transfer_manifest(&manifest).unwrap();
        assert!(
            store
                .checkpoint_download_progress(job.token, &delta)
                .unwrap()
        );
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces,
            delta
        );
        assert!(store.stop_download_job(job.token).unwrap());
        delta[0].prefix_bytes = 9;
        delta[0].present_bytes = 9;
        assert!(
            !store
                .checkpoint_download_progress(job.token, &delta)
                .unwrap()
        );
        assert_eq!(
            store
                .download_job_manifest(job.token.job_id)
                .unwrap()
                .unwrap()
                .pieces[0]
                .prefix_bytes,
            4
        );
    }
}

#[cfg(test)]
mod aggregate_tests;
