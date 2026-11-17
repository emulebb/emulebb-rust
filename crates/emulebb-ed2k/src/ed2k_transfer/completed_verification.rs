//! Explicit output verification is separate from durable completion and ownership.
use super::{
    Ed2kTransferRuntime,
    deliver::{DeliveredOutputIdentity, classify_delivered_output},
};
use anyhow::{Context, Result, ensure};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::JobToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletedOutputVerification {
    Verified,
    Missing,
    Damaged,
}

impl Ed2kTransferRuntime {
    /// Hash only this completed job's recorded output. Never hydrate its retired
    /// pieces, seek another copy, refresh destructive ownership, or reopen it.
    /// The caller owns execution through the awaited hash, independently of any
    /// requesting connection. Lifecycle serialization fences removal/replacement.
    pub async fn verify_completed_output(
        &self,
        token: JobToken,
    ) -> Result<Option<CompletedOutputVerification>> {
        let _lifecycle = self.lock_lifecycle(token.job_id).await;
        let Some(detail) = self.download_detail(token.job_id).await? else {
            return Ok(None);
        };
        if detail.job.removed_at_s.is_some() {
            return Ok(None);
        }
        ensure!(
            detail.job.token == token,
            "stale completed verification generation"
        );
        ensure!(
            detail.job.completed_at_s.is_some(),
            "job has not completed delivery"
        );
        let path = detail
            .delivered_path
            .as_deref()
            .context("completed job has no recorded output")?;
        let size = detail
            .job
            .expected_size_bytes
            .context("completed job has no recorded size")?;
        let hash = detail.job.file_hash.parse::<Ed2kHash>()?;
        // Explicit verify always reads bytes; a matching cached fingerprint is
        // sufficient for routine delivery checks, never for this action.
        let outcome = match classify_delivered_output(path, None, size, hash.0).await? {
            DeliveredOutputIdentity::Matching(Some(_)) => CompletedOutputVerification::Verified,
            DeliveredOutputIdentity::Matching(None) => {
                anyhow::bail!("completed output lacks stable native verification evidence");
            }
            DeliveredOutputIdentity::Missing => CompletedOutputVerification::Missing,
            DeliveredOutputIdentity::Foreign => CompletedOutputVerification::Damaged,
        };
        Ok(Some(outcome))
    }
}
