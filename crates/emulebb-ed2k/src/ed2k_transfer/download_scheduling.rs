//! Current-execution classification and fenced runtime yield requests.
use super::{Ed2kTransferRuntime, LocalMutationError, block_lease, store};
use anyhow::Result;
use emulebb_metadata::JobToken;
use std::time::Instant;

pub(super) const WORK_BYTES: usize = 1024 * 1024;

/// Process-local evidence only. This is neither saved priority nor a claim that
/// cancellation/retirement has released the execution's backing.
#[derive(Debug, Clone, Copy)]
pub struct DownloadSchedulingState {
    pub acquiring_rare: bool,
    pub endgame: bool,
    pub session_bytes: u64,
    pub last_payload_at: Option<Instant>,
    pub yielding: bool,
}

impl Ed2kTransferRuntime {
    /// Called only by the existing bounded blocking owner. Refuse contention
    /// instead of parking a work credit behind a payload producer's job gate.
    pub(super) fn classify_or_yield_download(
        &self,
        token: JobToken,
        yield_if_unchanged: Option<u64>,
    ) -> Result<Option<DownloadSchedulingState>> {
        let _job = store::scoped_lock(&self.manifest_locks, token.job_id)
            .try_lock_owned()
            .ok_or(LocalMutationError::Busy)?;
        let Some(manifest) = self
            .manifest_cache
            .try_lock()
            .map_err(|_| LocalMutationError::Busy)?
            .get(&token.job_id)
            .filter(|manifest| manifest.token == token)
            .cloned()
        else {
            return Ok(None);
        };
        if self.active_job_session(token).is_none() {
            return Ok(None);
        }
        let frequencies = self
            .source_frequencies_with_budget(
                token,
                u32::try_from(manifest.pieces.len())?,
                Instant::now(),
                Some(WORK_BYTES - 4096),
            )
            .ok_or(LocalMutationError::Busy)?;
        let acquiring_rare = self.acquiring_rare_block(token, &frequencies);
        let endgame = manifest.completed
            || manifest.final_rehash_pending
            || block_lease::download_is_in_endgame(
                manifest.file_size,
                manifest.durable_present_bytes(),
                self.download_speed_bytes_per_sec(token),
            );
        let (session_bytes, last_payload_at) = self.download_payload_observation(token);
        // Logical stop/removal may retire authority while the read computes.
        let Some(sessions) = self.active_job_session(token) else {
            return Ok(None);
        };
        let session = sessions.get(&token.job_id).expect("fenced current session");
        // WHY: recheck accepted progress under the same short ledger fence as
        // payload accounting; a stale selection cannot displace renewed work.
        if yield_if_unchanged.is_some_and(|expected| expected == session_bytes)
            && !acquiring_rare
            && !endgame
            && self.download_payload_observation(token).0 == session_bytes
        {
            session.scheduling_yield.cancel();
        }
        let yielding = session.scheduling_yield.is_cancelled();
        drop(sessions);
        Ok(Some(DownloadSchedulingState {
            acquiring_rare,
            endgame,
            session_bytes,
            last_payload_at,
            yielding,
        }))
    }

    pub(crate) fn download_yield_signal(
        &self,
        token: JobToken,
    ) -> Option<tokio_util::sync::CancellationToken> {
        self.active_job_session(token)?
            .get(&token.job_id)
            .map(|session| session.scheduling_yield.clone())
    }

    /// A runtime-only request leaves logical intent and resumable storage intact.
    pub fn download_yield_requested(&self, token: JobToken) -> bool {
        self.download_yield_signal(token)
            .is_some_and(|signal| signal.is_cancelled())
    }

    /// Wake an idle current execution without canceling an in-flight producer.
    pub async fn download_yield_notified(&self, token: JobToken) {
        if let Some(signal) = self.download_yield_signal(token) {
            signal.cancelled().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests;
