//! Read-only classification of already selected executions for safe scheduling.
use super::{Ed2kTransferRuntime, Ed2kTransferState, LocalMutationError, block_lease, store};
use anyhow::Result;
use emulebb_metadata::JobToken;
use std::time::Instant;

pub(super) const WORK_BYTES: usize = 1024 * 1024;

/// Process-local evidence only. This is neither saved priority nor a claim that
/// cancellation/retirement has released the execution's backing.
#[derive(Debug, Clone, Copy)]
pub struct DownloadSchedulingState {
    pub rare: bool,
    pub endgame: bool,
    pub session_bytes: u64,
    pub last_payload_at: Option<Instant>,
}

impl Ed2kTransferRuntime {
    /// Called only by the existing bounded blocking owner. Refuse contention
    /// instead of parking a work credit behind a payload producer's job gate.
    pub(super) fn read_download_scheduling_state(
        &self,
        token: JobToken,
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
        let rare = manifest.pieces.iter().any(|piece| {
            piece.state != Ed2kTransferState::Verified
                && u64::from(piece.piece_index) * manifest.piece_size < manifest.file_size
                && frequencies.get(piece.piece_index as usize) == Some(&1)
        });
        let endgame = manifest.completed
            || manifest.final_rehash_pending
            || block_lease::download_is_in_endgame(
                manifest.file_size,
                manifest.durable_present_bytes(),
                self.download_speed_bytes_per_sec(token),
            );
        let (session_bytes, last_payload_at) = self.download_payload_observation(token);
        // Logical stop/removal may retire authority while the read computes.
        if self.active_job_session(token).is_none() {
            return Ok(None);
        }
        Ok(Some(DownloadSchedulingState {
            rare,
            endgame,
            session_bytes,
            last_payload_at,
        }))
    }
}

#[cfg(test)]
mod tests;
