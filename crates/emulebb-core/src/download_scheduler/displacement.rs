//! One rare-opportunity displacement, with actual owner retirement accounting.
use super::*;
use emulebb_metadata::JobToken;
use std::time::Instant;

impl EmulebbCore {
    pub(super) async fn ready_source_is_rare(&self, entry: &ReadyDownload) -> bool {
        use crate::download_preparation::DownloadPreparation;
        let result = match &entry.source {
            DownloadPreparation::Direct(source) => {
                self.ed2k_transfers
                    .download_source_has_rare_part(
                        entry.guard.token(),
                        source.peer.availability().user_hash,
                    )
                    .await
            }
            DownloadPreparation::Callback(source) => {
                self.ed2k_transfers
                    .download_live_source_has_rare_part(
                        entry.guard.token(),
                        source.file_size,
                        source.user_hash,
                        std::sync::Arc::clone(&source.available_parts),
                        source.observed_at,
                    )
                    .await
            }
            _ => Ok(false),
        };
        match result {
            Ok(rare) => rare,
            Err(error) => {
                tracing::debug!(job_id=%entry.guard.token().job_id,%error,"ready scarcity observation unavailable");
                false
            }
        }
    }

    pub(super) async fn displace_ordinary_download(
        &self,
        ready: &ReadyDownload,
        shutdown: &CancellationToken,
    ) {
        let owners = self.download_attempts.displacement_owners();
        // A requested stop/yield owns its slot until the producer and checkpoint
        // receipt finish. Do not displace more jobs while that owner drains.
        if owners.iter().any(|owner| {
            owner.draining || self.ed2k_transfers.download_yield_requested(owner.token)
        }) {
            return;
        }
        let mut candidate: Option<(Instant, JobToken, u64)> = None;
        for owner in owners
            .into_iter()
            .filter(|owner| !owner.protected_readiness)
        {
            let Ok(Some(state)) = self
                .ed2k_transfers
                .download_scheduling_state(owner.token)
                .await
            else {
                continue;
            };
            if state.yielding {
                return;
            }
            if state.acquiring_rare || state.endgame {
                continue;
            }
            let last = state.last_payload_at.unwrap_or(owner.selected_at);
            if candidate.as_ref().is_none_or(|(previous, token, _)| {
                (last, owner.token.job_id) < (*previous, token.job_id)
            }) {
                candidate = Some((last, owner.token, state.session_bytes));
            }
        }
        let Some((_, token, bytes)) = candidate else {
            return;
        };
        if !self.ready_source_is_rare(ready).await
            || shutdown.is_cancelled()
            || ready.guard.cancellation().is_cancelled()
            || ready
                .deadline()
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return;
        }
        match self
            .ed2k_transfers
            .request_download_yield(token, bytes)
            .await
        {
            Ok(true) => {
                self.download_attempts.mark_yielding(token);
            }
            Ok(false) => {}
            Err(error) => {
                tracing::debug!(job_id=%token.job_id,%error,"download displacement deferred")
            }
        }
    }
}
