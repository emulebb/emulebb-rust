//! Admission and scheduler publication share the existing profile owner.
use super::*;
use crate::{DownloadSummary, download_attempts::DownloadAttemptControl};
use anyhow::Context;
use emulebb_ed2k::ed2k_transfer::{Ed2kTransferRuntime, RetainedRead};
use emulebb_metadata::{DownloadJobRequest, MetadataDownloadInitialPeers};

pub(crate) struct DownloadCreateCommand {
    pub request: DownloadJobRequest,
    pub category: Option<String>,
    pub redownload: bool,
    pub aich: Option<String>,
    pub peers: MetadataDownloadInitialPeers,
    pub runtime: Arc<Ed2kTransferRuntime>,
    pub attempts: Arc<DownloadAttemptControl>,
}

impl DownloadCreateCommand {
    pub(super) fn bytes(&self) -> usize {
        self.request
            .file_hash
            .capacity()
            .saturating_add(self.request.display_name.capacity())
            .saturating_add(self.category.as_ref().map_or(0, String::capacity))
            .saturating_add(self.aich.as_ref().map_or(0, String::capacity))
            .saturating_add(self.peers.payload_bytes().unwrap_or(usize::MAX))
    }
}

impl PersistenceOwner {
    pub(crate) async fn create_download(
        &self,
        command: DownloadCreateCommand,
    ) -> anyhow::Result<(bool, RetainedRead<DownloadSummary>)> {
        command.peers.payload_bytes()?;
        let charge = command
            .bytes()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(FIXED_CHARGE + 1024 * 1024))
            .ok_or(PersistenceError::TooLarge)?;
        match self
            .submit_reserved(charge, || {
                Ok(Command::Category(
                    category::CategoryCommand::CreateDownload(command),
                ))
            })
            .await?
        {
            Response::DownloadCreated(result) => result,
            _ => Err(PersistenceError::Worker.into()),
        }
    }
}

pub(super) async fn process(
    state: &Arc<Mutex<CoreState>>,
    mut command: DownloadCreateCommand,
    #[cfg(test)] publication_gate: &StdMutex<Option<Arc<PublicationGate>>>,
) -> anyhow::Result<(bool, RetainedRead<DownloadSummary>)> {
    // Category mutations use this same serialized owner. Resolve here so a
    // disconnected caller cannot drop a separate category guard midway.
    command.request.category_id = match command.category.as_deref() {
        None => None,
        Some(name) => {
            anyhow::ensure!(
                crate::valid_category_name(name),
                "category does not match a configured category"
            );
            let state = state.lock().await;
            Some(
                state
                    .categories
                    .values()
                    .find(|category| category.name.eq_ignore_ascii_case(name))
                    .context("category does not match a configured category")?
                    .id,
            )
        }
    };
    let admitted = command
        .runtime
        .admit_download_job(
            &command.request,
            command.redownload,
            command.aich.as_deref(),
            &command.peers,
        )
        .await?;
    #[cfg(test)]
    let gate = publication_gate.lock().unwrap().clone();
    #[cfg(test)]
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    // Publish immediately after durable admission, before response projection
    // can fail or the requesting connection can discard its reply.
    if admitted.created {
        command.attempts.changed.notify_one();
    }
    let _fence = command.runtime.lock_category_publication().await;
    let running = command.attempts.snapshot();
    let verifying = command.runtime.verifying_downloads().await;
    let state = state.lock().await;
    let category = admitted
        .job
        .category_id
        .map(|id| {
            state
                .categories
                .get(&id)
                .context("admitted job category is missing from coherent Core state")
        })
        .transpose()?;
    let created = admitted.created;
    let bytes = 4096
        + admitted.job.display_name.capacity()
        + admitted.job.file_hash.capacity()
        + category.map_or(0, |category| category.name.len());
    let projected = admitted
        .try_project(bytes, |admitted| {
            Ok(crate::downloads::summary_from_job(
                admitted.job,
                category.map(|category| category.name.as_str()),
                &running,
                &verifying,
            ))
        })
        .context("job admission completed; response projection failed")?;
    Ok((created, projected))
}

#[cfg(test)]
mod tests;
