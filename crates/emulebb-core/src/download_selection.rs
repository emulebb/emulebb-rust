//! Selection is the only transition that hydrates an unfinished execution.
#[cfg(test)]
use crate::download_attempts::AdmissionDenied;
use crate::{EmulebbCore, Transfer, download_attempts::DownloadAttemptGuard};
use anyhow::{Context, Result};
use emulebb_metadata::DownloadIntent;
use std::collections::BTreeMap;

impl EmulebbCore {
    /// Reserve a live slot before storage/hydration. A stale stopped/faulted
    /// token cannot be implicitly restarted during the asynchronous handoff.
    #[cfg(test)]
    pub(crate) async fn select_download_execution(
        &self,
        id: emulebb_metadata::JobId,
    ) -> Result<Option<(DownloadAttemptGuard, Transfer)>> {
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(None);
        };
        let mut guard = match self
            .download_attempts
            .try_enter(job.token, job.file_hash.parse()?)
        {
            Ok(guard) => guard,
            Err(AdmissionDenied::Duplicate | AdmissionDenied::Busy) => return Ok(None),
            Err(AdmissionDenied::Exhausted) => anyhow::bail!("download admission nonce exhausted"),
        };
        drop(job);
        Ok(self
            .hydrate_selected_download(&mut guard)
            .await?
            .map(|transfer| (guard, transfer)))
    }

    /// The scheduler reserves this slot before spawning its worker. Selection
    /// may wait for native ownership without creating unbounded pending tasks.
    pub(crate) async fn hydrate_selected_download(
        &self,
        guard: &mut DownloadAttemptGuard,
    ) -> Result<Option<Transfer>> {
        let _category_guard = self.category_mutation_gate.lock().await;
        self.persistence_owner.check_coherent_state()?;
        let Some(job) = self
            .ed2k_transfers
            .download_job(guard.token().job_id)
            .await?
        else {
            return Ok(None);
        };
        if job.token != guard.token()
            || guard.cancellation().is_cancelled()
            || job.intent != DownloadIntent::Started
            || job.storage_failure.is_some()
            || job.removed_at_s.is_some()
            || job.completed_at_s.is_some()
            || job.expected_size_bytes.is_none()
        {
            return Ok(None);
        }
        let hash = job.file_hash.parse()?;
        let temp = self.download_temp_selection(&job).await?;
        let token = job.token;
        drop(job);
        // Unlike explicit start, selection uses the previously healthy token.
        // A concurrent stop or storage fault changes it and refuses this write.
        let started = self
            .ed2k_transfers
            .begin_download_job_execution(token, Some(&temp))
            .await?;
        let Some(job) = started.as_ref() else {
            return Ok(None);
        };
        if !guard.rebind(job.token) {
            return Ok(None);
        }
        let created_at = job.created_at_s;
        let selected = emulebb_ed2k::ed2k_transfer::new_transfer_job(
            job.token,
            hash,
            job.display_name.clone(),
            job.expected_size_bytes
                .context("selected job lost its expected size")?,
        );
        drop(started);
        drop(_category_guard);
        let manifest = self.ed2k_transfers.ensure_job(&selected).await?;
        let mut transfer = self.transfer_from_manifest(&manifest, "downloading")?;
        let category = manifest.category_id;
        drop(manifest);
        if guard.cancellation().is_cancelled() {
            return Ok(None);
        }
        let observations = {
            let mut state = self.state.lock().await;
            let live = self.download_attempts.snapshot();
            state
                .transfers
                .retain(|_, transfer| live.iter().any(|(token, _)| *token == transfer.job_token()));
            transfer.category_id = category;
            transfer.category_name = category
                .and_then(|id| state.categories.get(&id))
                .map(|category| category.name.clone());
            transfer.added_at = Some(created_at);
            state
                .transfers
                .insert(transfer.hash.clone(), transfer.clone());
            // Hash-leading ordered seeks avoid unrelated search history. Replay
            // only bounded, genuine live evidence; persisted AICH strings never vote.
            let mut votes = BTreeMap::new();
            for ((_, _), evidence) in state
                .kad_aich_search_votes
                .range((transfer.hash.clone(), String::new())..)
                .take_while(|((candidate, _), _)| candidate == &transfer.hash)
                .take(4)
            {
                for (root, ip) in evidence.observations() {
                    if votes.len() == 64 {
                        break;
                    }
                    votes.entry(ip).or_insert(root);
                }
            }
            votes
                .into_iter()
                .map(|(ip, root)| (root, ip))
                .collect::<Vec<_>>()
        };
        if !observations.is_empty() {
            self.ed2k_transfers
                .record_network_aich_observations(guard.token(), &observations)
                .await?;
        }
        Ok(Some(transfer))
    }
}
