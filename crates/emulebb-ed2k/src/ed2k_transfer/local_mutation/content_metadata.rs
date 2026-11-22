//! Shared-content presentation updates use the existing retained publication owner.
use super::*;
use crate::ed2k_transfer as transfer;
use std::sync::atomic::Ordering;
const WORKSPACE: usize = PUBLICATION_WORKSPACE + 768 * 1024;
struct ContentMetadataOutcome {
    accepted: bool,
    metadata_found: bool,
    sharing_change: Option<bool>,
}
impl LocalMutationRegistry {
    fn submit_content_metadata(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
        watch: Option<(u64, u64)>,
        sharing: Option<bool>,
    ) -> Result<oneshot::Receiver<Result<ContentMetadataOutcome>>> {
        ensure!(
            priority.is_none_or(|v| v.0.len() <= 64) && comment.is_none_or(|v| v.0.len() <= 65_536),
            LocalMutationError::TooLarge
        );
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_unit(&mut state, WORKSPACE, true, false)?;
        let priority = priority.map(|(s, b)| (s.to_owned(), b));
        let comment = comment.map(|(s, b)| (s.to_owned(), b));
        let metadata = runtime.metadata.clone();
        let cache = Arc::clone(&runtime.manifest_cache);
        let residents = Arc::clone(&self.residents);
        let locks = Arc::clone(&runtime.content_locks);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let queue = Arc::clone(&runtime.upload_queue);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let publication =
            super::publication::ContentPublication::new(runtime).with_watch(hash.0, watch);
        let (sender, receipt) = oneshot::channel();
        #[cfg(test)]
        let gate = state.publication_gate.take();
        Self::spawn_unit_reply(&mut state, lease, sender, move |lease| {
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let hash_text = hash.to_string();
                let _content =
                    transfer::store::scoped_lock(&locks, hash_text.clone()).blocking_lock_owned();
                let _stripe = eligibility.begin_mutation(&[hash.0])?;
                let sharing_change = sharing
                    .map(|enabled| metadata.set_library_sharing_enabled(&hash_text, enabled))
                    .transpose()?
                    .flatten();
                if sharing.is_some() && sharing_change.is_none() {
                    return Ok(ContentMetadataOutcome {
                        accepted: false,
                        metadata_found: false,
                        sharing_change: None,
                    });
                }
                committed = sharing_change == Some(true);
                let mutation = priority.is_some() || comment.is_some();
                let observed =
                    metadata.capture_local_ingest_jobs(std::slice::from_ref(&hash_text))?[0].token;
                let mut resident_write = if let Some(token) = observed.filter(|_| mutation) {
                    if cache
                        .blocking_lock()
                        .get(&token.job_id)
                        .is_some_and(|m| m.token == token)
                    {
                        Some(residents.reserve(token.job_id)?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let token = if mutation {
                    let updated = metadata.update_shared_content_metadata(
                        &hash_text,
                        priority.as_ref().map(|v| (v.0.as_str(), v.1)),
                        comment.as_ref().map(|v| (v.0.as_str(), v.1)),
                    )?;
                    let Some(token) = updated else {
                        return Ok(ContentMetadataOutcome {
                            accepted: false,
                            metadata_found: false,
                            sharing_change,
                        });
                    };
                    token
                } else {
                    observed
                };
                committed |= mutation;
                #[cfg(test)]
                if let Some((reached, release)) = gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                if let Some(token) = token.filter(|_| mutation)
                    && let Some(current) = cache
                        .blocking_lock()
                        .get_mut(&token.job_id)
                        .filter(|m| m.token == token)
                {
                    let permit = resident_write
                        .take()
                        .ok_or_else(|| anyhow!("content cache lacks preadmitted write credit"))?;
                    current.write_with(permit, |current| {
                        if let Some((value, auto)) = &priority {
                            current.upload_priority = value.clone();
                            current.auto_upload_priority = *auto;
                        }
                        if let Some((value, rating)) = &comment {
                            current.comment = value.clone();
                            current.rating = *rating;
                        }
                        Ok(())
                    })?;
                }
                if let Some((value, auto)) = &priority {
                    let mut queue = queue.blocking_lock();
                    let count = queue.upload_client_count_for_file(&hash_text);
                    queue.update_file_priority(
                        &hash_text,
                        transfer::upload_queue::upload_priority_score(value, *auto, count),
                    );
                }
                drop(priority);
                drop(comment);
                publication.publish(
                    hash,
                    lease,
                    super::publication::PublicationGuards {
                        content: _content,
                        stripe: _stripe,
                        job: None,
                    },
                )?;
                Ok(ContentMetadataOutcome {
                    accepted: publication.watch_accepted(),
                    metadata_found: true,
                    sharing_change,
                })
            }));
            let (result, outcome) = match result {
                Ok(Ok(accepted)) => (Ok(accepted), 0),
                Ok(Err(error)) if committed => {
                    tracing::error!(%error,"shared metadata committed but publication failed");
                    (Err(LocalMutationError::Committed.into()), 1)
                }
                Ok(Err(error)) => (Err(error), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            if outcome != 0 {
                dirty.store(true, Ordering::Release);
                failed.store(true, Ordering::Release);
            }
            (result, outcome)
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// Edit a client hash without requiring an available payload or a job.
    /// Admitted SQL/cache publication finishes independently of the caller.
    /// False identifies a hash outside the client library; no content is created.
    pub async fn update_library_file_metadata(
        &self,
        file_hash: &str,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
    ) -> Result<bool> {
        ensure!(
            priority.is_some() || comment.is_some(),
            "metadata edit is empty"
        );
        self.publish_content_command(file_hash.parse()?, priority, comment, None, None)
            .await
            .map(|outcome| outcome.metadata_found)
    }

    pub(in crate::ed2k_transfer) async fn persist_content_metadata(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
    ) -> Result<()> {
        let outcome = self
            .publish_content_command(hash, priority, comment, None, None)
            .await?;
        ensure!(
            priority.is_none() && comment.is_none() || outcome.metadata_found,
            "client library content is missing"
        );
        Ok(())
    }
    pub(in crate::ed2k_transfer) async fn persist_category_publication(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        watch: (u64, u64),
    ) -> Result<bool> {
        self.publish_content_command(hash, None, None, Some(watch), None)
            .await
            .map(|outcome| outcome.accepted)
    }
    /// Persist a complete-library hash policy and publish its current eligibility.
    /// Admitted work retains ownership after caller disconnect. Unknown hashes
    /// return None; Some(false) reports an explicitly unchanged durable value.
    pub async fn set_library_sharing_enabled(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        enabled: bool,
    ) -> Result<Option<bool>> {
        self.publish_content_command(hash, None, None, None, Some(enabled))
            .await
            .map(|outcome| outcome.sharing_change)
    }
    async fn publish_content_command(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
        watch: Option<(u64, u64)>,
        sharing: Option<bool>,
    ) -> Result<ContentMetadataOutcome> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            match self
                .local_mutations
                .submit_content_metadata(self, hash, priority, comment, watch, sharing)
            {
                Ok(receipt) => return receipt.await.map_err(|_| LocalMutationError::Unknown)?,
                Err(error)
                    if matches!(
                        error.downcast_ref::<LocalMutationError>(),
                        Some(LocalMutationError::Busy)
                    ) =>
                {
                    self.local_mutations
                        .wait_for_completion(capacity_revision)
                        .await?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests;
