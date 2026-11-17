//! Shared-content presentation updates use the existing retained publication owner.
use super::*;
use crate::ed2k_transfer as transfer;
use std::sync::atomic::Ordering;
const WORKSPACE: usize = PUBLICATION_WORKSPACE + 768 * 1024;
impl LocalMutationRegistry {
    fn submit_content_metadata(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
        watch: Option<(u64, u64)>,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
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
        Self::spawn_unit(&mut state, lease, move |lease| {
            let mut committed = false;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let hash_text = hash.to_string();
                let _content =
                    transfer::store::scoped_lock(&locks, hash_text.clone()).blocking_lock_owned();
                let _stripe = eligibility.begin_mutation(&[hash.0])?;
                let mutation = priority.is_some() || comment.is_some();
                let observed = metadata.capture_local_ingest_jobs(&[hash_text.clone()])?[0].token;
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
                    metadata
                        .update_shared_content_metadata(
                            &hash_text,
                            priority.as_ref().map(|v| (v.0.as_str(), v.1)),
                            comment.as_ref().map(|v| (v.0.as_str(), v.1)),
                        )?
                        .ok_or_else(|| anyhow!("missing shared content or current download job"))?
                } else {
                    observed
                };
                committed = mutation;
                #[cfg(test)]
                if let Some((reached, release)) = gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                if let Some(token) = token.filter(|_| mutation) {
                    if let Some(current) = cache
                        .blocking_lock()
                        .get_mut(&token.job_id)
                        .filter(|m| m.token == token)
                    {
                        let permit = resident_write.take().ok_or_else(|| {
                            anyhow!("content cache lacks preadmitted write credit")
                        })?;
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
                Ok(publication.watch_accepted())
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
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    pub(in crate::ed2k_transfer) async fn persist_content_metadata(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
    ) -> Result<()> {
        self.publish_content_command(hash, priority, comment, None)
            .await
            .map(|_| ())
    }
    pub(in crate::ed2k_transfer) async fn persist_category_publication(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        watch: (u64, u64),
    ) -> Result<bool> {
        self.publish_content_command(hash, None, None, Some(watch))
            .await
    }
    async fn publish_content_command(
        &self,
        hash: emulebb_kad_proto::Ed2kHash,
        priority: Option<(&str, bool)>,
        comment: Option<(&str, u8)>,
        watch: Option<(u64, u64)>,
    ) -> Result<bool> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            match self
                .local_mutations
                .submit_content_metadata(self, hash, priority, comment, watch)
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
