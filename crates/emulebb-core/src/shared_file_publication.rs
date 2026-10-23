use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrackedPublishPhase {
    Publishing,
    Published,
    Failed,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TrackedPublishAttempt {
    pub(crate) phase: TrackedPublishPhase,
    pub(crate) last_success_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct KadFilePublishState {
    pub(crate) keywords: HashMap<String, TrackedPublishAttempt>,
    pub(crate) source: Option<TrackedPublishAttempt>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SharedKadFilePublication {
    files: Arc<Mutex<HashMap<String, KadFilePublishState>>>,
}

impl SharedKadFilePublication {
    pub(crate) fn keyword_started(&self, file_hashes: &[String], keyword: &str) {
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for file_hash in file_hashes {
            let previous_success = files
                .get(file_hash)
                .and_then(|state| state.keywords.get(keyword))
                .and_then(|attempt| attempt.last_success_at_ms);
            files
                .entry(file_hash.clone())
                .or_default()
                .keywords
                .insert(
                    keyword.to_string(),
                    TrackedPublishAttempt {
                        phase: TrackedPublishPhase::Publishing,
                        last_success_at_ms: previous_success,
                    },
                );
        }
    }

    pub(crate) fn source_started(&self, file_hash: &str) {
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = files.entry(file_hash.to_string()).or_default();
        let previous_success = state
            .source
            .and_then(|attempt| attempt.last_success_at_ms);
        state.source = Some(TrackedPublishAttempt {
            phase: TrackedPublishPhase::Publishing,
            last_success_at_ms: previous_success,
        });
    }

    pub(crate) fn keyword_finished(
        &self,
        file_hashes: &[String],
        keyword: &str,
        succeeded_at_ms: Option<i64>,
    ) {
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for file_hash in file_hashes {
            let state = files.entry(file_hash.clone()).or_default();
            let previous_success = state
                .keywords
                .get(keyword)
                .and_then(|attempt| attempt.last_success_at_ms);
            state.keywords.insert(
                keyword.to_string(),
                TrackedPublishAttempt {
                    phase: if succeeded_at_ms.is_some() {
                        TrackedPublishPhase::Published
                    } else {
                        TrackedPublishPhase::Failed
                    },
                    last_success_at_ms: succeeded_at_ms.or(previous_success),
                },
            );
        }
    }

    pub(crate) fn source_finished(&self, file_hash: &str, succeeded_at_ms: Option<i64>) {
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = files.entry(file_hash.to_string()).or_default();
        let previous_success = state
            .source
            .and_then(|attempt| attempt.last_success_at_ms);
        state.source = Some(TrackedPublishAttempt {
            phase: if succeeded_at_ms.is_some() {
                TrackedPublishPhase::Published
            } else {
                TrackedPublishPhase::Failed
            },
            last_success_at_ms: succeeded_at_ms.or(previous_success),
        });
    }

    pub(crate) fn keyword_busy(&self, file_hashes: &[String], keyword: &str) {
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for file_hash in file_hashes {
            if let Some(state) = files.get_mut(file_hash) {
                let has_previous_success = state
                    .keywords
                    .get(keyword)
                    .is_some_and(|attempt| attempt.last_success_at_ms.is_some());
                if has_previous_success {
                    if let Some(attempt) = state.keywords.get_mut(keyword) {
                        attempt.phase = TrackedPublishPhase::Published;
                    }
                } else {
                    state.keywords.remove(keyword);
                }
            }
        }
    }

    pub(crate) fn source_busy(&self, file_hash: &str) {
        if let Some(state) = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(file_hash)
        {
            if state
                .source
                .is_some_and(|attempt| attempt.last_success_at_ms.is_some())
            {
                if let Some(attempt) = state.source.as_mut() {
                    attempt.phase = TrackedPublishPhase::Published;
                }
            } else {
                state.source = None;
            }
        }
    }

    pub(crate) fn snapshot(&self, file_hash: &str) -> KadFilePublishState {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(file_hash)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn retain_only(&self, keep: &std::collections::HashSet<String>) {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|file_hash, _| keep.contains(file_hash));
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedKadFilePublication, TrackedPublishPhase};

    #[test]
    fn keyword_failure_preserves_last_success_and_busy_returns_to_due() {
        let publication = SharedKadFilePublication::default();
        let hashes = vec!["00112233445566778899AABBCCDDEEFF".to_string()];

        publication.keyword_started(&hashes, "shared");
        publication.keyword_finished(&hashes, "shared", Some(42));
        publication.keyword_started(&hashes, "shared");
        publication.keyword_finished(&hashes, "shared", None);

        let failed = publication.snapshot(&hashes[0]);
        assert_eq!(
            failed.keywords["shared"].phase,
            TrackedPublishPhase::Failed
        );
        assert_eq!(failed.keywords["shared"].last_success_at_ms, Some(42));

        publication.keyword_started(&hashes, "shared");
        publication.keyword_busy(&hashes, "shared");
        let restored = publication.snapshot(&hashes[0]);
        assert_eq!(
            restored.keywords["shared"].phase,
            TrackedPublishPhase::Published
        );
        assert_eq!(restored.keywords["shared"].last_success_at_ms, Some(42));
    }

    #[test]
    fn source_failure_preserves_last_success_and_busy_returns_to_due() {
        let publication = SharedKadFilePublication::default();
        let hash = "00112233445566778899AABBCCDDEEFF";

        publication.source_started(hash);
        publication.source_finished(hash, Some(84));
        publication.source_started(hash);
        publication.source_finished(hash, None);

        let failed = publication.snapshot(hash).source.expect("source state");
        assert_eq!(failed.phase, TrackedPublishPhase::Failed);
        assert_eq!(failed.last_success_at_ms, Some(84));

        publication.source_started(hash);
        publication.source_busy(hash);
        let restored = publication.snapshot(hash).source.expect("source state");
        assert_eq!(restored.phase, TrackedPublishPhase::Published);
        assert_eq!(restored.last_success_at_ms, Some(84));
    }

    #[test]
    fn removed_files_are_pruned() {
        let publication = SharedKadFilePublication::default();
        publication.source_started("00112233445566778899AABBCCDDEEFF");
        publication.source_started("FFEEDDCCBBAA99887766554433221100");

        publication.retain_only(&std::collections::HashSet::from([
            "00112233445566778899AABBCCDDEEFF".to_string(),
        ]));

        assert!(
            publication
                .snapshot("00112233445566778899AABBCCDDEEFF")
                .source
                .is_some()
        );
        assert!(
            publication
                .snapshot("FFEEDDCCBBAA99887766554433221100")
                .source
                .is_none()
        );
    }
}
