use std::{collections::HashMap, error::Error, fmt};

use anyhow::Result;
use emulebb_ed2k::ed2k_transfer::Ed2kDownloadEvidence;
use serde::{Deserialize, Serialize};

use crate::{EmulebbCore, ParsedEd2kLink};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownFilePolicy {
    #[default]
    Reject,
    Redownload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DownloadConflictKind {
    ActiveTransfer,
    PresentLocalFile,
    PreviouslyCompleted,
    IdentityMismatch,
    RequestDuplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadConflictEvidence {
    pub hash: String,
    pub kind: DownloadConflictKind,
    pub requested_name: String,
    pub requested_size_bytes: u64,
    pub recorded_name: String,
    pub recorded_size_bytes: u64,
    pub transfer_state: Option<String>,
    pub current_paths: Vec<String>,
    pub first_completed_at_ms: Option<i64>,
    pub last_completed_at_ms: Option<i64>,
    pub redownload_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadConflictError {
    pub conflicts: Vec<DownloadConflictEvidence>,
}

impl fmt::Display for DownloadConflictError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one or more requested files already have local download evidence")
    }
}

impl Error for DownloadConflictError {}

#[derive(Debug, Default)]
pub(crate) struct DownloadPreflight {
    redownload_by_hash: HashMap<String, bool>,
}

impl DownloadPreflight {
    pub(crate) fn should_redownload(&self, file_hash: &str) -> bool {
        self.redownload_by_hash
            .get(file_hash)
            .copied()
            .unwrap_or(false)
    }
}

impl EmulebbCore {
    pub(crate) async fn preflight_downloads(
        &self,
        requests: &[ParsedEd2kLink],
        policy: KnownFilePolicy,
    ) -> Result<DownloadPreflight> {
        let mut first_by_hash: HashMap<&str, &ParsedEd2kLink> = HashMap::new();
        let mut conflicts = Vec::new();
        let mut preflight = DownloadPreflight::default();

        for request in requests {
            if let Some(first) = first_by_hash.insert(&request.file_hash, request) {
                conflicts.push(conflict(
                    request,
                    DownloadConflictKind::RequestDuplicate,
                    &first.name,
                    first.size_bytes,
                    false,
                ));
                continue;
            }

            let evidence = self
                .ed2k_transfers
                .download_evidence(&request.file_hash)
                .await?;
            if let Some((recorded_name, recorded_size)) = identity_mismatch(request, &evidence) {
                conflicts.push(conflict(
                    request,
                    DownloadConflictKind::IdentityMismatch,
                    recorded_name,
                    recorded_size,
                    false,
                ));
                continue;
            }

            let mut has_overrideable_evidence = false;
            if let Some(active) = evidence.active_transfer.as_ref() {
                let mut item = conflict(
                    request,
                    DownloadConflictKind::ActiveTransfer,
                    &active.display_name,
                    active.file_size,
                    false,
                );
                item.transfer_state = Some(
                    if active.final_rehash_pending {
                        "completing"
                    } else {
                        "downloading"
                    }
                    .to_string(),
                );
                conflicts.push(item);
            }
            if !evidence.current_local_files.is_empty() {
                has_overrideable_evidence = true;
                if policy == KnownFilePolicy::Reject {
                    let local = &evidence.current_local_files[0];
                    let mut item = conflict(
                        request,
                        DownloadConflictKind::PresentLocalFile,
                        &local.display_name,
                        local.file_size,
                        true,
                    );
                    item.current_paths = evidence
                        .current_local_files
                        .iter()
                        .map(|entry| entry.path.clone())
                        .collect();
                    conflicts.push(item);
                }
            }
            if let Some(history) = evidence.previously_completed.as_ref() {
                has_overrideable_evidence = true;
                if policy == KnownFilePolicy::Reject {
                    let mut item = conflict(
                        request,
                        DownloadConflictKind::PreviouslyCompleted,
                        &history.display_name,
                        history.file_size,
                        true,
                    );
                    item.first_completed_at_ms = Some(history.first_completed_at_ms);
                    item.last_completed_at_ms = Some(history.last_completed_at_ms);
                    conflicts.push(item);
                }
            }
            preflight.redownload_by_hash.insert(
                request.file_hash.clone(),
                policy == KnownFilePolicy::Redownload
                    && evidence.active_transfer.is_none()
                    && has_overrideable_evidence,
            );
        }

        if conflicts.is_empty() {
            Ok(preflight)
        } else {
            Err(anyhow::Error::new(DownloadConflictError { conflicts }))
        }
    }
}

fn identity_mismatch<'a>(
    request: &ParsedEd2kLink,
    evidence: &'a Ed2kDownloadEvidence,
) -> Option<(&'a str, u64)> {
    if let Some(active) = evidence.active_transfer.as_ref()
        && active.file_size != request.size_bytes
    {
        return Some((&active.display_name, active.file_size));
    }
    if let Some(local) = evidence
        .current_local_files
        .iter()
        .find(|local| local.file_size != request.size_bytes)
    {
        return Some((&local.display_name, local.file_size));
    }
    evidence
        .previously_completed
        .as_ref()
        .filter(|history| history.file_size != request.size_bytes)
        .map(|history| (history.display_name.as_str(), history.file_size))
}

fn conflict(
    request: &ParsedEd2kLink,
    kind: DownloadConflictKind,
    recorded_name: &str,
    recorded_size_bytes: u64,
    redownload_allowed: bool,
) -> DownloadConflictEvidence {
    DownloadConflictEvidence {
        hash: request.file_hash.clone(),
        kind,
        requested_name: request.name.clone(),
        requested_size_bytes: request.size_bytes,
        recorded_name: recorded_name.to_string(),
        recorded_size_bytes,
        transfer_state: None,
        current_paths: Vec::new(),
        first_completed_at_ms: None,
        last_completed_at_ms: None,
        redownload_allowed,
    }
}
