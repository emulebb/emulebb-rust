//! Retained physical validation for independent verified download payloads.
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{JobId, MetadataDownloadPayload, MetadataStore};

// Within the existing 2 MiB long-filesystem sublimit. Provider pages account
// text twice and native paths at least four times; their live representation
// plus one exact snapshot recheck and path/probe scratch fit this workspace.
const WORKSPACE: usize = 2 * 1024 * 1024;
pub(in crate::ed2k_transfer) enum Request<'a> {
    Page(Option<JobId>, usize),
    Eligibility(&'a [[u8; 16]]),
}
enum OwnedRequest {
    Page(Option<JobId>, usize),
    Eligibility(Vec<[u8; 16]>),
}
#[derive(Debug)]
pub(in crate::ed2k_transfer) struct PayloadPage {
    pub entries: Vec<transfer::Ed2kSharedEntry>,
    pub cursor: Option<JobId>,
    pub(super) _lease: CapacityLease,
}
#[derive(Debug)]
pub(in crate::ed2k_transfer) enum Output {
    Page(PayloadPage),
    Eligibility(
        Option<Vec<(bool, Option<emulebb_metadata::MetadataPartialOffer>)>>,
        CapacityLease,
    ),
}

/// No SQL connection or catalog lock is held during these native operations.
/// A matching byte fingerprint is serving evidence, never deletion authority.
pub(super) struct PhysicalProof {
    normalized: std::path::PathBuf,
    evidence: emulebb_metadata::NativeFileIdentityEvidence,
}
impl PhysicalProof {
    pub(super) fn admit(
        self,
        metadata: &MetadataStore,
        candidate: &MetadataDownloadPayload,
    ) -> Result<bool> {
        metadata.admit_download_payload(candidate, &self.normalized, self.evidence)
    }
}
pub(super) fn physical_proof(candidate: &MetadataDownloadPayload) -> Result<Option<PhysicalProof>> {
    if super::job_storage::validate_storage(&candidate.storage).is_err() {
        return Ok(None);
    }
    let path =
        crate::long_path::long_path(&candidate.storage.path).join(transfer::PAYLOAD_FILE_NAME);
    let file = match transfer::ingest::open_regular_file_without_follow(&path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let opened = file.metadata()?;
    let Some(current) = transfer::ingest::native_file_fingerprint_from_handle(&file, &opened)
    else {
        return Ok(None);
    };
    if !candidate.fingerprint.safely_matches(&current) {
        return Ok(None);
    }
    let evidence =
        transfer::ingest::native_file_identity_evidence_from_handle(&file, &opened, &current)?;
    let normalized =
        match std::fs::canonicalize(crate::long_path::long_path(&candidate.storage.path)) {
            Ok(parent) => parent.join(transfer::PAYLOAD_FILE_NAME),
            Err(_) => return Ok(None),
        };
    if transfer::ingest::native_directory_identity(&candidate.storage.path)
        != candidate.storage.identity
    {
        return Ok(None);
    }
    Ok(Some(PhysicalProof {
        normalized,
        evidence,
    }))
}
fn probe(metadata: &MetadataStore, candidate: &MetadataDownloadPayload) -> Result<bool> {
    match physical_proof(candidate)? {
        Some(proof) => proof.admit(metadata, candidate),
        None => Ok(false),
    }
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_payload_read(
        &self,
        metadata: &MetadataStore,
        request: Request<'_>,
    ) -> Result<oneshot::Receiver<Result<Output>>> {
        match &request {
            Request::Page(_, limit) => {
                ensure!((1..=200).contains(limit), "invalid payload catalog page")
            }
            Request::Eligibility(hashes) => {
                ensure!(hashes.len() <= 200, "invalid eligibility batch")
            }
        }
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let capacity_lease = Self::reserve_long_fs(&mut state, WORKSPACE)?;
        let request = match request {
            Request::Page(after, limit) => OwnedRequest::Page(after, limit),
            Request::Eligibility(hashes) => OwnedRequest::Eligibility(hashes.to_vec()),
        };
        let metadata = metadata.clone();
        let (send, receive) = oneshot::channel();
        #[cfg(test)]
        let gate = state.publication_gate.take();
        Self::spawn_unit(&mut state, capacity_lease, move |capacity_lease| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(test)]
                if let Some((reached, release)) = gate {
                    let _ = reached.send(());
                    let _ = release.recv();
                }
                match request {
                    OwnedRequest::Page(after, limit) => {
                        let page = metadata.download_payloads_after(after, limit)?;
                        let mut entries = Vec::with_capacity(page.entries.len());
                        for candidate in page.entries {
                            if probe(&metadata, &candidate)? {
                                entries.push(
                                    transfer::transfer_sql::shared_entry_from_catalog_entry(
                                        candidate.catalog,
                                    )?,
                                );
                            }
                        }
                        Ok(Output::Page(PayloadPage {
                            entries,
                            cursor: page.cursor,
                            _lease: capacity_lease.take_result(),
                        }))
                    }
                    OwnedRequest::Eligibility(hashes) => {
                        let Some(mut rows) = metadata.try_verified_share_batch(&hashes)? else {
                            return Ok(Output::Eligibility(None, capacity_lease.take_result()));
                        };
                        for (hash, (complete, _)) in hashes.iter().zip(rows.iter_mut()) {
                            if !*complete
                                // Complete internal payloads obey the same hash policy
                                // as root copies; partial offers remain independent.
                                && metadata.library_sharing_enabled(&hex::encode(hash))? == Some(true)
                                && let Some(candidate) =
                                    metadata.download_payload_candidate(&hex::encode(hash))?
                            {
                                *complete = probe(&metadata, &candidate)?;
                            }
                        }
                        Ok(Output::Eligibility(
                            Some(rows),
                            capacity_lease.take_result(),
                        ))
                    }
                }
            }));
            let (result, outcome) = match result {
                Ok(result) => (result, 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = send.send(result);
            outcome
        });
        Ok(receive)
    }
}
impl transfer::Ed2kTransferRuntime {
    pub(in crate::ed2k_transfer) async fn payload_catalog_page(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<PayloadPage> {
        loop {
            let capacity_revision = self.local_mutations.capacity_revision();
            match self
                .local_mutations
                .submit_payload_read(&self.metadata, Request::Page(after, limit))
            {
                Ok(receipt) => {
                    let Output::Page(page) =
                        receipt.await.map_err(|_| LocalMutationError::Unknown)??
                    else {
                        unreachable!()
                    };
                    return Ok(page);
                }
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
