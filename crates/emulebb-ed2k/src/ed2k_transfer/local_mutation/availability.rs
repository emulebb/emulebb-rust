//! Native probes run in the existing retained filesystem owner, outside SQLite.
use super::read_result::RetainedRead;
use super::*;
use crate::ed2k_transfer as transfer;
use emulebb_metadata::{
    AvailabilitySource, LocalContentAvailability as Availability, MetadataAvailabilityCandidate,
    MetadataAvailabilityCut, MetadataStore,
};

pub(super) const WORKSPACE: usize = 2 * 1024 * 1024;
// One row per indexed page, at most 64 rows including skipped history rows and
// three end-of-stream seeks. No operation accumulates a copy/history container.
const MAX_STEPS: usize = 64;
const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct ScanBudget {
    steps: usize,
    bytes: usize,
}

pub(super) fn changed_to_busy(error: anyhow::Error) -> anyhow::Error {
    if error.is::<emulebb_metadata::MetadataAvailabilityChanged>() {
        LocalMutationError::Busy.into()
    } else {
        error
    }
}

/// A current fingerprint proves presence only. Neither this read nor explicit
/// redownload grants adoption, deletion or storage ownership of an existing file.
fn probe(candidate: &MetadataAvailabilityCandidate) -> Availability {
    use transfer::ingest;
    let path = crate::long_path::long_path(&candidate.path);
    let path = if candidate.source == AvailabilitySource::Payload {
        path.join(transfer::PAYLOAD_FILE_NAME)
    } else {
        path
    };
    let Some(parent) = path.parent() else {
        return Availability::Unavailable;
    };
    let root = candidate.root.as_deref().map(crate::long_path::long_path);
    let root = root.as_deref().unwrap_or(parent);
    if !candidate.root_accessible || !path.starts_with(root) {
        return Availability::Unavailable;
    }
    let (Some(root_before), Some(parent_before)) = (
        ingest::native_directory_identity(root),
        ingest::native_directory_identity(parent),
    ) else {
        return Availability::Unavailable;
    };
    let result = match ingest::open_regular_file_without_follow(&path) {
        Ok(file) => {
            let current = file
                .metadata()
                .ok()
                .and_then(|m| ingest::native_file_fingerprint_from_handle(&file, &m));
            if candidate
                .fingerprint
                .as_ref()
                .zip(current.as_ref())
                .is_some_and(|(expected, current)| {
                    expected.size_bytes == candidate.size_bytes && expected.safely_matches(current)
                })
            {
                Availability::Present
            } else {
                Availability::Unavailable
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // WHY: NotFound alone includes disconnected roots and missing parent
            // trees. Only an absent leaf under two stable native directory
            // observations can be classified absent; every other error is unknown.
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Availability::ConfirmedAbsent
                }
                _ => Availability::Unavailable,
            }
        }
        Err(_) => Availability::Unavailable,
    };
    if ingest::native_directory_identity(root) != Some(root_before)
        || ingest::native_directory_identity(parent) != Some(parent_before)
    {
        Availability::Unavailable
    } else {
        result
    }
}

pub(super) fn scan(
    metadata: &MetadataStore,
    hash: &str,
    cut: &MetadataAvailabilityCut,
    budget: &mut ScanBudget,
) -> Result<(Availability, Option<transfer::Ed2kCurrentLocalFileEvidence>)> {
    let mut availability = Availability::ConfirmedAbsent;
    for source in [
        AvailabilitySource::Library,
        AvailabilitySource::Delivered,
        AvailabilitySource::Payload,
    ] {
        let mut cursor = 0;
        loop {
            if budget.steps == MAX_STEPS || budget.bytes == MAX_DECODED_BYTES {
                return Ok((Availability::Unavailable, None));
            }
            budget.steps += 1;
            let Some(step) = metadata.next_download_availability(
                hash,
                source,
                cursor,
                cut,
                (MAX_DECODED_BYTES - budget.bytes).min(WORKSPACE),
            )?
            else {
                break;
            };
            cursor = step.key;
            budget.bytes = budget.bytes.saturating_add(step.charged_bytes);
            if budget.bytes > MAX_DECODED_BYTES {
                return Ok((Availability::Unavailable, None));
            }
            let Some(candidate) = step.candidate else {
                continue;
            };
            match probe(&candidate) {
                Availability::ConfirmedAbsent => {}
                Availability::Unavailable => availability = Availability::Unavailable,
                Availability::Present => {
                    let path = if source == AvailabilitySource::Payload {
                        candidate.path.join(transfer::PAYLOAD_FILE_NAME)
                    } else {
                        candidate.path
                    };
                    let native = emulebb_metadata::NativePath::from(path.as_path());
                    return Ok((
                        Availability::Present,
                        Some(transfer::Ed2kCurrentLocalFileEvidence {
                            display_name: native.display_file_name().unwrap_or_default(),
                            file_size: candidate.size_bytes,
                            path: native.display_path(),
                            kind: match source {
                                AvailabilitySource::Library => {
                                    transfer::Ed2kCurrentLocalFileKind::Shared
                                }
                                AvailabilitySource::Delivered => {
                                    transfer::Ed2kCurrentLocalFileKind::Delivered
                                }
                                AvailabilitySource::Payload => {
                                    transfer::Ed2kCurrentLocalFileKind::ManagedPayload
                                }
                            },
                        }),
                    ));
                }
            }
        }
    }
    Ok((availability, None))
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_availability_read(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        hash: &str,
    ) -> Result<oneshot::Receiver<Result<RetainedRead<transfer::Ed2kDownloadEvidence>>>> {
        ensure!(hash.len() == 32, LocalMutationError::TooLarge);
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        let lease = Self::reserve_long_fs(&mut state, WORKSPACE)?;
        let hash = hash.to_owned();
        let metadata = runtime.metadata.clone();
        let epoch = Arc::clone(&runtime.category_root_epoch);
        let (send, receive) = oneshot::channel();
        Self::spawn_unit(&mut state, lease, move |lease| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let root_cut = epoch.load(std::sync::atomic::Ordering::Acquire);
                ensure!(root_cut.is_multiple_of(2), LocalMutationError::Busy);
                let cut = metadata.capture_download_availability()?;
                let (availability, present_file) =
                    scan(&metadata, &hash, &cut, &mut ScanBudget::default())?;
                let active_job = metadata.active_download_job(&hash)?.map(|job| {
                    transfer::Ed2kActiveDownloadEvidence {
                        token: job.token,
                        display_name: job.display_name,
                        expected_size_bytes: job.expected_size_bytes,
                    }
                });
                let previously_completed = metadata.download_history_by_hash(&hash)?.map(|entry| {
                    transfer::Ed2kPreviouslyCompletedEvidence {
                        display_name: entry.display_name,
                        file_size: entry.file_size,
                        aich_root: entry.aich_root,
                        first_completed_at_s: entry.first_completed_at_s,
                        last_completed_at_s: entry.last_completed_at_s,
                    }
                });
                metadata.validate_download_availability(&cut)?;
                ensure!(
                    epoch.load(std::sync::atomic::Ordering::Acquire) == root_cut,
                    LocalMutationError::Busy
                );
                let result = transfer::Ed2kDownloadEvidence {
                    active_job,
                    availability,
                    present_file,
                    previously_completed,
                };
                let mut retained = lease.take_result();
                retained.shrink(1024 * 1024)?;
                Ok(RetainedRead::new(result, retained))
            }));
            let (result, outcome) = match result {
                Ok(result) => (result.map_err(changed_to_busy), 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = send.send(result);
            outcome
        });
        Ok(receive)
    }
}

#[cfg(test)]
mod tests;
