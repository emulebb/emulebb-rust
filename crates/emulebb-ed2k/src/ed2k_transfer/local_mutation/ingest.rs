//! One retained preparation and binding unit; no asynchronous handoff.

use super::super as transfer;
use super::*;
use emulebb_metadata::{MetadataPartialShare, MetadataTransferRange};
use std::sync::atomic::{AtomicBool, Ordering};

const PREPARED_ALLOWANCE: usize = 64 * 1024 * 1024;
const HASH_REPRESENTATION: usize = 36_055_288;
// Two selected native paths (<=65536 bytes each), escaped display names,
// conversion copies and fixed bookkeeping. Parser-owned media allocations are
// deliberately NOT described by this representation allowance.
const COPY_PATHS_AND_CONTROL: usize = 2 * 1024 * 1024 + 65_536;

struct PreparationLease(Arc<AtomicBool>);
impl Drop for PreparationLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn preparation_charge(
    path: &std::path::Path,
    name: &str,
    options: &transfer::LocalIngestOptions<'_>,
) -> Result<usize> {
    ensure!(name.len() <= 65_536, LocalMutationError::TooLarge);
    let mut charge = HASH_REPRESENTATION + PUBLICATION_WORKSPACE + COPY_PATHS_AND_CONTROL;
    // Includes long-path normalization, content/summary copies, native SQL
    // conversion and escaped names. Validate before owner-held clones exist.
    let input = withdrawal_path_charge(path)?
        .checked_mul(8)
        .and_then(|n| n.checked_add(name.len().checked_mul(8)?))
        .ok_or(LocalMutationError::TooLarge)?;
    charge = charge
        .checked_add(input)
        .ok_or(LocalMutationError::TooLarge)?;
    for root in options.roots {
        let root_bytes = withdrawal_path_charge(&root.root)?
            .checked_add(withdrawal_path_charge(&root.relative)?)
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<emulebb_metadata::MetadataIngestRoot>())
            })
            .ok_or(LocalMutationError::TooLarge)?;
        charge = charge
            .checked_add(root_bytes)
            .ok_or(LocalMutationError::TooLarge)?;
    }
    if let Some(content_type) = options.index_type {
        charge = charge
            .checked_add(
                content_type
                    .len()
                    .checked_mul(4)
                    .ok_or(LocalMutationError::TooLarge)?,
            )
            .ok_or(LocalMutationError::TooLarge)?;
    }
    ensure!(charge <= PREPARED_ALLOWANCE, LocalMutationError::TooLarge);
    Ok(charge)
}

fn live_partial(
    manifest: Option<&transfer::Ed2kResumeManifest>,
) -> Result<Option<Option<MetadataPartialShare>>> {
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    if manifest.completed
        || manifest.final_rehash_pending
        || !manifest.md4_hashset_acquired
        || manifest.transfer_row_removed
        || manifest.verified_ranges.is_empty()
    {
        return Ok(Some(None));
    }
    ensure!(
        manifest.display_name.len() <= 65_536
            && manifest.comment.len() <= 65_536
            && manifest.upload_priority.len() <= 65_536
            && manifest
                .aich_root
                .as_ref()
                .is_none_or(|root| root.len() <= 40)
            && manifest.verified_ranges.len() <= 28_258
            && manifest.file_size <= 0x4000000000,
        "live partial projection exceeds bound"
    );
    let mut ranges = Vec::with_capacity(manifest.verified_ranges.len());
    for range in &manifest.verified_ranges {
        ranges.push(MetadataTransferRange {
            start: range.start,
            end: range.end,
        });
    }
    Ok(Some(Some(MetadataPartialShare {
        file_hash: manifest.file_hash.clone(),
        display_name: manifest.display_name.clone(),
        file_size: manifest.file_size,
        aich_root: manifest.aich_root.clone(),
        upload_priority: manifest.upload_priority.clone(),
        auto_upload_priority: manifest.auto_upload_priority,
        comment: manifest.comment.clone(),
        rating: manifest.rating,
        ranges,
    })))
}

impl LocalMutationRegistry {
    pub(in crate::ed2k_transfer) fn submit_ingest(
        &self,
        runtime: &transfer::Ed2kTransferRuntime,
        path: &std::path::Path,
        name: &str,
        observer: Option<&transfer::LocalIngestProgressObserver>,
        options: &transfer::LocalIngestOptions<'_>,
    ) -> Result<oneshot::Receiver<Result<transfer::Ed2kLocalIngestSummary>>> {
        let _charge = preparation_charge(path, name, options)?;
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        Self::reap(&mut state);
        if state.sealed {
            return Err(LocalMutationError::Closing.into());
        }
        if state.faulted {
            return Err(LocalMutationError::Unknown.into());
        }
        if state.tasks.len() >= MAX_UNITS || self.preparation.swap(true, Ordering::AcqRel) {
            return Err(LocalMutationError::Busy.into());
        }
        let lease = PreparationLease(Arc::clone(&self.preparation));
        // The workspace is within the 64 MiB lease, NOT the ordinary 8 MiB
        // counter: a long hash must leave withdrawals/admissions runnable.
        let path = path.to_path_buf();
        let name = name.to_owned();
        let roots = options.roots.to_vec();
        let index_type = options.index_type.map(str::to_owned);
        let observer = observer.cloned();
        let metadata = runtime.metadata.clone();
        let locks = Arc::clone(&runtime.manifest_locks);
        let manifests = Arc::clone(&runtime.manifest_cache);
        let catalog = Arc::clone(&runtime.shared_catalog);
        let eligibility = Arc::clone(&runtime.share_eligibility);
        let epoch = Arc::clone(&runtime.category_root_epoch);
        let dirty = Arc::clone(&runtime.category_root_dirty);
        let failed = Arc::clone(&runtime.share_publication_failed);
        let generation = Arc::clone(&runtime.shared_catalog_generation);
        let hashes_cache = Arc::clone(&runtime.servable_shared_hash_cache);
        let demand = Arc::clone(&runtime.shared_publish_demand_revision);
        let notify = Arc::clone(&runtime.shared_publish_demand_notify);
        let (response, receive) = oneshot::channel();
        #[cfg(test)]
        let publication_gate = state.publication_gate.take();
        state.tasks.spawn_blocking(move || {
            let _lease = lease;
            let mut committed = false;
            let operation = || {
                let path = crate::long_path::long_path(&path);
                let expected = metadata.local_file_instance(&path)?;
                let prepared = transfer::ingest::prepare_local_ingest(&path, &name, observer)?;
                let mut hashes = Vec::with_capacity(2);
                if let Some(old) = &expected { hashes.push(old.file_hash.clone()); }
                hashes.push(prepared.content.file_hash.clone());
                hashes.sort_unstable(); hashes.dedup();
                let lock_handles: Vec<_> = {
                    let mut locks = locks.lock().map_err(|_| LocalMutationError::Unknown)?;
                    hashes.iter().map(|hash| Arc::clone(locks.entry(hash.clone()).or_default())).collect()
                };
                // No SQL/root/catalog lock is held across these waits. Existing
                // manifest->admission callers drop guards on Busy before waiting
                // for registry capacity, so the retained slot cannot form a cycle.
                let _guards: Vec<_> = lock_handles.into_iter().map(|lock| lock.blocking_lock_owned()).collect();
                let raw_hashes = hashes.iter().map(|hash| hash.parse::<emulebb_kad_proto::Ed2kHash>()
                    .map(|hash| hash.0)).collect::<Result<Vec<_>, _>>()?;
                let stripe = eligibility.begin_mutation(&raw_hashes)?;
                let mut cut = 0;
                let mut committed_result = None;
                for _ in 0..100 {
                    cut = epoch.load(Ordering::Acquire);
                    if cut % 2 != 0 {
                        std::thread::sleep(std::time::Duration::from_millis(5)); continue;
                    }
                    // A prehash global epoch may be hours old. Revalidate only
                    // the selected intent at a fresh cut, without rehashing or
                    // silently changing which path/hash guards this unit owns.
                    ensure!(transfer::ingest::native_file_fingerprint(&path).as_ref() == Some(&prepared.content.fingerprint),
                        "local ingest source changed before binding");
                    for root in &roots {
                        ensure!(crate::long_path::long_path(&root.root).is_dir(),
                            "required ingest root is no longer accessible");
                    }
                    match metadata.commit_local_ingest(&prepared.content, &prepared.recovery,
                        &prepared.media, expected.as_ref(), &roots, index_type.as_deref(), (&epoch, cut)) {
                        Err(error) if error.is::<emulebb_metadata::ObservedRootChanged>() => continue,
                        result => { committed_result = Some(result?); break; }
                    }
                }
                let result = committed_result.ok_or_else(|| anyhow!("ingest root transaction could not stabilize"))?;
                committed = true;
                if let Some(error) = result.recovery_error {
                    tracing::warn!(%error, "Verified MD4 content retained without AICH recovery cache");
                }
                #[cfg(test)]
                if let Some((reached, release)) = publication_gate {
                    let _ = reached.send(()); let _ = release.recv();
                }
                let mut projections = Some(result.projections);
                for _ in 0..100 {
                    let current = epoch.load(Ordering::Acquire);
                    if current % 2 != 0 {
                        std::thread::sleep(std::time::Duration::from_millis(5)); continue;
                    }
                    if current != cut || projections.is_none() {
                        // Drop old allocations before fetching replacements.
                        drop(projections.take());
                        projections = Some(metadata.local_ingest_projections(&hashes)?);
                        cut = current;
                    }
                    let projections = projections.take().expect("current ingest projections");
                    let mut choices = Vec::with_capacity(projections.len());
                    {
                        let mut cache = manifests.blocking_lock();
                        for projection in projections {
                            if let (Some(manifest), Some(aich)) = (cache.get_mut(&projection.file_hash), projection.aich) {
                                if manifest.aich_trust_generation < aich.generation {
                                    manifest.aich_root = aich.root;
                                    manifest.aich_root_origin = aich.origin.as_deref()
                                        .map(transfer::Ed2kAichRootOrigin::parse).transpose()?;
                                    manifest.aich_trust_generation = aich.generation;
                                    manifest.aich_hashset.clear();
                                    manifest.aich_hashset_acquired = false;
                                }
                            }
                            let live = if projection.complete.is_none() {
                                live_partial(cache.get(&projection.file_hash))?
                            } else { None };
                            choices.push((projection.file_hash, projection.complete, projection.partial, live));
                        }
                    }
                    let mut replacements = Vec::with_capacity(choices.len());
                    for (file_hash, complete, stored_partial, live) in choices {
                            // Select and move one fallback outside cache locks.
                            // Never retain two converted range alternatives.
                            let next = if let Some(complete) = complete {
                                drop(stored_partial);
                                Some(transfer::transfer_sql::shared_entry_from_catalog_entry(complete)?)
                            } else {
                                let partial = match live {
                                    Some(live) => { drop(stored_partial); live }
                                    None => stored_partial,
                                };
                                partial.map(transfer::Ed2kSharedEntry::from_partial_share)
                            };
                            let hash = file_hash.parse::<emulebb_kad_proto::Ed2kHash>()?;
                            replacements.push((hash, next));
                    }
                    let mut entries = catalog.blocking_write();
                    if epoch.load(Ordering::Acquire) != cut { drop(entries); continue; }
                    for (hash, mut next) in replacements {
                        if let (Some(previous), Some(next)) = (entries.entry_by_hash(&hash), next.as_mut()) {
                            next.publish = previous.publish.clone();
                            next.all_time_uploaded_bytes = previous.all_time_uploaded_bytes;
                        }
                        entries.upsert_verified(hash, next);
                    }
                    generation.fetch_add(1, Ordering::AcqRel);
                    hashes_cache.lock().map_err(|_| LocalMutationError::Unknown)?.hashes = None;
                    drop(entries);
                    drop(stripe); drop(_guards);
                    demand.fetch_add(1, Ordering::AcqRel);
                    notify.notify_waiters();
                    return Ok(prepared.summary);
                }
                Err(anyhow!("ingest committed but root publication could not stabilize"))
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
            let (result, status) = match outcome {
                Ok(Ok(summary)) => (Ok(summary), 0),
                Ok(Err(error)) => {
                    let unknown = error.is::<emulebb_metadata::MetadataIngestCommitUncertain>()
                        || error.is::<LocalMutationError>() && matches!(error.downcast_ref::<LocalMutationError>(), Some(LocalMutationError::Unknown));
                    if unknown { (Err(LocalMutationError::Unknown.into()), 2) }
                    else if committed { tracing::error!(%error, "ingest committed but publication failed");
                        (Err(LocalMutationError::Committed.into()), 1) }
                    else { (Err(error), 0) }
                }
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            if status != 0 { dirty.store(true, Ordering::Release); failed.store(true, Ordering::Release); }
            let _ = response.send(result);
            (0, status)
        });
        Ok(receive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partial_bytes(partial: &MetadataPartialShare) -> usize {
        partial.file_hash.capacity()
            + partial.display_name.capacity()
            + partial.upload_priority.capacity()
            + partial.comment.capacity()
            + partial.aich_root.as_ref().map_or(0, String::capacity)
            + partial.ranges.capacity() * std::mem::size_of::<MetadataTransferRange>()
    }

    #[test]
    fn two_hash_partial_workspace_uses_actual_maximum_capacities() {
        let job = transfer::new_transfer_job(
            emulebb_kad_proto::Ed2kHash([1; 16]),
            "x".repeat(65_536),
            0x4000000000,
        );
        let mut manifest = transfer::Ed2kResumeManifest::new(&job);
        manifest.md4_hashset_acquired = true;
        manifest.comment = "c".repeat(65_536);
        manifest.upload_priority = "p".repeat(65_536);
        manifest.aich_root = Some("11".repeat(20));
        manifest.verified_ranges = (0..28_258u64)
            .map(|n| transfer::Ed2kSharedRange {
                start: n * 2,
                end: n * 2 + 1,
            })
            .collect();
        // The unit may hold two SQL partials plus two live partials, but never
        // clones their converted entries. Count capacities, not just lengths.
        let mut alternatives = Vec::with_capacity(4);
        for _ in 0..4 {
            alternatives.push(live_partial(Some(&manifest)).unwrap().unwrap().unwrap());
        }
        let retained = alternatives.iter().map(partial_bytes).sum::<usize>();
        assert_eq!(alternatives[0].ranges.capacity(), 28_258);
        assert!(retained <= 4 * 648_808);
        let selected = alternatives.pop().unwrap();
        let selected_bytes = partial_bytes(&selected);
        let converted = transfer::Ed2kSharedEntry::from_partial_share(selected);
        let converted_bytes = converted.file_hash.capacity()
            + converted.display_name.capacity()
            + converted.upload_priority.capacity()
            + converted.comment.capacity()
            + converted.aich_root.as_ref().map_or(0, String::capacity)
            + converted.verified_ranges.capacity()
                * std::mem::size_of::<transfer::Ed2kSharedRange>()
            + converted.complete_parts.capacity() * std::mem::size_of::<bool>();
        // Pessimistically count both input and output during conversion even
        // though Rust may reuse the consumed range allocation.
        assert!(retained + converted_bytes + 65_536 < PUBLICATION_WORKSPACE);
        assert!(selected_bytes <= 648_808);
        assert!(
            HASH_REPRESENTATION + PUBLICATION_WORKSPACE + COPY_PATHS_AND_CONTROL
                < PREPARED_ALLOWANCE
        );
    }

    #[test]
    fn prepared_allowance_includes_checked_root_intents_without_ordinary_byte_charge() {
        let roots = (0..256)
            .map(|_| emulebb_metadata::MetadataIngestRoot {
                root: std::path::PathBuf::from("r".repeat(16_000)),
                relative: "sample.bin".into(),
            })
            .collect::<Vec<_>>();
        let options = transfer::LocalIngestOptions {
            roots: &roots,
            ..Default::default()
        };
        assert!(matches!(
            preparation_charge(std::path::Path::new("sample.bin"), "sample.bin", &options)
                .unwrap_err()
                .downcast_ref::<LocalMutationError>(),
            Some(LocalMutationError::TooLarge)
        ));
        assert!(
            preparation_charge(
                std::path::Path::new("sample.bin"),
                "sample.bin",
                &transfer::LocalIngestOptions::default()
            )
            .unwrap()
                < PREPARED_ALLOWANCE
        );
    }

    #[test]
    fn mixed_complete_partial_workspace_accounts_media_clone_and_native_path_separately() {
        let job = transfer::new_transfer_job(
            emulebb_kad_proto::Ed2kHash([1; 16]),
            "n".repeat(65_536),
            0x4000000000,
        );
        let mut manifest = transfer::Ed2kResumeManifest::new(&job);
        manifest.md4_hashset_acquired = true;
        manifest.comment = "c".repeat(65_536);
        manifest.upload_priority = "p".repeat(65_536);
        manifest.aich_root = Some("11".repeat(20));
        manifest.verified_ranges = (0..28_258u64)
            .map(|n| transfer::Ed2kSharedRange {
                start: n * 2,
                end: n * 2 + 1,
            })
            .collect();
        // One stored partial beside the complete identity, and the other
        // identity's SQL and live alternatives. This pessimistically keeps the
        // first partial even though production drops it before conversion.
        let mut partials = (0..3)
            .map(|_| live_partial(Some(&manifest)).unwrap().unwrap().unwrap())
            .collect::<Vec<_>>();
        let partial_capacity = partials.iter().map(partial_bytes).sum::<usize>();
        #[cfg(windows)]
        let path = {
            use std::os::windows::ffi::OsStringExt;
            std::path::PathBuf::from(std::ffi::OsString::from_wide(&vec![0xd800; 32_768]))
        };
        #[cfg(not(windows))]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![0xff; 65_536]))
        };
        let display_name = emulebb_metadata::NativePath::from(path.as_path())
            .display_file_name()
            .unwrap();
        let native_path_capacity = path.capacity() + display_name.capacity() + 65_536;
        // Includes a second selected-copy allowance and native conversion
        // buffers. These allocations do not belong to the 4 MiB text/range pool.
        assert!(2 * native_path_capacity + 65_536 < COPY_PATHS_AND_CONTROL);
        let complete = emulebb_metadata::MetadataTransferCatalogEntry {
            file_hash: "22".repeat(16),
            display_name,
            file_size: 0x4000000000,
            part_count: 28_257,
            aich_root: Some("33".repeat(20)),
            upload_priority: "p".repeat(65_536),
            auto_upload_priority: false,
            comment: "c".repeat(65_536),
            rating: 0,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
            media_path: Some(path),
            media: emulebb_metadata::MetadataTransferMediaMetadata {
                artist: "a".repeat(65_536),
                album: "b".repeat(65_536),
                title: "t".repeat(65_536),
                codec: "k".repeat(65_536),
                extractor_version: transfer::transfer_sql::MEDIA_METADATA_EXTRACTOR_VERSION,
                ..Default::default()
            },
        };
        let media_clone = complete.media.artist.capacity()
            + complete.media.album.capacity()
            + complete.media.title.capacity()
            + complete.media.codec.capacity();
        let complete_capacity = complete.file_hash.capacity()
            + complete.aich_root.as_ref().unwrap().capacity()
            + complete.upload_priority.capacity()
            + complete.comment.capacity()
            + media_clone;
        assert_eq!(media_clone, 4 * 65_536);
        assert!(
            partial_capacity + complete_capacity + media_clone + 65_536 < PUBLICATION_WORKSPACE
        );
        let complete = transfer::transfer_sql::shared_entry_from_catalog_entry(complete).unwrap();
        assert_eq!(complete.media.artist.capacity(), 65_536);
        let partial = transfer::Ed2kSharedEntry::from_partial_share(partials.pop().unwrap());
        let partial_output = partial.file_hash.capacity()
            + partial.display_name.capacity()
            + partial.upload_priority.capacity()
            + partial.comment.capacity()
            + partial.aich_root.as_ref().unwrap().capacity()
            + partial.verified_ranges.capacity() * std::mem::size_of::<transfer::Ed2kSharedRange>()
            + partial.complete_parts.capacity();
        assert!(
            partial_capacity + complete_capacity + partial_output + 65_536 < PUBLICATION_WORKSPACE
        );
    }
}
