use super::*;
use md4::Digest;
use transfer::{Ed2kTransferRuntime, test_support::admit_download_job};

#[tokio::test]
async fn payload_pages_advance_over_unverified_jobs_and_reject_replaced_bytes() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let waiting = admit_download_job(
        &runtime,
        emulebb_kad_proto::Ed2kHash::from_bytes([19; 16]),
        "waiting.bin".into(),
        16,
    );
    let bytes = b"independent verified internal payload";
    let hash = emulebb_kad_proto::Ed2kHash::from_bytes(md4::Md4::digest(bytes).into());
    let job = admit_download_job(&runtime, hash, "payload.bin".into(), bytes.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, bytes.len() as u64, bytes)
        .await
        .unwrap();
    let first = runtime.payload_catalog_page(None, 1).await.unwrap();
    assert!(first.entries.is_empty());
    assert_eq!(first.cursor, Some(waiting.token.job_id));
    let second = runtime.payload_catalog_page(first.cursor, 1).await.unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_eq!(second.entries[0].display_name, "payload.bin");
    assert!(second.entries[0].verified_complete);
    let snapshot = runtime
        .metadata
        .download_payload_candidate(&hash.to_string())
        .unwrap()
        .unwrap();
    assert!(probe(&runtime.metadata, &snapshot).unwrap());
    let path =
        crate::long_path::long_path(&snapshot.storage.path).join(transfer::PAYLOAD_FILE_NAME);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, vec![0; bytes.len()]).unwrap();
    assert!(!probe(&runtime.metadata, &snapshot).unwrap());
    let rejected = runtime.payload_catalog_page(first.cursor, 1).await.unwrap();
    assert!(rejected.entries.is_empty());
    assert_eq!(rejected.cursor, Some(job.token.job_id));
    assert!(
        runtime
            .payload_catalog_page(rejected.cursor, 1)
            .await
            .unwrap()
            .cursor
            .is_none()
    );
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

// This holds the real tracked worker at its scheduling seam, not in an OS I/O
// call. It proves task/charge retention and cancellation-safe drain ownership.
#[tokio::test]
async fn cancelled_payload_receipt_and_drain_retain_long_fs_charge() {
    let registry = Arc::new(LocalMutationRegistry::default());
    let metadata = MetadataStore::in_memory().unwrap();
    let (started, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    registry.install_publication_gate(started, gate);
    let receipt = registry
        .submit_payload_read(&metadata, Request::Page(None, 1))
        .unwrap();
    ready.await.unwrap();
    drop(receipt);
    {
        let state = registry.state.lock().unwrap();
        assert_eq!(state.capacity.usage().long_fs_units, 1);
        assert_eq!(state.capacity.usage().long_fs_bytes, WORKSPACE);
        assert_eq!(state.capacity.usage().bytes, WORKSPACE);
        assert!(state.tasks.len() < MAX_UNITS);
        assert!(state.capacity.usage().bytes + PUBLICATION_WORKSPACE < MAX_BYTES);
    }
    let pending = registry.signal_next_pending_drain();
    let first = {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move { registry.seal_and_drain().await })
    };
    pending.await.unwrap();
    first.abort();
    let _ = first.await;
    assert_eq!(
        registry
            .state
            .lock()
            .unwrap()
            .capacity
            .usage()
            .long_fs_bytes,
        WORKSPACE
    );
    assert!(matches!(
        registry
            .submit_payload_read(&metadata, Request::Page(None, 1))
            .err()
            .unwrap()
            .downcast_ref::<LocalMutationError>(),
        Some(LocalMutationError::Closing)
    ));
    release.send(()).unwrap();
    registry.seal_and_drain().await.unwrap();
    let state = registry.state.lock().unwrap();
    assert_eq!(state.capacity.usage().long_fs_units, 0);
    assert_eq!(state.capacity.usage().bytes, 0);
}

// Product-owned backing-capacity ledger, not an allocator/RSS bound.
#[test]
fn payload_page_and_exact_probe_workspace_fits_existing_long_fs_allowance() {
    use std::mem::size_of;
    // Provider charges text twice, native paths four times, and 4096 fixed
    // bytes per candidate. Cover text-heavy and path-heavy accepted pages.
    for text_fields in [0usize, 7] {
        for long_path in [false, true] {
            #[cfg(windows)]
            let path = std::path::PathBuf::from(if long_path {
                "漢".repeat(32_768)
            } else {
                "payload".into()
            });
            #[cfg(not(windows))]
            let path = std::path::PathBuf::from(if long_path {
                "x".repeat(65_536)
            } else {
                "/payload".into()
            });
            let text = (0..text_fields)
                .map(|_| "x".repeat(65_536))
                .collect::<Vec<_>>();
            let text_bytes = text.iter().map(String::capacity).sum::<usize>();
            let charge = 4096 + 2 * text_bytes + 4 * path.as_os_str().len();
            let vector_bytes = 200 * size_of::<MetadataDownloadPayload>();
            let count = ((WORKSPACE - vector_bytes) / charge).min(200);
            assert!(count > 0);
            let rows = count * (text_bytes + path.capacity() + 128);
            // Full input and output vector backing can coexist as entries move.
            let vectors = vector_bytes + 200 * size_of::<transfer::Ed2kSharedEntry>();
            let mut joined = path.clone();
            joined.push(transfer::PAYLOAD_FILE_NAME);
            let mut normalized = path.clone();
            normalized.push(transfer::PAYLOAD_FILE_NAME);
            // Exact row reread, joined paths, and bounded native encoding.
            // Overlong joined paths fail validation before native encoding.
            let probe_peak = rows
                + vectors
                + text_bytes
                + path.capacity()
                + joined.capacity()
                + normalized.capacity()
                + 65_536;
            // Conversion clones four media strings; all other text moves.
            let conversion_peak = rows + vectors + text_fields.min(4) * 65_536;
            assert!(
                probe_peak <= WORKSPACE,
                "probe: {probe_peak}, text={text_fields}, long={long_path}"
            );
            assert!(
                conversion_peak <= WORKSPACE,
                "conversion: {conversion_peak}"
            );
        }
    }
}

#[tokio::test]
async fn ordinary_withdrawal_and_content_updates_select_current_internal_payload() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let bytes = b"independent job survives ordinary path withdrawal";
    let local = root.path().join("local.bin");
    std::fs::write(&local, bytes).unwrap();
    let summary = runtime
        .ingest_local_file(&local, "local.bin")
        .await
        .unwrap();
    transfer::test_support::admit_local_share(&runtime, root.path(), &local).await;
    let hash = summary.file_hash.parse().unwrap();
    let job = admit_download_job(&runtime, hash, "independent.bin".into(), bytes.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, bytes.len() as u64, bytes)
        .await
        .unwrap();
    runtime
        .withdraw_monitored_shared_path(&summary.file_hash, &crate::long_path::long_path(&local))
        .await
        .unwrap();
    {
        let catalog = runtime.shared_catalog.read().await;
        let entry = catalog.entry_by_hash(&hash).unwrap();
        assert!(entry.verified_complete);
        assert_eq!(entry.display_name, "independent.bin");
    }
    let watch = runtime.watch_category_catalog_hash(hash.0).await.unwrap();
    assert!(
        runtime
            .publish_category_catalog_decision(
                hash.0,
                watch,
                transfer::CategoryCatalogDecision::Remove
            )
            .await
            .unwrap()
    );
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .unwrap()
            .verified_complete
    );
    let stale = runtime.watch_category_catalog_hash(hash.0).await.unwrap();
    runtime
        .persist_content_metadata(hash, Some(("high", false)), None)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .unwrap()
            .upload_priority,
        "high"
    );
    assert!(
        !runtime
            .publish_category_catalog_decision(
                hash.0,
                stale,
                transfer::CategoryCatalogDecision::Remove
            )
            .await
            .unwrap()
    );
    let candidate = runtime
        .metadata
        .download_payload_candidate(&summary.file_hash)
        .unwrap()
        .unwrap();
    let payload =
        crate::long_path::long_path(&candidate.storage.path).join(transfer::PAYLOAD_FILE_NAME);
    std::fs::remove_file(&payload).unwrap();
    std::fs::write(&payload, vec![0; bytes.len()]).unwrap();
    runtime
        .persist_content_metadata(hash, Some(("normal", false)), None)
        .await
        .unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    // Durable completion evidence never makes the replaced object serveable.
    assert!(
        runtime
            .metadata
            .download_payload_candidate(&summary.file_hash)
            .unwrap()
            .is_some()
    );
    runtime
        .remove_download_job(job.token.job_id, false)
        .await
        .unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn ingest_rebind_keeps_independent_payload_in_atomic_two_hash_publication() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create(root.path()).unwrap();
    let bytes = b"old path binding with independent verified bytes";
    let path = root.path().join("rebound.bin");
    std::fs::write(&path, bytes).unwrap();
    let old = runtime
        .ingest_local_file(&path, "rebound.bin")
        .await
        .unwrap();
    transfer::test_support::admit_local_share(&runtime, root.path(), &path).await;
    let hash = old.file_hash.parse().unwrap();
    let job = admit_download_job(&runtime, hash, "independent.bin".into(), bytes.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, bytes.len() as u64, bytes)
        .await
        .unwrap();
    std::fs::write(&path, b"new unrelated content at the same native path").unwrap();
    let new = runtime
        .ingest_local_file_owned(
            &path,
            "rebound.bin",
            None,
            transfer::LocalIngestOptions {
                roots: &[emulebb_metadata::MetadataIngestRoot {
                    root: root.path().to_path_buf(),
                    relative: "rebound.bin".into(),
                }],
                index_type: None,
            },
        )
        .await
        .unwrap();
    assert_ne!(old.file_hash, new.file_hash);
    let catalog = runtime.shared_catalog.read().await;
    let old_entry = catalog.entry_by_hash(&hash).unwrap();
    assert!(old_entry.verified_complete);
    assert_eq!(old_entry.display_name, "independent.bin");
    assert!(
        catalog
            .entry_by_hash(&new.file_hash.parse().unwrap())
            .unwrap()
            .verified_complete
    );
    drop(catalog);
    runtime.local_mutations.seal_and_drain().await.unwrap();
}

#[tokio::test]
async fn removed_job_cannot_be_republished_by_a_cancelled_waiting_payload_probe() {
    let root = tempfile::tempdir().unwrap();
    let runtime = Arc::new(Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
    let bytes = b"retained probe with a concurrent logical removal";
    let hash = emulebb_kad_proto::Ed2kHash::from_bytes(md4::Md4::digest(bytes).into());
    let job = admit_download_job(&runtime, hash, "remove.bin".into(), bytes.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(job.token, Vec::new())
        .await
        .unwrap();
    runtime
        .append_piece_block(job.token, 0, 0, bytes.len() as u64, bytes)
        .await
        .unwrap();
    let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
    let (reached, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    capacity.install_probe_gate(reached, gate);
    let caller = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            runtime
                .persist_content_metadata(hash, Some(("high", false)), None)
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(capacity.usage().long_fs_bytes, WORKSPACE);
    // Two more eligible workers are waiting for the same bounded physical
    // workspace. The real remove must still fit the fourth ordinary slot.
    for _ in 0..2 {
        let mut state = runtime.local_mutations.state.lock().unwrap();
        let lease =
            LocalMutationRegistry::reserve_unit(&mut state, 128 * 1024, true, false).unwrap();
        LocalMutationRegistry::spawn_unit(&mut state, lease, move |lease| {
            lease.enter_filesystem(128 * 1024, WORKSPACE).unwrap();
            0
        });
    }
    assert_eq!(capacity.usage().long_fs_units, 3);
    // The original worker released its content/job guards before this gate.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        runtime.remove_download_job(job.token.job_id, false),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    caller.abort();
    let _ = caller.await;
    let pending = runtime.local_mutations.signal_next_pending_drain();
    let drain = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.local_mutations.seal_and_drain().await })
    };
    pending.await.unwrap();
    drain.abort();
    let _ = drain.await;
    release.send(()).unwrap();
    runtime.local_mutations.seal_and_drain().await.unwrap();
    assert!(
        runtime
            .shared_catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    assert_eq!(capacity.usage().bytes, 0);
}

#[test]
fn prepared_two_hash_payload_proofs_fit_existing_four_mib_publication_workspace() {
    #[cfg(windows)]
    let path = std::path::PathBuf::from("漢".repeat(32_768));
    #[cfg(not(windows))]
    let path = std::path::PathBuf::from("x".repeat(65_536));
    let mut joined = path.clone();
    joined.push(transfer::PAYLOAD_FILE_NAME);
    let texts = (0..7).map(|_| "x".repeat(65_536)).collect::<Vec<_>>();
    let text_bytes = texts.iter().map(String::capacity).sum::<usize>();
    let proof = text_bytes + path.capacity() + joined.capacity() + 4096;
    let partial =
        28_258 * std::mem::size_of::<emulebb_metadata::MetadataTransferRange>() + 3 * 65_536 + 4096;
    // Remaining proof + selected proof + exact SQL recheck + one partial.
    // A previous converted replacement takes no more than the partial charge.
    let recheck = text_bytes + path.capacity() + 65_536 + 4096;
    assert!(2 * proof + recheck + partial <= PUBLICATION_WORKSPACE);
    assert!(proof + recheck + 2 * partial <= PUBLICATION_WORKSPACE);
}

#[test]
fn ordinary_payload_publication_keeps_partial_and_native_reread_phases_separate() {
    #[cfg(windows)]
    let path = std::path::PathBuf::from("漢".repeat(32_768));
    #[cfg(not(windows))]
    let path = std::path::PathBuf::from("x".repeat(65_536));
    let mut joined = path.clone();
    joined.push(transfer::PAYLOAD_FILE_NAME);
    let text = (0..7).map(|_| "x".repeat(65_536)).collect::<Vec<_>>();
    let text_bytes = text.iter().map(String::capacity).sum::<usize>();
    let candidate = text_bytes + path.capacity() + 4096;
    let exact_reread = candidate + 65_536;
    let retained = 128 * 1024;
    assert!(candidate + joined.capacity() + exact_reread + retained <= WORKSPACE);
    let partial =
        28_258 * std::mem::size_of::<emulebb_metadata::MetadataTransferRange>() + 3 * 65_536 + 4096;
    let conversion = 28_258 * std::mem::size_of::<transfer::Ed2kSharedRange>() + 28_258;
    assert!(2 * partial + conversion + retained <= WORKSPACE);
}
