//! Complete local files are served from verified library instances. Ingest
//! never creates a download transfer or copies bytes into its piece store.

use std::fs;

use emulebb_kad_proto::Ed2kHash;
use std::str::FromStr;

use super::super::test_support::admit_local_share;
use super::super::{ED2K_EMBLOCK_SIZE, Ed2kTransferRuntime};
use super::write_repeating_pattern_file;
use crate::paths::unique_test_dir;
use emulebb_metadata::MetadataSharedDirectoryRoot;

#[tokio::test]
async fn cancelled_stale_withdrawal_and_first_drain_still_publish_before_second_drain() {
    let root = unique_test_dir("stale-withdrawal-cancel-drain");
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let path = source_dir.join("shared.bin");
    let original = source_dir.join("original.bin");
    fs::write(&path, b"verified original bytes").unwrap();
    let runtime = std::sync::Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let shared = runtime
        .ingest_local_file(&path, "shared.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &path).await;
    let hash = Ed2kHash::from_str(&shared.file_hash).unwrap();
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, release_rx);
    fs::rename(&path, &original).unwrap();
    fs::write(&path, b"different replacement bytes").unwrap();
    let caller = {
        let runtime = std::sync::Arc::clone(&runtime);
        tokio::spawn(async move { runtime.read_verified_range(&hash, 0, 4).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), reached_rx)
        .await
        .expect("withdrawal did not reach publication")
        .unwrap();
    caller.abort();
    let _ = caller.await;
    let first_pending = runtime.local_mutations.signal_next_pending_drain();
    let first = {
        let runtime = std::sync::Arc::clone(&runtime);
        tokio::spawn(async move { runtime.drain_local_mutations().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), first_pending)
        .await
        .expect("first drain did not reach the pending join")
        .unwrap();
    assert!(!first.is_finished());
    first.abort();
    let _ = first.await;
    let second_pending = runtime.local_mutations.signal_next_pending_drain();
    let second = {
        let runtime = std::sync::Arc::clone(&runtime);
        tokio::spawn(async move { runtime.drain_local_mutations().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), second_pending)
        .await
        .expect("second drain did not reach the pending join")
        .unwrap();
    assert!(!second.is_finished());
    release.send(()).unwrap();
    second.await.unwrap().unwrap();
    assert!(
        runtime
            .metadata
            .next_shared_copy(&shared.file_hash, 0, 65_536)
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .shared_catalog()
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
    assert!(
        runtime
            .shared_source_invalidation_signal()
            .try_recv()
            .is_some()
    );
    assert_eq!(fs::read(&original).unwrap(), b"verified original bytes");
    assert_eq!(fs::read(&path).unwrap(), b"different replacement bytes");
}

#[tokio::test]
async fn stale_withdrawal_rereads_projection_after_overlapping_root_change() {
    let root = unique_test_dir("stale-withdrawal-root-overlap");
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let path = source_dir.join("shared.bin");
    let original = source_dir.join("original.bin");
    fs::write(&path, b"verified original bytes").unwrap();
    let runtime = std::sync::Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let shared = runtime
        .ingest_local_file(&path, "shared.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &path).await;
    let hash = Ed2kHash::from_str(&shared.file_hash).unwrap();
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, release_rx);
    fs::rename(&path, &original).unwrap();
    fs::write(&path, b"different replacement bytes").unwrap();
    let caller = {
        let runtime = std::sync::Arc::clone(&runtime);
        tokio::spawn(async move { runtime.read_verified_range(&hash, 0, 4).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), reached_rx)
        .await
        .unwrap()
        .unwrap();
    let mutation = runtime.begin_category_root_mutation().await.unwrap();
    runtime
        .metadata
        .set_shared_root_accessible(&source_dir, false)
        .unwrap();
    drop(mutation);
    release.send(()).unwrap();
    assert!(caller.await.unwrap().unwrap().is_none());
    runtime.drain_local_mutations().await.unwrap();
    assert!(
        !runtime
            .share_publication_failed
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(
        runtime
            .shared_catalog()
            .read()
            .await
            .entry_by_hash(&hash)
            .is_none()
    );
}

#[tokio::test]
async fn monitored_withdrawal_waits_for_capacity_and_converges() {
    let root = unique_test_dir("monitored-withdrawal-capacity");
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let first_path = source_dir.join("first.bin");
    let second_path = source_dir.join("second.bin");
    fs::write(&first_path, b"first shared content").unwrap();
    fs::write(&second_path, b"second shared content").unwrap();
    let runtime = std::sync::Arc::new(Ed2kTransferRuntime::load_or_create(&root).unwrap());
    let first = runtime
        .ingest_local_file(&first_path, "first.bin")
        .await
        .unwrap();
    let second = runtime
        .ingest_local_file(&second_path, "second.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &first_path).await;
    admit_local_share(&runtime, &source_dir, &second_path).await;
    let (reached, reached_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    runtime
        .local_mutations
        .install_publication_gate(reached, release_rx);
    let first_path = crate::long_path::long_path(&first_path);
    let second_path = crate::long_path::long_path(&second_path);
    let first_task = {
        let runtime = std::sync::Arc::clone(&runtime);
        let hash = first.file_hash.clone();
        tokio::spawn(async move {
            runtime
                .withdraw_monitored_shared_path(&hash, &first_path)
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), reached_rx)
        .await
        .unwrap()
        .unwrap();
    let waiting = runtime.local_mutations.signal_next_pending_wait();
    let second_task = {
        let runtime = std::sync::Arc::clone(&runtime);
        let hash = second.file_hash.clone();
        tokio::spawn(async move {
            runtime
                .withdraw_monitored_shared_path(&hash, &second_path)
                .await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    assert!(!second_task.is_finished());
    assert!(
        runtime
            .metadata
            .next_shared_copy(&second.file_hash, 0, 65_536)
            .unwrap()
            .is_some()
    );
    release.send(()).unwrap();
    first_task.await.unwrap().unwrap();
    second_task.await.unwrap().unwrap();
    assert!(
        runtime
            .metadata
            .next_shared_copy(&second.file_hash, 0, 65_536)
            .unwrap()
            .is_none()
    );
    assert!(
        runtime
            .shared_catalog()
            .read()
            .await
            .entry_by_hash(&second.file_hash.parse().unwrap())
            .is_none()
    );
    runtime.drain_local_mutations().await.unwrap();
}

#[cfg(unix)]
use emulebb_metadata::NativePath;

#[tokio::test]
async fn ingest_shares_complete_file_in_place_without_copying_to_piece_store() {
    let root = unique_test_dir("ed2k-share-in-place");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    // The operator's original shared file lives OUTSIDE the transfer store.
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("Shared.Complete.File.bin");
    let size = 1_048_576usize; // single ED2K part
    write_repeating_pattern_file(&source_path, size, b"emulebb-share-in-place-payload");
    let size = size as u64;

    let summary = runtime
        .ingest_local_file(&source_path, "Shared.Complete.File.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &source_path).await;
    let file_hash = summary.file_hash.clone();
    assert!(
        runtime
            .metadata
            .latest_download_job(&file_hash)
            .unwrap()
            .is_none()
    );
    // (1) The read-only protocol view resolves the original verified path.
    let manifest = runtime.serving_view(&file_hash).await.unwrap();
    let cached = runtime
        .metadata
        .local_file_instance(manifest.local_path.as_deref().unwrap())
        .unwrap()
        .expect("whole-payload hash pass must cache the verified native path");
    assert_eq!(cached.file_hash, file_hash);
    assert!(manifest.completed, "shared complete file must be completed");
    assert_eq!(
        manifest.local_path.as_deref(),
        Some(crate::long_path::long_path(&source_path).as_path()),
        "manifest must record the original on-disk source path",
    );

    // (2) Ingest creates neither a job allocation nor a resident piece store.
    assert!(
        runtime
            .metadata
            .latest_download_job(&file_hash)
            .unwrap()
            .is_none()
    );
    assert!(runtime.job_storage.lock().unwrap().is_empty());

    // (3) The original file is untouched and still its full size.
    assert_eq!(fs::metadata(&source_path).unwrap().len(), size);

    // (4) The upload-serving read path returns the ORIGINAL file's bytes,
    // proving uploads serve from the real path rather than a piece-store copy.
    let hash = Ed2kHash::from_str(&file_hash).unwrap();
    let served = runtime
        .read_verified_range(&hash, 0, size)
        .await
        .unwrap()
        .expect("a completed shared file must serve its verified range");
    assert_eq!(served.len() as u64, size);
    assert_eq!(served, fs::read(&source_path).unwrap());

    // (5) Small/tail upload reads stay exact instead of priming a full
    // protocol-window read-ahead, avoiding cold-disk amplification when a peer
    // asks for a short range near the end of a file.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    let source_bytes = fs::read(&source_path).unwrap();
    let first = reader.read_range(0, 4096).await.unwrap().unwrap();
    let second = reader.read_range(4096, 8192).await.unwrap().unwrap();
    assert_eq!(first, source_bytes[0..4096]);
    assert_eq!(second, source_bytes[4096..8192]);
    assert_eq!(reader.cache_miss_count(), 2);
    assert_eq!(reader.cache_hit_count(), 0);
    assert_eq!(reader.disk_read_bytes(), 8192);

    // (6) A caller can suppress read-ahead for an accepted block when the rest
    // of the OP_REQUESTPARTS ranges were already served and should not drive
    // speculative disk IO.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    let first = reader
        .read_range_with_read_ahead(0, ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE)
        .await
        .unwrap()
        .unwrap();
    let second = reader
        .read_range_with_read_ahead(ED2K_EMBLOCK_SIZE, ED2K_EMBLOCK_SIZE * 2, ED2K_EMBLOCK_SIZE)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first, source_bytes[0..ED2K_EMBLOCK_SIZE as usize]);
    assert_eq!(
        second,
        source_bytes[ED2K_EMBLOCK_SIZE as usize..(ED2K_EMBLOCK_SIZE * 2) as usize]
    );
    assert_eq!(reader.cache_miss_count(), 2);
    assert_eq!(reader.cache_hit_count(), 0);
    assert_eq!(reader.disk_read_bytes(), ED2K_EMBLOCK_SIZE * 2);

    // (7) Upload read-ahead is bounded to one protocol request window: the
    // first fragment primes the cache, and the next two contiguous EMBLOCKSIZE
    // fragments reuse it without another disk read.
    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("a completed shared file must open a verified range reader");
    for index in 0..3u64 {
        let start = index * ED2K_EMBLOCK_SIZE;
        let end = start + ED2K_EMBLOCK_SIZE;
        let served = reader.read_range(start, end).await.unwrap().unwrap();
        assert_eq!(
            served,
            source_bytes[start as usize..end as usize],
            "fragment {index} must match the original source bytes",
        );
    }
    assert_eq!(
        reader.disk_read_count(),
        1,
        "three contiguous upload fragments should be covered by one read-ahead"
    );
    assert_eq!(reader.cache_miss_count(), 1);
    assert_eq!(reader.cache_hit_count(), 2);
    assert_eq!(reader.disk_read_bytes(), ED2K_EMBLOCK_SIZE * 3);
}

#[cfg(unix)]
#[tokio::test]
async fn non_utf8_local_share_reopens_and_serves_exact_bytes() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let root = unique_test_dir("ed2k-share-non-utf8-path");
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join(OsString::from_vec(b"native-\xff.bin".to_vec()));
    let payload = b"non-UTF-8 share upload payload";
    match fs::write(&source_path, payload) {
        Ok(()) => {}
        // WHY: filesystems such as APFS reject invalid UTF-8 names with
        // EILSEQ. Exercise native-byte names wherever they are representable,
        // but keep all unrelated fixture I/O failures fatal.
        Err(error) if error.raw_os_error() == Some(libc::EILSEQ) => {
            eprintln!("skipping native-byte filename test: filesystem rejects the name: {error}");
            fs::remove_dir_all(&root).unwrap();
            return;
        }
        Err(error) => panic!("failed to create native-byte filename fixture: {error}"),
    }
    let display_name = NativePath::from(source_path.as_path())
        .display_file_name()
        .unwrap();

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, &display_name)
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &source_path).await;
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    assert_eq!(
        runtime
            .serving_view(&summary.file_hash)
            .await
            .unwrap()
            .display_name,
        display_name,
    );
    assert!(
        runtime
            .metadata
            .latest_download_job(&summary.file_hash)
            .unwrap()
            .is_none()
    );
    drop(runtime);

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.refresh_complete_shared_catalog().await.unwrap();
    let manifest = runtime.serving_view(&summary.file_hash).await.unwrap();
    assert_eq!(manifest.display_name, display_name);
    assert_eq!(
        runtime
            .shared_catalog()
            .read()
            .await
            .iter()
            .find(|entry| entry.file_hash == summary.file_hash)
            .unwrap()
            .display_name,
        display_name,
    );
    assert_eq!(manifest.local_path.as_deref(), Some(source_path.as_path()));
    assert_eq!(
        runtime
            .download_evidence(&summary.file_hash)
            .await
            .unwrap()
            .current_local_files[0]
            .path,
        NativePath::from(source_path.as_path()).display_path(),
    );
    assert_eq!(
        runtime
            .read_verified_range(&hash, 0, payload.len() as u64)
            .await
            .unwrap()
            .unwrap(),
        payload,
    );
}

#[tokio::test]
async fn root_member_upload_withdraws_changed_path_without_erasing_hash_cache() {
    let root = unique_test_dir("ed2k-member-upload-withdraw");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let shared_root = root.join("library");
    fs::create_dir_all(&shared_root).unwrap();
    let path = shared_root.join("Sample.bin");
    fs::write(&path, b"original content").unwrap();
    let summary = runtime
        .ingest_local_file(&path, "Sample.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &shared_root, &path).await;
    let manifest = runtime.serving_view(&summary.file_hash).await.unwrap();
    let native_path = manifest.local_path.unwrap();
    let fingerprint = manifest.local_fingerprint.unwrap();
    let mut metadata = runtime.metadata.clone();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: shared_root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    metadata
        .replace_root_memberships(
            &shared_root,
            &[(native_path.clone(), "Sample.bin".into(), fingerprint)],
        )
        .unwrap();
    assert_eq!(metadata.active_shared_content_count().unwrap(), 1);
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    metadata
        .set_shared_root_accessible(&shared_root, false)
        .unwrap();
    assert!(
        runtime
            .open_verified_range_reader(&hash)
            .await
            .unwrap()
            .is_none()
    );
    metadata
        .set_shared_root_accessible(&shared_root, true)
        .unwrap();
    assert!(
        runtime
            .open_verified_range_reader(&hash)
            .await
            .unwrap()
            .is_none()
    );
    let fingerprint = metadata
        .local_file_instance(&native_path)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    metadata
        .replace_root_memberships(
            &shared_root,
            &[(native_path.clone(), "Sample.bin".into(), fingerprint)],
        )
        .unwrap();
    assert!(
        runtime
            .open_verified_range_reader(&hash)
            .await
            .unwrap()
            .is_some()
    );
    fs::write(&path, b"changed content!").unwrap();
    assert!(
        runtime
            .open_verified_range_reader(&hash)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(metadata.active_shared_content_count().unwrap(), 0);
    assert!(
        metadata
            .local_file_instance(&native_path)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn complete_local_file_never_creates_a_transfer() {
    let root = unique_test_dir("ed2k-local-no-transfer");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let shared_root = root.join("library");
    fs::create_dir_all(&shared_root).unwrap();
    let path = shared_root.join("Sample.bin");
    fs::write(&path, b"verified local content").unwrap();
    let summary = runtime
        .ingest_local_file(&path, "Sample.bin")
        .await
        .unwrap();
    let native_path = crate::long_path::long_path(&path);
    let fingerprint = runtime
        .metadata
        .local_file_instance(&native_path)
        .unwrap()
        .unwrap()
        .verified_fingerprint;
    let mut metadata = runtime.metadata.clone();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: shared_root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    metadata
        .replace_root_memberships(
            &shared_root,
            &[(native_path.clone(), "Sample.bin".into(), fingerprint)],
        )
        .unwrap();
    assert!(
        metadata
            .latest_download_job(&summary.file_hash)
            .unwrap()
            .is_none()
    );
    let restarted = Ed2kTransferRuntime::load_or_create_with_metadata(&root, metadata).unwrap();
    let catalog = restarted.shared_catalog();
    let catalog = catalog.read().await;
    assert_eq!(catalog.len(), 1);
    assert_eq!(
        catalog
            .entry_by_hash(&Ed2kHash::from_str(&summary.file_hash).unwrap())
            .unwrap()
            .display_name,
        "Sample.bin"
    );
    drop(catalog);
    let virtual_manifest = restarted.serving_view(&summary.file_hash).await.unwrap();
    assert!(virtual_manifest.completed);
    assert_eq!(virtual_manifest.local_path, Some(native_path));
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    assert_eq!(
        restarted
            .read_verified_range(&hash, 0, summary.file_size)
            .await
            .unwrap()
            .unwrap(),
        fs::read(&path).unwrap()
    );
}

#[tokio::test]
async fn replaced_share_source_is_withdrawn_before_upload() {
    let root = unique_test_dir("ed2k-share-replaced-source");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = root.join("library");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("shared.bin");
    let original_path = source_dir.join("original.bin");
    let trusted_payload = vec![0x46; 4096];
    let foreign_payload = vec![0x97; trusted_payload.len()];
    fs::write(&source_path, &trusted_payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &source_dir, &source_path).await;
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
    let invalidations = runtime.shared_source_invalidation_signal();
    assert_eq!(runtime.shared_catalog_count().await, 1);

    fs::rename(&source_path, &original_path).unwrap();
    fs::write(&source_path, &foreign_payload).unwrap();

    assert!(
        runtime
            .read_verified_range(&hash, 0, trusted_payload.len() as u64)
            .await
            .unwrap()
            .is_none(),
        "foreign replacement bytes must never be served under the trusted hash"
    );
    assert!(
        runtime
            .metadata
            .active_local_content_by_hash(&summary.file_hash)
            .unwrap()
            .is_none()
    );
    assert_eq!(runtime.shared_catalog_count().await, 0);
    assert_eq!(fs::read(&source_path).unwrap(), foreign_payload);
    assert_eq!(fs::read(&original_path).unwrap(), trusted_payload);

    let invalidation = invalidations
        .try_recv()
        .expect("withdrawal must queue targeted reconciliation");
    assert_eq!(invalidation.invalidation().file_hash, summary.file_hash);
    assert_eq!(
        invalidation.invalidation().source_path,
        crate::long_path::long_path(&source_path),
    );

    assert!(
        runtime
            .read_verified_range(&hash, 0, trusted_payload.len() as u64)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        invalidations.try_recv().is_none(),
        "repeated peer reads must coalesce behind the withdrawn path"
    );
    invalidation.acknowledge();
}

#[cfg(windows)]
#[tokio::test]
async fn verified_reader_excludes_concurrent_windows_writers() {
    let root = unique_test_dir("ed2k-share-reader-writer-exclusion");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_path = root.join("shared.bin");
    let payload = vec![0x42; 4096];
    fs::write(&source_path, &payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &root, &source_path).await;
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

    let reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("verified share must open a reader");
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_err(),
        "the verified reader must deny concurrent write handles"
    );
    drop(reader);
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_ok(),
        "writer must succeed after the verified reader closes"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn verified_reader_rejects_unix_mutation_after_open() {
    let root = unique_test_dir("ed2k-share-reader-post-open-mutation");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_path = root.join("shared.bin");
    let trusted_payload = vec![0x42; 4096];
    let foreign_payload = vec![0x73; trusted_payload.len()];
    fs::write(&source_path, &trusted_payload).unwrap();
    let summary = runtime
        .ingest_local_file(&source_path, "shared.bin")
        .await
        .unwrap();
    admit_local_share(&runtime, &root, &source_path).await;
    let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();

    let mut reader = runtime
        .open_verified_range_reader(&hash)
        .await
        .unwrap()
        .expect("verified share must open a reader");
    fs::write(&source_path, &foreign_payload).unwrap();
    let error = reader
        .read_range(0, foreign_payload.len() as u64)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("verified ED2K upload payload changed while being read")
    );
}

#[tokio::test]
async fn ingest_shares_files_with_unicode_brackets_and_nested_subfolders() {
    let root = unique_test_dir("ed2k-share-unicode-paths");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let size = 1_048_576usize; // single ED2K part
    let payload = b"emulebb-unicode-share-payload";

    // A library tree with the exact shape that triggered the live failure:
    // an accented + bracketed directory holding an accented + bracketed file,
    // a nested "covers" subfolder, and a CJK-named file -- all created with
    // their real on-disk names (NFC composed `\u{00e0}` = a-grave).
    let library = root.join("library");

    // (1) accented + bracketed directory and file, two levels deep.
    let accented_dir = library
        .join("Studio Sample")
        .join("La citt\u{00e0} sample [tt0000001]");
    fs::create_dir_all(&accented_dir).unwrap();
    let accented_file = accented_dir.join("(2001) La citt\u{00e0} sample [tt0000001].mkv");
    write_repeating_pattern_file(&accented_file, size, payload);

    // (2) nested "covers" subfolder with a plain file (subfolder-only case).
    let covers_dir = library.join("Studio Sample").join("Covers");
    fs::create_dir_all(&covers_dir).unwrap();
    let cover_file = covers_dir.join("front-cover.jpg");
    write_repeating_pattern_file(&cover_file, size, payload);

    // (3) CJK-named file in a CJK-named subfolder.
    let cjk_dir = library.join("\u{6620}\u{753b}");
    fs::create_dir_all(&cjk_dir).unwrap();
    let cjk_file = cjk_dir.join("\u{30b5}\u{30f3}\u{30d7}\u{30eb} sample.bin");
    write_repeating_pattern_file(&cjk_file, size, payload);

    // Every one of these must ingest without a stat/skip failure.
    for (label, source_path, display_name) in [
        (
            "accented+bracketed nested file",
            &accented_file,
            "(2001) La citt\u{00e0} sample [tt0000001].mkv",
        ),
        ("nested subfolder cover", &cover_file, "front-cover.jpg"),
        (
            "CJK nested file",
            &cjk_file,
            "\u{30b5}\u{30f3}\u{30d7}\u{30eb} sample.bin",
        ),
    ] {
        let summary = runtime
            .ingest_local_file(source_path, display_name)
            .await
            .unwrap_or_else(|error| panic!("ingest of {label} failed: {error:#}"));
        admit_local_share(&runtime, &library, source_path).await;
        assert_eq!(
            summary.file_size, size as u64,
            "{label}: ingested file size must match the on-disk payload",
        );

        // The shared file must be served back from its ORIGINAL on-disk path
        // (in-place share), proving the long-path stat/read resolved correctly.
        let hash = Ed2kHash::from_str(&summary.file_hash).unwrap();
        let served = runtime
            .read_verified_range(&hash, 0, size as u64)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{label}: shared file did not serve its verified range"));
        assert_eq!(
            served,
            fs::read(source_path).unwrap(),
            "{label}: served bytes"
        );
    }
}
