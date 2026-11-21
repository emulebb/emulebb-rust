use super::*;
use crate::{ed2k_transfer::Ed2kTransferRuntime, paths::unique_test_dir};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{MetadataIndexedFile, MetadataIndexedFileOrigin, MetadataStore};

fn seed(runtime: &Ed2kTransferRuntime, byte: u8, baseline: u64) -> Ed2kHash {
    let hash = Ed2kHash::from_bytes([byte; 16]);
    runtime
        .metadata
        .clone()
        .upsert_indexed_file(
            &MetadataIndexedFile {
                ed2k_hash: hash.to_string(),
                name: "Sample.bin".into(),
                size_bytes: 32,
                content_type: String::new(),
                availability_score: 0,
            },
            MetadataIndexedFileOrigin::LocalShare,
        )
        .unwrap();
    runtime
        .metadata
        .add_file_all_time_uploaded(&hash.to_string(), baseline)
        .unwrap();
    hash
}

#[tokio::test]
async fn admitted_publication_adds_pending_to_durable_without_checkpoint_or_hydration() {
    let root = unique_test_dir("file-statistics-publication");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = seed(&runtime, 0x31, 100);
    runtime.add_file_all_time_uploaded(&hash, 7).unwrap();
    let before = runtime
        .metadata
        .file_upload_snapshot(&hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(before.totals.uploaded_bytes, 100);
    let resident_before = runtime.download_resource_snapshot().resident_bytes;
    let stats = runtime
        .library_file_statistics(&hash.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stats.session_uploaded_bytes, 7);
    assert_eq!(stats.lifetime.uploaded_bytes, 107);
    assert_eq!(
        runtime.download_resource_snapshot().resident_bytes,
        resident_before
    );
    assert_eq!(
        runtime.download_resource_snapshot().transient_bytes,
        64 * 1024
    );
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap(),
        before
    );
    drop(stats);
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
    runtime.flush_parked_credit().await;
    let after = runtime
        .library_file_statistics(&hash.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.session_uploaded_bytes, 7);
    assert_eq!(after.lifetime.uploaded_bytes, 107);
    drop(after);
    let reopened = MetadataStore::open(root.join("metadata.sqlite")).unwrap();
    let fresh = reopened
        .file_upload_statistics(&hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(fresh.session_uploaded_bytes, 0);
    assert_eq!(fresh.lifetime.uploaded_bytes, 107);
}

#[test]
fn captures_after_the_publication_sample_remain_dirty_for_the_next_read() {
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("statistics-capture-race")).unwrap();
    let hash = seed(&runtime, 0x32, 100);
    runtime.add_file_all_time_uploaded(&hash, 7).unwrap();
    let parts = runtime.parked_credit_flush_parts();
    parts
        .publish_file_statistics_with(|| {
            runtime.add_file_all_time_uploaded(&hash, 5).unwrap();
        })
        .unwrap();
    let first = runtime
        .metadata
        .file_upload_statistics(&hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(
        (first.session_uploaded_bytes, first.lifetime.uploaded_bytes),
        (7, 107)
    );
    assert!(
        runtime
            .parked_credit
            .lock()
            .statistics_dirty
            .contains(&hash.0)
    );
    parts.publish_file_statistics().unwrap();
    let next = runtime
        .metadata
        .file_upload_statistics(&hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(
        (next.session_uploaded_bytes, next.lifetime.uploaded_bytes),
        (12, 112)
    );
    assert!(runtime.parked_credit.lock().statistics_dirty.is_empty());
    parts
        .publish_file_statistics_with(|| panic!("idle publication sampled counters"))
        .unwrap();
}

#[test]
fn failed_publication_and_unwind_restore_detached_keys_before_retry() {
    let root = unique_test_dir("statistics-publication-failure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = seed(&runtime, 0x33, i64::MAX as u64 - 1);
    runtime.add_file_all_time_uploaded(&hash, 2).unwrap();
    let parts = runtime.parked_credit_flush_parts();
    assert!(parts.publish_file_statistics().is_err());
    assert!(
        runtime
            .parked_credit
            .lock()
            .statistics_dirty
            .contains(&hash.0)
    );
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap()
            .totals
            .uploaded_bytes,
        i64::MAX as u64 - 1
    );
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parts
            .publish_file_statistics_with(|| panic!("injected publication unwind"))
            .unwrap();
    }));
    assert!(failed.is_err());
    assert!(
        runtime
            .parked_credit
            .lock()
            .statistics_dirty
            .contains(&hash.0)
    );
    // Repair only the synthetic baseline; pending events and session counters
    // remain untouched, proving absolute retry without a second addition.
    rusqlite::Connection::open(root.join("metadata.sqlite"))
        .unwrap()
        .execute(
            "UPDATE known_files SET all_time_uploaded_bytes=?1",
            [i64::MAX - 2],
        )
        .unwrap();
    parts.publish_file_statistics().unwrap();
    let stats = runtime
        .metadata
        .file_upload_statistics(&hash.to_string())
        .unwrap()
        .unwrap();
    assert_eq!(
        (stats.session_uploaded_bytes, stats.lifetime.uploaded_bytes),
        (2, i64::MAX as u64)
    );
    assert!(runtime.parked_credit.lock().statistics_dirty.is_empty());
}

#[test]
fn publication_crosses_batch_boundaries_without_copying_the_ledger() {
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("statistics-publication-batches"))
            .unwrap();
    for byte in 1..=129 {
        let hash = seed(&runtime, byte, 100);
        runtime.add_file_all_time_uploaded(&hash, 1).unwrap();
    }
    let mut batches = 0;
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime
            .parked_credit_flush_parts()
            .publish_file_statistics_with(|| {
                batches += 1;
                assert_ne!(batches, 2, "injected failure after one published chunk");
            })
            .unwrap();
    }));
    assert!(failed.is_err());
    assert_eq!(runtime.parked_credit.lock().statistics_dirty.len(), 129);
    batches = 0;
    runtime
        .parked_credit_flush_parts()
        .publish_file_statistics_with(|| {
            batches += 1;
        })
        .unwrap();
    assert_eq!(batches, 2);
    assert!(runtime.parked_credit.lock().statistics_dirty.is_empty());
    for byte in 1..=129 {
        let hash = Ed2kHash::from_bytes([byte; 16]);
        let stats = runtime
            .metadata
            .file_upload_statistics(&hash.to_string())
            .unwrap()
            .unwrap();
        assert_eq!(
            (stats.session_uploaded_bytes, stats.lifetime.uploaded_bytes),
            (1, 101)
        );
    }
}

#[tokio::test]
async fn checkpoint_waits_for_publication_and_retains_captures_made_during_it() {
    use std::{sync::mpsc, time::Duration};
    let runtime = Arc::new(
        Ed2kTransferRuntime::load_or_create(&unique_test_dir(
            "statistics-checkpoint-publication-race",
        ))
        .unwrap(),
    );
    let hash = seed(&runtime, 0x34, 100);
    runtime.add_file_all_time_uploaded(&hash, 7).unwrap();
    let (sampled, reached) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let parts = runtime.parked_credit_flush_parts();
    let publication = tokio::task::spawn_blocking(move || {
        parts.publish_file_statistics_with(|| {
            sampled.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
        })
    });
    reached.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(runtime.credit_flush_gate.try_lock().is_none());
    runtime.add_file_all_time_uploaded(&hash, 5).unwrap();
    let (started, starting) = tokio::sync::oneshot::channel();
    let checkpoint = tokio::spawn({
        let runtime = Arc::clone(&runtime);
        async move {
            let _ = started.send(());
            runtime.checkpoint_upload_accounting().await
        }
    });
    starting.await.unwrap();
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap()
            .totals
            .uploaded_bytes,
        100
    );
    release.send(()).unwrap();
    publication.await.unwrap().unwrap();
    checkpoint.await.unwrap().unwrap();
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap()
            .totals
            .uploaded_bytes,
        112
    );
    let stats = runtime
        .library_file_statistics(&hash.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (stats.session_uploaded_bytes, stats.lifetime.uploaded_bytes),
        (12, 112)
    );
    assert!(runtime.parked_credit.lock().statistics_dirty.is_empty());
}

#[tokio::test]
async fn library_pages_publish_live_and_inactive_durable_facts_without_hydration() {
    use emulebb_metadata::{LibraryFileQuery, LibraryFileSort, LibraryFileView};
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("library-global-statistics")).unwrap();
    let active = seed(&runtime, 0x41, 100);
    let inactive = seed(&runtime, 0x42, 200);
    runtime.add_file_all_time_uploaded(&active, 7).unwrap();
    let resident = runtime.download_resource_snapshot().resident_bytes;
    let mut query = LibraryFileQuery {
        view: LibraryFileView::AllKnown,
        sort: LibraryFileSort::LifetimeUploadedBytes,
        descending: true,
        limit: 1,
        count_total: true,
        ..Default::default()
    };
    let first = runtime.library_file_page(query.clone()).await.unwrap();
    assert_eq!(first.total, Some(2));
    assert_eq!(first.files[0].file_hash, inactive.to_string());
    assert_eq!(first.files[0].statistics.lifetime.uploaded_bytes, 200);
    assert_eq!(first.files[0].statistics.session_uploaded_bytes, 0);
    assert!(
        runtime.file_upload_statistics(&inactive).is_none(),
        "a metadata-only read must not allocate runtime accounting"
    );
    assert_eq!(
        runtime.download_resource_snapshot().resident_bytes,
        resident
    );
    assert_eq!(
        runtime.download_resource_snapshot().transient_bytes,
        2 * 1024 * 1024
    );
    query.after = first.next_after;
    drop(first);
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
    let second = runtime.library_file_page(query).await.unwrap();
    assert_eq!(second.files[0].file_hash, active.to_string());
    assert_eq!(second.files[0].statistics.session_uploaded_bytes, 7);
    assert_eq!(second.files[0].statistics.lifetime.uploaded_bytes, 107);
    assert!(second.next_after.is_none());
    drop(second);
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&active.to_string())
            .unwrap()
            .unwrap()
            .totals
            .uploaded_bytes,
        100
    );
    assert!(
        runtime
            .library_file_page(LibraryFileQuery::default())
            .await
            .unwrap()
            .files
            .is_empty()
    );
    let mut oversized = String::with_capacity(65_537);
    oversized.push_str("abc");
    assert!(
        runtime
            .library_file_page(LibraryFileQuery {
                search: Some(oversized),
                ..Default::default()
            })
            .await
            .is_err()
    );
    assert_eq!(runtime.download_resource_snapshot().transient_bytes, 0);
}
