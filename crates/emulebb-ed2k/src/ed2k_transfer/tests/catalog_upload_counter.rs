//! Per-hash accounting remains authoritative while serving projections change
//! or their write lock is contended. Projection refresh reads absolute totals.

use std::time::Instant;

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kSharedEntry, Ed2kTransferRuntime, catalog::Ed2kSharedPublishStats},
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

const FRAGMENT: u64 = 180 * 1024;

/// Seed a fully verified (servable, non-hint) catalog entry so `update_by_hash`
/// resolves it for the demand-counter credit.
async fn seed_verified_entry(runtime: &Ed2kTransferRuntime, hash: &Ed2kHash) {
    let catalog = runtime.shared_catalog();
    let mut guard = catalog.write().await;
    let mut entries: Vec<Ed2kSharedEntry> = guard.iter().cloned().collect();
    entries.push(Ed2kSharedEntry {
        file_hash: hash.to_string(),
        display_name: "Seed.bin".to_string(),
        file_size: 4 * FRAGMENT,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        media: Default::default(),
        all_time_uploaded_bytes: 0,
        complete_parts: Vec::new(),
        publish: Ed2kSharedPublishStats::default(),
    });
    guard.replace_with(entries);
}

/// Read the catalog demand counters (all-time + session upload bytes) for a hash.
async fn catalog_counters(runtime: &Ed2kTransferRuntime, hash: &Ed2kHash) -> (u64, u64) {
    let catalog = runtime.shared_catalog();
    let guard = catalog.read().await;
    let idx = guard
        .index_by_hash(hash)
        .expect("seeded catalog entry must be indexed");
    (
        guard[idx].all_time_uploaded_bytes,
        guard[idx].publish.session_uploaded_bytes,
    )
}

#[tokio::test]
async fn contended_fragments_are_parked_then_flushed_without_loss() {
    let root = unique_test_dir("ed2k-catalog-upload-counter-no-loss");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = Ed2kHash::from_bytes([0x25; 16]);
    seed_verified_entry(&runtime, &hash).await;

    // Hold the catalog READ lock so every per-fragment `try_write` fails, exactly
    // like a publish-rank build in progress. The fragment credits must park.
    {
        let catalog = runtime.shared_catalog();
        let read_guard = catalog.read().await;
        for _ in 0..3 {
            runtime.add_file_all_time_uploaded(&hash, FRAGMENT).unwrap();
        }
        // Still contended: nothing has reached the catalog counter yet.
        let idx = read_guard.index_by_hash(&hash).unwrap();
        assert_eq!(read_guard[idx].all_time_uploaded_bytes, 0);
        assert_eq!(read_guard[idx].publish.session_uploaded_bytes, 0);
    }

    // Read lock dropped, but no further add happened yet: the 3 fragments are
    // still parked (the flush only fires on the next add or at session release).
    assert_eq!(catalog_counters(&runtime, &hash).await, (0, 0));

    // The next uncontended fragment flushes the WHOLE parked amount plus itself:
    // 4 fragments total, nothing lost.
    runtime.add_file_all_time_uploaded(&hash, FRAGMENT).unwrap();
    assert_eq!(
        catalog_counters(&runtime, &hash).await,
        (4 * FRAGMENT, 4 * FRAGMENT)
    );

    // A further uncontended fragment adds exactly once (no double-count of the
    // already-flushed bytes).
    runtime.add_file_all_time_uploaded(&hash, FRAGMENT).unwrap();
    assert_eq!(
        catalog_counters(&runtime, &hash).await,
        (5 * FRAGMENT, 5 * FRAGMENT)
    );
}

#[tokio::test]
async fn session_release_flushes_the_parked_tail() {
    let root = unique_test_dir("ed2k-catalog-upload-counter-release-flush");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let hash = Ed2kHash::from_bytes([0x26; 16]);
    seed_verified_entry(&runtime, &hash).await;

    let (handle, _status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x01, 0x0A00_0026), &hash, Instant::now())
        .await;

    // Park two fragments under contention, then release the read lock WITHOUT a
    // further add, so the tail stays parked (counter still zero).
    {
        let catalog = runtime.shared_catalog();
        let _read_guard = catalog.read().await;
        runtime.add_file_all_time_uploaded(&hash, FRAGMENT).unwrap();
        runtime.add_file_all_time_uploaded(&hash, FRAGMENT).unwrap();
    }
    assert_eq!(catalog_counters(&runtime, &hash).await, (0, 0));

    // Session release must drain the parked tail into the catalog.
    runtime.release_upload_session(&handle).await;
    assert_eq!(
        catalog_counters(&runtime, &hash).await,
        (2 * FRAGMENT, 2 * FRAGMENT)
    );
}

#[tokio::test]
async fn accepted_upload_sessions_count_once_across_guards_and_again_after_release() {
    let root = unique_test_dir("ed2k-upload-accepted-sessions");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let hash = Ed2kHash::from_bytes([0x27; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
    let accepted = || {
        database
            .query_row(
                "SELECT all_time_upload_accepts FROM known_files WHERE ed2k_hash=?1",
                [hash.0.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
    };
    let peer = upload_peer(1, 0x17, 0x0A00_0027);
    let (handle, status) = runtime
        .begin_upload_session_at(peer.clone(), &hash, Instant::now())
        .await;
    assert_eq!(
        status,
        crate::ed2k_transfer::Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        accepted(),
        0,
        "a queue grant is not an admitted payload request"
    );
    let first = runtime.begin_upload_work(&handle).await.unwrap();
    let parallel = runtime.begin_upload_work(&handle).await.unwrap();
    tokio::join!(
        runtime.note_file_upload_accept(&hash, &first),
        runtime.note_file_upload_accept(&hash, &parallel)
    );
    assert_eq!(accepted(), 0, "acceptance is parked until checkpoint");
    runtime.flush_parked_credit().await;
    assert_eq!(accepted(), 1);
    drop((first, parallel));
    let next_packet = runtime.begin_upload_work(&handle).await.unwrap();
    runtime.note_file_upload_accept(&hash, &next_packet).await;
    assert_eq!(accepted(), 1);
    drop(next_packet);
    runtime.release_upload_session(&handle).await;
    let (next, status) = runtime
        .begin_upload_session_at(peer, &hash, Instant::now())
        .await;
    assert_eq!(
        status,
        crate::ed2k_transfer::Ed2kUploadSessionStatus::Granted
    );
    let work = runtime.begin_upload_work(&next).await.unwrap();
    runtime.note_file_upload_accept(&hash, &work).await;
    runtime.flush_parked_credit().await;
    assert_eq!(accepted(), 2);
    let catalog = runtime.shared_catalog();
    let guard = catalog.read().await;
    let entry = &guard[guard.index_by_hash(&hash).unwrap()];
    assert_eq!(entry.publish.session_accept_count, 2);
    assert_eq!(entry.publish.all_time_accept_count, 2);
}

async fn seed_known_counter_file(runtime: &Ed2kTransferRuntime, hash: &Ed2kHash) {
    use emulebb_metadata::{MetadataIndexedFile, MetadataIndexedFileOrigin};
    let mut metadata = runtime.metadata.clone();
    metadata
        .upsert_indexed_file(
            &MetadataIndexedFile {
                ed2k_hash: hash.to_string(),
                name: "Sample.bin".into(),
                size_bytes: 4096,
                content_type: String::new(),
                availability_score: 0,
            },
            MetadataIndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    seed_verified_entry(runtime, hash).await;
}

#[tokio::test]
async fn accepted_stint_checkpoint_failure_preserves_credit_bytes_and_exactly_once_count() {
    let root = unique_test_dir("ed2k-upload-accept-checkpoint-failure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let hash = Ed2kHash::from_bytes([0x28; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
    let totals = || {
        database.query_row(
        "SELECT all_time_uploaded_bytes,all_time_upload_accepts FROM known_files WHERE ed2k_hash=?1",
        [hash.0.as_slice()], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?)),
    ).unwrap()
    };
    let peer = [0x39; 16];
    let (handle, _) = runtime
        .begin_upload_session_at(upload_peer(1, 0x18, 0x0A00_0028), &hash, Instant::now())
        .await;
    let work = runtime.begin_upload_work(&handle).await.unwrap();
    runtime.note_file_upload_accept(&hash, &work).await;
    runtime.add_file_all_time_uploaded(&hash, 11).unwrap();
    runtime.add_peer_credit_delta(peer, 9, 0).unwrap();
    database
        .execute_batch(
            "CREATE TRIGGER synthetic_accept_failure BEFORE UPDATE ON known_files
        WHEN new.all_time_upload_accepts > old.all_time_upload_accepts
        BEGIN SELECT RAISE(ABORT,'synthetic accepted-stint checkpoint failure'); END;",
        )
        .unwrap();
    runtime.flush_parked_credit().await;
    assert_eq!(totals(), (0, 0), "the entire batch rolls back together");
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM peers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    runtime.add_file_all_time_uploaded(&hash, 7).unwrap();
    runtime.add_peer_credit_delta(peer, 3, 0).unwrap();
    runtime.note_file_upload_accept(&hash, &work).await;
    database
        .execute_batch("DROP TRIGGER synthetic_accept_failure")
        .unwrap();
    runtime.flush_parked_credit().await;
    assert_eq!(totals(), (18, 1));
    let uploaded_at: Option<i64> = database
        .query_row("SELECT last_uploaded_at_s FROM known_files", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(uploaded_at.is_some_and(|at| at > 0 && at <= super::super::upload::unix_time_s()));
    assert_eq!(
        runtime
            .peer_credit_by_hash(peer)
            .unwrap()
            .unwrap()
            .uploaded_bytes,
        12
    );
    runtime.flush_parked_credit().await;
    assert_eq!(
        totals(),
        (18, 1),
        "retries and duplicate packets cannot double count"
    );
    drop(work);
    drop(database);
    drop(runtime);
    let reopened = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
    assert_eq!(
        database
            .query_row("SELECT all_time_upload_accepts FROM known_files", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .query_row("SELECT last_uploaded_at_s FROM known_files", [], |r| r
                .get::<_, Option<
                i64,
            >>(
                0
            ))
            .unwrap(),
        uploaded_at
    );
    assert_eq!(
        reopened
            .peer_credit_by_hash(peer)
            .unwrap()
            .unwrap()
            .uploaded_bytes,
        12
    );
}

#[tokio::test]
async fn session_statistics_survive_removal_rebuild_and_checkpoint_but_reset_on_restart() {
    use emulebb_metadata::MetadataFileUploadTotals;
    let root = unique_test_dir("ed2k-session-statistics-owner");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let hash = Ed2kHash::from_bytes([0x29; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
    database.execute("UPDATE known_files SET all_time_uploaded_bytes=100,all_time_upload_requests=5,all_time_upload_accepts=3", []).unwrap();
    let base = MetadataFileUploadTotals {
        uploaded_bytes: 100,
        upload_requests: 5,
        accepted_sessions: 3,
        ..Default::default()
    };
    runtime.observe_file_upload_statistics(&hash, base);
    let stale = runtime
        .shared_catalog()
        .read()
        .await
        .entry_by_hash(&hash)
        .unwrap()
        .clone();
    runtime.note_file_upload_request(&hash).await;
    let (handle, _) = runtime
        .begin_upload_session_at(upload_peer(1, 0x19, 0x0A00_0029), &hash, Instant::now())
        .await;
    let work = runtime.begin_upload_work(&handle).await.unwrap();
    runtime.note_file_upload_accept(&hash, &work).await;
    runtime.add_file_all_time_uploaded(&hash, 17).unwrap();
    let before = runtime.file_upload_statistics(&hash).unwrap();
    assert_eq!(
        (
            before.session_uploaded_bytes,
            before.session_upload_requests,
            before.session_accepted_uploads
        ),
        (17, 1, 1)
    );
    assert_eq!(
        (
            before.lifetime.uploaded_bytes,
            before.lifetime.upload_requests,
            before.lifetime.accepted_sessions
        ),
        (117, 6, 4)
    );
    runtime
        .shared_catalog()
        .write()
        .await
        .upsert_verified(hash, None);
    runtime.note_file_upload_request(&hash).await;
    let expected = runtime.file_upload_statistics(&hash).unwrap();
    assert_eq!(expected.session_upload_requests, 2);
    assert_eq!(expected.lifetime.upload_requests, 7);
    assert_eq!(expected.lifetime.uploaded_bytes, 117);
    assert_eq!(expected.lifetime.accepted_sessions, 4);
    runtime
        .shared_catalog()
        .write()
        .await
        .replace_with(Vec::new());
    assert_eq!(runtime.file_upload_statistics(&hash), Some(expected));
    runtime
        .shared_catalog()
        .write()
        .await
        .replace_with(vec![stale.clone()]);
    {
        let catalog = runtime.shared_catalog();
        let guard = catalog.read().await;
        let entry = guard.entry_by_hash(&hash).unwrap();
        assert_eq!(
            (
                entry.publish.session_uploaded_bytes,
                entry.publish.session_request_count,
                entry.publish.session_accept_count
            ),
            (17, 2, 1)
        );
        assert_eq!(entry.all_time_uploaded_bytes, 117);
        assert_eq!(entry.publish.all_time_accept_count, 4);
    }
    runtime.flush_parked_credit().await;
    assert_eq!(runtime.file_upload_statistics(&hash), Some(expected));
    runtime.shared_catalog().write().await.retain(|_| false);
    runtime.shared_catalog().write().await.push(stale);
    assert_eq!(runtime.file_upload_statistics(&hash), Some(expected));
    drop(work);
    drop(database);
    drop(runtime);
    let reopened = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let restored = reopened.observe_file_upload_statistics(&hash, expected.lifetime);
    assert_eq!(
        (
            restored.session_uploaded_bytes,
            restored.session_upload_requests,
            restored.session_accepted_uploads
        ),
        (0, 0, 0)
    );
    assert_eq!(restored.lifetime, expected.lifetime);
}

#[tokio::test]
async fn passive_and_unknown_demand_do_not_allocate_client_session_records() {
    use emulebb_metadata::{MetadataIndexedFile, MetadataIndexedFileOrigin};
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-passive-demand-accounting"))
            .unwrap();
    let hash = Ed2kHash::from_bytes([0x2A; 16]);
    let mut metadata = runtime.metadata.clone();
    metadata
        .upsert_indexed_file(
            &MetadataIndexedFile {
                ed2k_hash: hash.to_string(),
                name: "Remote.bin".into(),
                size_bytes: 32,
                content_type: String::new(),
                availability_score: 0,
            },
            MetadataIndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    runtime.note_file_upload_request(&hash).await;
    assert!(runtime.file_upload_statistics(&hash).is_none());
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap()
            .totals
            .upload_requests,
        0
    );
    let unknown = Ed2kHash::from_bytes([0x2B; 16]);
    runtime.note_file_upload_request(&unknown).await;
    assert!(runtime.file_upload_statistics(&unknown).is_none());
    assert!(runtime.parked_credit.lock().file_statistics.is_empty());
    runtime.flush_parked_credit().await;
    assert_eq!(
        runtime
            .metadata
            .file_upload_snapshot(&hash.to_string())
            .unwrap()
            .unwrap()
            .totals
            .upload_requests,
        1
    );
    assert!(
        runtime
            .metadata
            .file_upload_snapshot(&unknown.to_string())
            .unwrap()
            .is_none()
    );
    assert!(runtime.parked_credit.lock().file_statistics.is_empty());
}

#[tokio::test]
async fn request_and_acceptance_capture_do_not_wait_for_catalog_projection() {
    use std::{future::Future, task::Context};
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-catalog-accounting-capture"))
            .unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let hash = Ed2kHash::from_bytes([0x2C; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let (handle, _) = runtime
        .begin_upload_session_at(upload_peer(1, 0x1C, 0x0A00_002C), &hash, Instant::now())
        .await;
    let work = runtime.begin_upload_work(&handle).await.unwrap();
    let catalog = runtime.shared_catalog();
    let held_projection = catalog.read().await;
    let database = rusqlite::Connection::open(runtime.root_dir.join("metadata.sqlite")).unwrap();
    database.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(
        std::pin::pin!(runtime.note_file_upload_request(&hash))
            .as_mut()
            .poll(&mut context)
            .is_ready()
    );
    assert!(
        std::pin::pin!(runtime.note_file_upload_accept(&hash, &work))
            .as_mut()
            .poll(&mut context)
            .is_ready()
    );
    let current = runtime.file_upload_statistics(&hash).unwrap();
    assert_eq!(
        (
            current.session_upload_requests,
            current.session_accepted_uploads
        ),
        (1, 1)
    );
    assert_eq!(
        held_projection
            .entry_by_hash(&hash)
            .unwrap()
            .publish
            .session_request_count,
        0
    );
    assert_eq!(
        database
            .query_row(
                "SELECT all_time_upload_requests FROM known_files",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    database.execute_batch("ROLLBACK").unwrap();
    drop(held_projection);
    drop(work);
    runtime.release_upload_session(&handle).await;
    let guard = catalog.read().await;
    assert_eq!(
        guard
            .entry_by_hash(&hash)
            .unwrap()
            .publish
            .session_request_count,
        1
    );
    assert_eq!(
        guard
            .entry_by_hash(&hash)
            .unwrap()
            .publish
            .session_accept_count,
        1
    );
}

#[tokio::test]
async fn epoch_zero_request_time_survives_accounting_projection() {
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-accounting-epoch-zero"))
            .unwrap();
    let hash = Ed2kHash::from_bytes([0x2D; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let catalog = runtime.shared_catalog();
    let mut entry = catalog.read().await.entry_by_hash(&hash).unwrap().clone();
    entry.publish.last_upload_requested_at_s = Some(0);
    catalog
        .write()
        .await
        .upsert_verified(hash, Some(entry.clone()));
    assert_eq!(
        runtime
            .file_upload_statistics(&hash)
            .unwrap()
            .lifetime
            .last_requested_at_s,
        Some(0)
    );
    entry.publish.last_upload_requested_at_s = None;
    catalog.write().await.upsert_verified(hash, None);
    catalog.write().await.upsert_verified(hash, Some(entry));
    assert_eq!(
        catalog
            .read()
            .await
            .entry_by_hash(&hash)
            .unwrap()
            .publish
            .last_upload_requested_at_s,
        Some(0)
    );
}

#[tokio::test]
async fn cached_client_session_demand_survives_rejected_sql_write() {
    let root = unique_test_dir("ed2k-accounting-demand-write-failure");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let hash = Ed2kHash::from_bytes([0x2E; 16]);
    seed_known_counter_file(&runtime, &hash).await;
    let database = rusqlite::Connection::open(root.join("metadata.sqlite")).unwrap();
    database.execute_batch("CREATE TRIGGER synthetic_request_failure BEFORE UPDATE OF all_time_upload_requests ON known_files
        BEGIN SELECT RAISE(ABORT,'synthetic demand failure'); END;").unwrap();
    runtime.note_file_upload_request(&hash).await;
    runtime.add_file_all_time_uploaded(&hash, 7).unwrap();
    runtime.add_peer_credit_delta([0x4E; 16], 3, 0).unwrap();
    assert!(runtime.checkpoint_upload_accounting().await.is_err());
    assert_eq!(
        runtime
            .file_upload_statistics(&hash)
            .unwrap()
            .session_upload_requests,
        1
    );
    assert_eq!(
        runtime
            .shared_catalog()
            .read()
            .await
            .entry_by_hash(&hash)
            .unwrap()
            .publish
            .session_request_count,
        1
    );
    assert_eq!(
        database
            .query_row(
                "SELECT all_time_upload_requests FROM known_files",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT all_time_uploaded_bytes FROM known_files", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        database
            .query_row("SELECT count(*) FROM peers", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    database
        .execute_batch("DROP TRIGGER synthetic_request_failure")
        .unwrap();
    runtime.note_file_upload_request(&hash).await;
    assert_eq!(
        runtime
            .file_upload_statistics(&hash)
            .unwrap()
            .session_upload_requests,
        2
    );
    runtime.flush_parked_credit().await;
    runtime.flush_parked_credit().await;
    let stored = runtime
        .metadata
        .file_upload_snapshot(&hash.to_string())
        .unwrap()
        .unwrap()
        .totals;
    assert_eq!(stored.upload_requests, 2);
    assert_eq!(stored.uploaded_bytes, 7);
    assert_eq!(
        stored,
        runtime.file_upload_statistics(&hash).unwrap().lifetime
    );
    assert_eq!(
        database
            .query_row("SELECT uploaded_bytes FROM peers", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
}
