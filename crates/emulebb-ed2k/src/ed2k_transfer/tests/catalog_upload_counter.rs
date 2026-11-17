//! RUST-PAR-025 Note-1: the per-fragment shared-catalog demand-upload counter
//! must never drop a served fragment when the catalog write lock is contended
//! (e.g. by a publish-rank build holding the read lock). Fragments credited
//! while `try_write` fails are parked and flushed on the next successful
//! `try_write` (per fragment) and unconditionally at session release, so the
//! counter equals the full sum of served bytes while the hot path stays
//! non-blocking.

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
