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
        canonical_name: "Seed.bin".to_string(),
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
