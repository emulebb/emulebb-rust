//! Network-learned AICH root corroboration (FIX 3 / parity with
//! `CAICHRecoveryHashSet::AddHash`/`SetStatus`).
//!
//! A network-learned root must NOT become salvage-authorizing until at least
//! `MINUNIQUEIPS_TOTRUST` (10) distinct IPs have proposed it at
//! `MINPERCENTAGE_TOTRUST` (92%) agreement. Authoritative roots (locally
//! computed / explicitly supplied) have separate authority. An accepted
//! persisted decision resumes VERIFIED as stock while retaining its origin.

use std::net::IpAddr;

use super::super::{Ed2kAichHashset, Ed2kAichRootOrigin, Ed2kTransferRuntime, new_transfer_job};
use crate::paths::unique_test_dir;
use emulebb_kad_proto::Ed2kHash;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::from([a, b, c, d])
}

async fn runtime_with_job() -> (Ed2kTransferRuntime, String) {
    let root = unique_test_dir("ed2k-aich-corroboration");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x11; 16]);
    let job = new_transfer_job(file_hash, "corroboration.bin".to_string(), 4 * 9_728_000);
    runtime.ensure_job(&job).await.unwrap();
    (runtime, job.file_hash)
}

#[tokio::test]
async fn single_peer_root_is_not_trusted() {
    let (runtime, file_hash) = runtime_with_job().await;
    let manifest = runtime
        .record_network_aich_root(&file_hash, Some([0xAB; 20]), ip(203, 0, 113, 5))
        .await
        .unwrap();
    assert!(
        manifest.aich_root.is_none(),
        "a single peer's proposed root must not be promoted"
    );
    // And it must not be persisted either.
    let reloaded = runtime.manifest(&file_hash).await.unwrap();
    assert!(reloaded.aich_root.is_none());
}

fn consistent_candidate() -> Ed2kAichHashset {
    let part_hashes = vec![[0x21; 20], [0x43; 20], [0x65; 20], [0x87; 20]];
    let master_hash = super::super::hashset::reconstruct_aich_root_from_part_hashes(
        4 * super::super::ED2K_PART_SIZE,
        &part_hashes,
    )
    .unwrap();
    Ed2kAichHashset {
        master_hash,
        part_hashes,
    }
}

fn accept_independent_root(
    runtime: &Ed2kTransferRuntime,
    manifest: &super::super::Ed2kResumeManifest,
    root: [u8; 20],
    stock: bool,
) {
    let fingerprint = emulebb_metadata::NativeFileFingerprint {
        identity: emulebb_metadata::NativeFileIdentity::Unix {
            device_id: 1,
            inode_number: 2,
        },
        size_bytes: manifest.file_size,
        modified: emulebb_metadata::NativeFileTimestamp::new(0, 0).unwrap(),
        changed: None,
    };
    let path = runtime.root_dir.join("accepted-local.bin");
    if stock {
        runtime
            .metadata
            .accept_imported_local_files(&[(
                emulebb_metadata::MetadataFileImportRecord {
                    file_hash: manifest.file_hash.clone(),
                    display_name: "accepted-stock.bin".to_owned(),
                    file_size: manifest.file_size,
                    modified_s: 0,
                    md4_hashset: Vec::new(),
                    aich_root: Some(hex::encode(root)),
                    aich_hashset: Vec::new(),
                    upload_priority: "normal".to_owned(),
                    auto_upload_priority: false,
                    all_time_uploaded_bytes: 0,
                    all_time_upload_requests: 0,
                    all_time_upload_accepts: 0,
                    last_upload_request_ms: 0,
                },
                path,
                fingerprint,
            )])
            .unwrap();
    } else {
        runtime
            .metadata
            .upsert_verified_local_content(&emulebb_metadata::MetadataVerifiedLocalContent {
                file_hash: manifest.file_hash.clone(),
                display_name: "accepted-local.bin".to_owned(),
                file_size: manifest.file_size,
                part_size: manifest.piece_size,
                md4_hashset: Vec::new(),
                aich_root: Some(hex::encode(root)),
                aich_hashset: Vec::new(),
                path,
                fingerprint,
                upload_priority: "normal".to_owned(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn accepted_authority_retires_old_parts_without_another_vote_and_after_restart() {
    for stock in [false, true] {
        let (runtime, file_hash) = runtime_with_job().await;
        let old = consistent_candidate();
        let observations = (0..10)
            .map(|signer| (old.master_hash, ip(203, signer, 0, 1)))
            .collect::<Vec<_>>();
        runtime
            .record_network_aich_observations(&file_hash, &observations)
            .await
            .unwrap();
        let mut stale = runtime
            .store_aich_hashset(&file_hash, old.clone())
            .await
            .unwrap();
        // Simulate a newer cache-only append: identity refresh must not reload
        // old SQL piece rows over independently received payload progress.
        stale.pieces[0].bytes_written = 123;
        runtime.cache_manifest_unlocked(&stale).await;
        let mut replacement = consistent_candidate();
        replacement.part_hashes[0] = [0x91; 20];
        replacement.master_hash = super::super::hashset::reconstruct_aich_root_from_part_hashes(
            stale.file_size,
            &replacement.part_hashes,
        )
        .unwrap();
        accept_independent_root(&runtime, &stale, replacement.master_hash, stock);

        // Verify SQL before any runtime refresh or new peer observation. Both
        // cold loaders must see one coherent accepted decision.
        let persisted = runtime
            .metadata
            .transfer_manifest_by_hash(&file_hash)
            .unwrap()
            .unwrap();
        let listed = runtime.metadata.incomplete_transfer_manifests().unwrap();
        assert_eq!(listed[0].aich_root, persisted.aich_root);
        assert_eq!(
            persisted.aich_root,
            Some(hex::encode(replacement.master_hash))
        );
        assert!(persisted.aich_trust_generation > stale.aich_trust_generation);
        assert!(!persisted.aich_hashset_acquired);
        assert!(persisted.aich_hashset.is_empty());
        let current = runtime.manifest(&file_hash).await.unwrap();
        assert_eq!(current.pieces[0].bytes_written, 123);
        assert_eq!(current.aich_root, persisted.aich_root);
        assert!(!current.aich_hashset_acquired);
        let rejected = runtime
            .store_aich_hashset_for_generation(&file_hash, old, stale.aich_trust_generation)
            .await
            .unwrap();
        assert!(!rejected.aich_hashset_acquired);

        // A delayed full checkpoint also cannot restore its old root, origin,
        // generation or acquired set. Its independent piece progress survives.
        let guard = runtime.lock_manifest(&file_hash).await;
        runtime.store_manifest_unlocked(&stale).await.unwrap();
        drop(guard);
        let directory = runtime.root_dir.clone();
        drop(runtime);
        let resumed = Ed2kTransferRuntime::load_or_create(&directory).unwrap();
        let cold = resumed.manifest(&file_hash).await.unwrap();
        assert_eq!(cold.aich_root, persisted.aich_root);
        assert_eq!(cold.aich_trust_generation, persisted.aich_trust_generation);
        assert_eq!(cold.pieces[0].bytes_written, 123);
        assert!(!cold.aich_hashset_acquired);
        assert_eq!(
            cold.aich_root_origin,
            Some(if stock {
                Ed2kAichRootOrigin::StockImport
            } else {
                Ed2kAichRootOrigin::LocalComputed
            })
        );
        let acquired = resumed
            .store_aich_hashset_for_generation(&file_hash, replacement, cold.aich_trust_generation)
            .await
            .unwrap();
        assert!(acquired.aich_hashset_acquired);
    }
}

#[tokio::test]
async fn internally_consistent_peer_hashset_does_not_establish_trust() {
    let (runtime, file_hash) = runtime_with_job().await;
    let candidate = consistent_candidate();
    runtime
        .record_network_aich_root(&file_hash, Some(candidate.master_hash), ip(203, 0, 113, 5))
        .await
        .unwrap();
    let error = runtime
        .store_aich_hashset(&file_hash, candidate)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("independently trusted master"));
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert!(manifest.aich_root.is_none());
    assert!(manifest.aich_hashset.is_empty());
    assert!(!manifest.aich_hashset_acquired);
}

#[tokio::test]
async fn consistent_part_set_activates_only_after_independent_corroboration() {
    let (runtime, file_hash) = runtime_with_job().await;
    let candidate = consistent_candidate();
    for signer in 0..9 {
        runtime
            .record_network_aich_root(
                &file_hash,
                Some(candidate.master_hash),
                ip(203, signer, 0, 1),
            )
            .await
            .unwrap();
    }
    assert!(
        runtime
            .store_aich_hashset(&file_hash, candidate.clone())
            .await
            .is_err()
    );
    runtime
        .record_network_aich_root(&file_hash, Some(candidate.master_hash), ip(203, 9, 0, 1))
        .await
        .unwrap();
    let manifest = runtime
        .store_aich_hashset(&file_hash, candidate.clone())
        .await
        .unwrap();
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(manifest.aich_root, Some(hex::encode(candidate.master_hash)));
    assert_eq!(manifest.aich_hashset.len(), 4);
}

#[tokio::test]
async fn conflicting_consistent_hashset_cannot_replace_authoritative_identity() {
    let (runtime, file_hash) = runtime_with_job().await;
    let authoritative = [0x99; 20];
    runtime
        .reconcile_aich_root(&file_hash, Some(authoritative))
        .await
        .unwrap();
    assert!(
        runtime
            .store_aich_hashset(&file_hash, consistent_candidate())
            .await
            .is_err()
    );
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(manifest.aich_root, Some(hex::encode(authoritative)));
    assert!(!manifest.aich_hashset_acquired);
}

#[tokio::test]
async fn live_consensus_demotion_clears_part_set_and_rejects_aba_answer() {
    let (runtime, file_hash) = runtime_with_job().await;
    let candidate = consistent_candidate();
    let observations = (0..10)
        .map(|signer| (candidate.master_hash, ip(203, signer, 0, 1)))
        .collect::<Vec<_>>();
    let accepted = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    assert_eq!(
        accepted.aich_root_origin,
        Some(Ed2kAichRootOrigin::NetworkConsensus)
    );
    runtime
        .store_aich_hashset(&file_hash, candidate.clone())
        .await
        .unwrap();
    let demoted = runtime
        .record_network_aich_root(&file_hash, Some([0xff; 20]), ip(198, 0, 0, 1))
        .await
        .unwrap();
    assert!(demoted.aich_root.is_none());
    assert!(demoted.aich_hashset.is_empty());
    assert!(!demoted.aich_hashset_acquired);
    assert!(demoted.aich_trust_generation > accepted.aich_trust_generation);

    let observations = [10, 11].map(|signer| (candidate.master_hash, ip(203, signer, 0, 1)));
    let renewed = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    assert_eq!(renewed.aich_root, accepted.aich_root);
    assert!(renewed.aich_trust_generation > demoted.aich_trust_generation);
    let stale = runtime
        .store_aich_hashset_for_generation(
            &file_hash,
            candidate.clone(),
            accepted.aich_trust_generation,
        )
        .await
        .unwrap();
    assert!(!stale.aich_hashset_acquired);
    let current = runtime
        .store_aich_hashset_for_generation(&file_hash, candidate, renewed.aich_trust_generation)
        .await
        .unwrap();
    assert!(current.aich_hashset_acquired);
}

#[tokio::test]
async fn accepted_consensus_resumes_verified_without_erasing_network_origin() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0x42; 20];
    let observations = (0..10)
        .map(|signer| (root, ip(203, signer, 0, 1)))
        .collect::<Vec<_>>();
    let accepted = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    let directory = runtime.root_dir.clone();
    drop(runtime);
    let resumed = Ed2kTransferRuntime::load_or_create(&directory).unwrap();
    let observations = (0..20)
        .map(|signer| ([0xff; 20], ip(198, signer, 0, 1)))
        .collect::<Vec<_>>();
    let manifest = resumed
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    assert_eq!(manifest.aich_root, accepted.aich_root);
    assert_eq!(
        manifest.aich_trust_generation,
        accepted.aich_trust_generation
    );
    assert_eq!(
        manifest.aich_root_origin,
        Some(Ed2kAichRootOrigin::NetworkConsensus)
    );
}

#[tokio::test]
async fn canceled_acceptance_finishes_publication_before_conflicting_vote() {
    use std::{sync::Arc, time::Duration};

    let (runtime, file_hash) = runtime_with_job().await;
    let runtime = Arc::new(runtime);
    let root = [0x42; 20];
    let observations = (0..9)
        .map(|signer| (root, ip(203, signer, 0, 1)))
        .collect::<Vec<_>>();
    runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    let barrier = Arc::new(super::super::aich_trust::AichPersistBarrier::default());
    *runtime.aich_persist_barrier.lock().unwrap() = Some(Arc::clone(&barrier));
    let caller = {
        let runtime = Arc::clone(&runtime);
        let hash = file_hash.clone();
        tokio::spawn(async move {
            runtime
                .record_network_aich_root(&hash, Some(root), ip(203, 9, 0, 1))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), barrier.committed.notified())
        .await
        .unwrap();
    // SQL has committed but publication is deliberately paused. Aborting the
    // caller must not release the manifest gate or abandon the staged votes.
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        runtime.manifest_locks.lock().unwrap()[&file_hash]
            .try_lock()
            .is_err()
    );
    assert!(
        runtime.manifest_cache.lock().await[&file_hash]
            .aich_root
            .is_none()
    );
    let disagreeing = {
        let runtime = Arc::clone(&runtime);
        let hash = file_hash.clone();
        tokio::spawn(async move {
            runtime
                .record_network_aich_root(&hash, Some([0xff; 20]), ip(198, 0, 0, 1))
                .await
        })
    };
    barrier.release.notify_one();
    let demoted = tokio::time::timeout(Duration::from_secs(5), disagreeing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(demoted.aich_root.is_none());
    assert_eq!(demoted.aich_trust_generation, 2);
    let persisted = runtime
        .metadata
        .transfer_manifest_by_hash(&file_hash)
        .unwrap()
        .unwrap();
    assert_eq!(persisted.aich_root, demoted.aich_root);
    assert_eq!(
        persisted.aich_trust_generation,
        demoted.aich_trust_generation
    );
    let directory = runtime.root_dir.clone();
    drop(runtime);
    let resumed = Ed2kTransferRuntime::load_or_create(&directory).unwrap();
    assert!(
        resumed
            .manifest(&file_hash)
            .await
            .unwrap()
            .aich_root
            .is_none()
    );
}

#[tokio::test]
async fn operator_identity_supersedes_live_consensus_without_peer_veto() {
    let (runtime, file_hash) = runtime_with_job().await;
    let candidate = consistent_candidate();
    let observations = (0..10)
        .map(|signer| (candidate.master_hash, ip(203, signer, 0, 1)))
        .collect::<Vec<_>>();
    runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&file_hash, candidate)
        .await
        .unwrap();
    let root = [0x77; 20];
    let manifest = runtime
        .reconcile_aich_root(&file_hash, Some(root))
        .await
        .unwrap();
    assert_eq!(
        manifest.aich_root_origin,
        Some(Ed2kAichRootOrigin::OperatorLink)
    );
    assert!(manifest.aich_hashset.is_empty());
    assert!(
        !runtime
            .aich_root_corroboration
            .lock()
            .unwrap()
            .contains_key(&file_hash)
    );
    let observations = (0..20)
        .map(|signer| ([0xff; 20], ip(198, signer, 0, 1)))
        .collect::<Vec<_>>();
    let manifest = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    assert_eq!(manifest.aich_root, Some(hex::encode(root)));
}

#[tokio::test]
async fn deleting_transfer_releases_its_bounded_votes() {
    let (runtime, file_hash) = runtime_with_job().await;
    runtime
        .record_network_aich_root(&file_hash, Some([1; 20]), ip(203, 0, 0, 1))
        .await
        .unwrap();
    assert!(
        runtime
            .aich_root_corroboration
            .lock()
            .unwrap()
            .contains_key(&file_hash)
    );
    assert!(runtime.delete_transfer_files(&file_hash).await.unwrap());
    assert!(
        !runtime
            .aich_root_corroboration
            .lock()
            .unwrap()
            .contains_key(&file_hash)
    );
}

#[tokio::test]
async fn new_local_authority_replaces_cached_consensus_before_more_network_votes() {
    let (runtime, file_hash) = runtime_with_job().await;
    let candidate = consistent_candidate();
    let observations = (0..10)
        .map(|signer| (candidate.master_hash, ip(203, signer, 0, 1)))
        .collect::<Vec<_>>();
    let accepted = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&file_hash, candidate)
        .await
        .unwrap();
    let root = [0x77; 20];
    // Model independently accepted local evidence. No payload file is needed:
    // metadata admission never rehashes bytes supplied by its trusted caller.
    runtime
        .metadata
        .upsert_verified_local_content(&emulebb_metadata::MetadataVerifiedLocalContent {
            file_hash: file_hash.clone(),
            display_name: "accepted-local.bin".to_owned(),
            file_size: accepted.file_size,
            part_size: accepted.piece_size,
            md4_hashset: Vec::new(),
            aich_root: Some(hex::encode(root)),
            aich_hashset: Vec::new(),
            path: runtime.root_dir.join("accepted-local.bin"),
            fingerprint: emulebb_metadata::NativeFileFingerprint {
                identity: emulebb_metadata::NativeFileIdentity::Unix {
                    device_id: 1,
                    inode_number: 2,
                },
                size_bytes: accepted.file_size,
                modified: emulebb_metadata::NativeFileTimestamp::new(0, 0).unwrap(),
                changed: None,
            },
            upload_priority: "normal".to_owned(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        })
        .unwrap();
    let manifest = runtime
        .record_network_aich_root(&file_hash, Some([0xff; 20]), ip(198, 0, 0, 1))
        .await
        .unwrap();
    assert_eq!(manifest.aich_root, Some(hex::encode(root)));
    assert_eq!(
        manifest.aich_root_origin,
        Some(Ed2kAichRootOrigin::LocalComputed)
    );
    assert!(manifest.aich_trust_generation > accepted.aich_trust_generation);
    assert!(!manifest.aich_hashset_acquired);
    assert!(
        !runtime
            .aich_root_corroboration
            .lock()
            .unwrap()
            .contains_key(&file_hash)
    );
}

#[tokio::test]
async fn ten_unique_ip_majority_root_is_promoted() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0xCD; 20];
    let mut last = None;
    // Ten distinct /20 networks so masking keeps each unique.
    for i in 0..10u8 {
        last = Some(
            runtime
                .record_network_aich_root(&file_hash, Some(root), ip(203, i, 0, 9))
                .await
                .unwrap(),
        );
    }
    let manifest = last.unwrap();
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some(hex::encode(root).as_str()),
        "a 10-unique-IP unanimous root must be promoted"
    );
    // Persisted.
    let reloaded = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(
        reloaded.aich_root.as_deref(),
        Some(hex::encode(root).as_str())
    );
}

#[tokio::test]
async fn batched_independent_observations_promote_once() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0xCE; 20];
    let observations = (0..10u8)
        .map(|index| (root, ip(203, index, 0, 9)))
        .collect::<Vec<_>>();
    let manifest = runtime
        .record_network_aich_observations(&file_hash, &observations)
        .await
        .unwrap();
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some(hex::encode(root).as_str())
    );
}

#[tokio::test]
async fn nine_unique_ips_below_threshold_not_trusted() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0x42; 20];
    for i in 0..9u8 {
        runtime
            .record_network_aich_root(&file_hash, Some(root), ip(198, i, 0, 1))
            .await
            .unwrap();
    }
    let reloaded = runtime.manifest(&file_hash).await.unwrap();
    assert!(
        reloaded.aich_root.is_none(),
        "nine unique IPs is below MINUNIQUEIPS_TOTRUST (10)"
    );
}

#[tokio::test]
async fn same_subnet_floods_do_not_promote() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0x99; 20];
    // Twenty addresses, all within the same /20 -> one unique signer.
    for d in 0..20u8 {
        runtime
            .record_network_aich_root(&file_hash, Some(root), ip(10, 0, 0, d))
            .await
            .unwrap();
    }
    let reloaded = runtime.manifest(&file_hash).await.unwrap();
    assert!(
        reloaded.aich_root.is_none(),
        "a single-subnet flood must not count as 10 unique IPs"
    );
}

#[tokio::test]
async fn authoritative_seed_root_is_trusted_immediately() {
    let (runtime, file_hash) = runtime_with_job().await;
    let root = [0x77; 20];
    let manifest = runtime
        .reconcile_aich_root(&file_hash, Some(root))
        .await
        .unwrap();
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some(hex::encode(root).as_str()),
        "an authoritative root must be trusted on sight"
    );
}

#[tokio::test]
async fn network_proposals_ignored_once_authoritative_root_present() {
    let (runtime, file_hash) = runtime_with_job().await;
    let authoritative = [0x01; 20];
    runtime
        .reconcile_aich_root(&file_hash, Some(authoritative))
        .await
        .unwrap();
    // A flood of peers proposing a DIFFERENT root must not displace it.
    let attacker = [0xFF; 20];
    for i in 0..15u8 {
        runtime
            .record_network_aich_root(&file_hash, Some(attacker), ip(203, i, 16, 3))
            .await
            .unwrap();
    }
    let reloaded = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(
        reloaded.aich_root.as_deref(),
        Some(hex::encode(authoritative).as_str()),
        "the authoritative root must win over network proposals"
    );
}
