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
