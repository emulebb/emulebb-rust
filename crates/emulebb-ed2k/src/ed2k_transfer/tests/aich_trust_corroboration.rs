//! Network-learned AICH root corroboration (FIX 3 / parity with
//! `CAICHRecoveryHashSet::AddHash`/`SetStatus`).
//!
//! A network-learned root must NOT become salvage-authorizing until at least
//! `MINUNIQUEIPS_TOTRUST` (10) distinct IPs have proposed it at
//! `MINPERCENTAGE_TOTRUST` (92%) agreement. Authoritative roots (locally
//! computed / persisted) are trusted on sight.

use std::net::IpAddr;

use super::super::{Ed2kTransferRuntime, new_transfer_job};
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
    assert_eq!(reloaded.aich_root.as_deref(), Some(hex::encode(root).as_str()));
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
