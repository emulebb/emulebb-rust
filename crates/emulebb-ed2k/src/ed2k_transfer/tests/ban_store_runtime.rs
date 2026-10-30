//! Runtime-level tests for the client ban store (FIX 1) and the verified
//! secure-ident pubkey binding / wipe-on-new-key (FIX 2), driven through the
//! `Ed2kTransferRuntime` public surface.

use std::net::Ipv4Addr;

use crate::ed2k_transfer::Ed2kTransferRuntime;
use crate::paths::unique_test_dir;

const HASH_A: [u8; 16] = [0xAA; 16];
const HASH_B: [u8; 16] = [0xBB; 16];

#[tokio::test]
async fn runtime_ban_is_enforced_by_either_key() {
    let root = unique_test_dir("ed2k-transfer-ban-store");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let ip = Ipv4Addr::new(203, 0, 113, 9);

    assert!(!runtime.is_client_banned(Some(ip), Some(&HASH_A)));
    runtime.ban_client(Some(ip), Some(HASH_A));

    // Banned by IP (any hash) and by hash (any IP), mirroring IsBannedClient.
    assert!(runtime.is_client_banned(Some(ip), Some(&HASH_B)));
    let other_ip = Ipv4Addr::new(203, 0, 113, 50);
    assert!(runtime.is_client_banned(Some(other_ip), Some(&HASH_A)));
    // Unrelated client is not banned.
    assert!(!runtime.is_client_banned(Some(other_ip), Some(&HASH_B)));
}

#[tokio::test]
async fn first_verified_key_is_hydrated_after_restart_and_rejects_rebinding() {
    let root = unique_test_dir("ed2k-transfer-verified-ident");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let first_key = [1u8; 80];
    let replacement_key = [2u8; 80];
    let first_bind = runtime
        .bind_verified_secure_ident(HASH_A, &first_key)
        .unwrap();
    assert!(first_bind.accepted());
    assert_eq!(first_bind.pinned_public_key(), first_key);
    runtime.add_peer_credit_delta(HASH_A, 4000, 8000).unwrap();
    runtime.flush_parked_credit().await;
    drop(runtime);

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert_eq!(
        runtime.pinned_secure_ident_public_key(HASH_A).unwrap(),
        Some(first_key.to_vec())
    );
    let credit = runtime.peer_credit_by_hash(HASH_A).unwrap().unwrap();
    assert_eq!(credit.uploaded_bytes, 4000);
    assert_eq!(credit.downloaded_bytes, 8000);

    let same_key = runtime
        .bind_verified_secure_ident(HASH_A, &first_key)
        .unwrap();
    assert!(same_key.accepted());
    assert_eq!(same_key.pinned_public_key(), first_key);

    let mismatch = runtime
        .bind_verified_secure_ident(HASH_A, &replacement_key)
        .unwrap();
    assert!(!mismatch.accepted());
    assert_eq!(mismatch.pinned_public_key(), first_key);
    assert_eq!(
        runtime.pinned_secure_ident_public_key(HASH_A).unwrap(),
        Some(first_key.to_vec())
    );
    let credit = runtime.peer_credit_by_hash(HASH_A).unwrap().unwrap();
    assert_eq!(credit.uploaded_bytes, 4000);
    assert_eq!(credit.downloaded_bytes, 8000);
}
