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
async fn first_verified_key_keeps_credits_then_different_key_wipes() {
    let root = unique_test_dir("ed2k-transfer-verified-ident");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    // Verify a first key on a fresh slot (no prior credit): key bound, nothing
    // wiped. Then accumulate credit under the verified key.
    let wiped_first = runtime
        .record_verified_secure_ident(HASH_A, &[1u8; 80])
        .unwrap();
    assert!(!wiped_first);
    runtime.add_peer_credit_delta(HASH_A, 4000, 8000).unwrap();
    let credit = runtime.peer_credit_by_hash(HASH_A).unwrap().unwrap();
    assert_eq!(credit.uploaded_bytes, 4000);
    assert_eq!(credit.downloaded_bytes, 8000);

    // Same key again: still kept.
    let wiped_same = runtime
        .record_verified_secure_ident(HASH_A, &[1u8; 80])
        .unwrap();
    assert!(!wiped_same);

    // A different key for the same user hash: credits wiped to the sentinel.
    let wiped_new = runtime
        .record_verified_secure_ident(HASH_A, &[2u8; 80])
        .unwrap();
    assert!(wiped_new);
    let credit = runtime.peer_credit_by_hash(HASH_A).unwrap().unwrap();
    assert_eq!(credit.uploaded_bytes, 1);
    assert_eq!(credit.downloaded_bytes, 1);
}
