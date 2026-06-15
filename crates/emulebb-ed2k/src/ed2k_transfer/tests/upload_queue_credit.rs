use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadSessionStatus},
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer, upload_peer_with_ident};

#[tokio::test]
async fn upload_queue_scores_waiters_with_persisted_peer_credits() {
    let root = unique_test_dir("ed2k-upload-queue-peer-credit");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xE1; 16]);
    let credited_user_hash = [0xE3; 16];
    runtime
        .record_peer_credit_totals(credited_user_hash, 1_048_576, 20 * 1_048_576)
        .unwrap();

    let now = Instant::now();
    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0xE1, 0x0A00_0051), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (regular_handle, regular_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0xE2, 0x0A00_0052), &file_hash, now)
        .await;
    assert_eq!(regular_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (credited_handle, credited_status) = runtime
        .begin_upload_session_at(
            upload_peer(3, credited_user_hash[0], 0x0A00_0053),
            &file_hash,
            now,
        )
        .await;
    assert_eq!(
        credited_status,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );

    let scored_at = now + Duration::from_secs(1);
    assert_eq!(
        runtime
            .poll_upload_session_at(&credited_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&regular_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}

#[tokio::test]
async fn unverified_ident_earns_no_credit_ratio_bonus() {
    // A4: eMule `GetScoreRatio` returns the neutral 1.0 for a peer that is not
    // IS_IDENTIFIED (crypto available), so an unverified peer must not jump ahead
    // of a plain waiter even when its user hash carries large persisted credits.
    let root = unique_test_dir("ed2k-upload-queue-unverified-credit");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xF1; 16]);
    let credited_user_hash = [0xF3; 16];
    // Same generous credit profile that wins a rank when verified.
    runtime
        .record_peer_credit_totals(credited_user_hash, 1_048_576, 20 * 1_048_576)
        .unwrap();

    let now = Instant::now();
    // Slot holder.
    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0xF1, 0x0A00_00F1), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // A plain waiter (no credits), enqueued first.
    let (regular_handle, regular_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0xF2, 0x0A00_00F2), &file_hash, now)
        .await;
    assert_eq!(regular_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    // The credited-but-UNVERIFIED peer, enqueued second.
    let (credited_handle, credited_status) = runtime
        .begin_upload_session_at(
            upload_peer_with_ident(3, credited_user_hash[0], 0x0A00_00F3, false),
            &file_hash,
            now,
        )
        .await;
    assert_eq!(
        credited_status,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );

    // After scoring, the unverified peer's neutral ratio leaves it behind the
    // plain waiter (contrast the verified case, which promotes it to rank 1).
    let scored_at = now + Duration::from_secs(1);
    assert_eq!(
        runtime
            .poll_upload_session_at(&credited_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&regular_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
}
