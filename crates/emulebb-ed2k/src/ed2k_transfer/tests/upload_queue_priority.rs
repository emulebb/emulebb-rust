use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadSessionStatus, new_transfer_job},
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

#[tokio::test]
async fn upload_queue_scores_waiters_with_persisted_file_priority() {
    let root = unique_test_dir("ed2k-upload-queue-file-priority");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let active_file = Ed2kHash::from_bytes([0xA7; 16]);
    let normal_file = Ed2kHash::from_bytes([0xB8; 16]);
    let high_file = Ed2kHash::from_bytes([0xC9; 16]);

    runtime
        .ensure_job(&new_transfer_job(
            normal_file,
            "Normal.Priority.bin".to_string(),
            1024,
        ))
        .await
        .unwrap();
    runtime
        .ensure_job(&new_transfer_job(
            high_file,
            "High.Priority.bin".to_string(),
            1024,
        ))
        .await
        .unwrap();
    runtime
        .update_shared_file_metadata(&high_file.to_string(), Some(("high", false)), None)
        .await
        .unwrap();

    let now = Instant::now();
    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0xA1, 0x0A00_0031), &active_file, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // Both registered files have an all-time upload ratio of 0 (< the 0.5
    // threshold), so the master low-ratio bonus applies to each. The additive
    // bonus is scaled by file priority, so it exposes the priority ordering even
    // at zero waiting time: the high-priority waiter outranks the normal one on
    // arrival (master `GetScoreBreakdown` adds the bonus after the priority
    // multiply).
    let (normal_handle, normal_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0xB2, 0x0A00_0032), &normal_file, now)
        .await;
    assert_eq!(normal_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (high_handle, high_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0xC3, 0x0A00_0033), &high_file, now)
        .await;
    assert_eq!(high_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let scored_at = now + Duration::from_secs(1);
    assert_eq!(
        runtime
            .poll_upload_session_at(&high_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&normal_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}

#[tokio::test]
async fn upload_queue_refreshes_waiter_score_after_priority_change() {
    let root = unique_test_dir("ed2k-upload-queue-priority-refresh");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let active_file = Ed2kHash::from_bytes([0xD1; 16]);
    let older_file = Ed2kHash::from_bytes([0xD2; 16]);
    let boosted_file = Ed2kHash::from_bytes([0xD3; 16]);

    for (file_hash, name) in [
        (older_file, "Older.Priority.bin"),
        (boosted_file, "Boosted.Priority.bin"),
    ] {
        runtime
            .ensure_job(&new_transfer_job(file_hash, name.to_string(), 1024))
            .await
            .unwrap();
    }

    let now = Instant::now();
    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0xD1, 0x0A00_0041), &active_file, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (older_handle, older_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0xD2, 0x0A00_0042), &older_file, now)
        .await;
    assert_eq!(older_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (boosted_handle, boosted_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0xD3, 0x0A00_0043), &boosted_file, now)
        .await;
    assert_eq!(boosted_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    runtime
        .update_shared_file_metadata(&boosted_file.to_string(), Some(("release", false)), None)
        .await
        .unwrap();

    let scored_at = now + Duration::from_secs(1);
    assert_eq!(
        runtime
            .poll_upload_session_at(&boosted_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&older_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}

#[tokio::test]
async fn upload_queue_low_id_waiter_scores_below_high_id_peer() {
    let root = unique_test_dir("ed2k-upload-queue-low-id-divisor");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xE1; 16]);

    let now = Instant::now();
    // Take the single slot.
    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0xE0, 0x0A00_0050), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);

    // A LowID waiter (client_id < 0x01000000) and a HighID waiter queue together
    // for the same file (identical priority + neutral credit), so the only
    // discriminator is the LowID score divisor.
    let (low_id_handle, low_id_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0xE2, 0x0000_2222), &file_hash, now)
        .await;
    assert_eq!(low_id_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (high_id_handle, high_id_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0xE3, 0x0A00_0053), &file_hash, now)
        .await;
    assert_eq!(high_id_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    // After accumulating waiting time the HighID peer's full score outranks the
    // LowID peer's halved score, so HighID becomes rank 1.
    let scored_at = now + Duration::from_secs(10);
    assert_eq!(
        runtime
            .poll_upload_session_at(&high_id_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&low_id_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}
