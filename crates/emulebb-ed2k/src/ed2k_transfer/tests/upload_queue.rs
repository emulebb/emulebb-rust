use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadSessionPhaseSnapshot, Ed2kUploadSessionStatus},
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

#[tokio::test]
async fn upload_queue_snapshot_exposes_active_and_waiting_sessions() {
    let root = unique_test_dir("ed2k-upload-queue-snapshot");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);

    let (_active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 0x0A00_0001), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (_waiting_handle, waiting_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 0x0A00_0002), &file_hash)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let snapshot = runtime.upload_queue_snapshot().await;

    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].phase, Ed2kUploadSessionPhaseSnapshot::Granted);
    assert_eq!(snapshot[0].queue_rank, None);
    assert_eq!(snapshot[1].phase, Ed2kUploadSessionPhaseSnapshot::Waiting);
    assert_eq!(snapshot[1].queue_rank, Some(1));
    assert_eq!(snapshot[1].file_hash, file_hash.to_string());
}

#[tokio::test]
async fn upload_queue_snapshot_tracks_session_uploaded_bytes() {
    let root = unique_test_dir("ed2k-upload-queue-session-bytes");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x34; 16]);

    let (handle, status) = runtime
        .begin_upload_session(upload_peer(1, 0x14, 0x0A00_0014), &file_hash)
        .await;
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);

    assert_eq!(
        runtime.note_upload_payload_sent(&handle, 65_536).await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime.note_upload_payload_sent(&handle, 32_768).await,
        Ed2kUploadSessionStatus::Granted
    );

    let snapshot = runtime.upload_queue_snapshot().await;
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].uploaded_bytes, 98_304);
}

#[tokio::test]
async fn upload_queue_grants_immediately_then_promotes_waiter() {
    let root = unique_test_dir("ed2k-upload-queue-promote");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x5A; 16]);

    let (first_handle, first_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 1), &file_hash)
        .await;
    assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

    let (second_handle, second_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 2), &file_hash)
        .await;
    assert_eq!(second_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    runtime.release_upload_session(&first_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&second_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
}

#[tokio::test]
async fn upload_queue_release_client_selects_waiter_or_active_slot() {
    let root = unique_test_dir("ed2k-upload-queue-release-client");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x6B; 16]);

    let (_active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 1), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 2), &file_hash)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    assert!(runtime.release_upload_client("10.0.0.2:4662", true).await);
    assert_eq!(
        runtime.poll_upload_session(&waiting_handle, true).await,
        Ed2kUploadSessionStatus::Stale
    );

    assert!(
        runtime
            .release_upload_client("11111111111111111111111111111111", false)
            .await
    );
    assert!(runtime.upload_queue_snapshot().await.is_empty());
}

#[tokio::test]
async fn upload_queue_reconnect_replaces_stale_connection() {
    let root = unique_test_dir("ed2k-upload-queue-reconnect");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xA5; 16]);
    let peer = upload_peer(9, 0x44, 9);

    let (first_handle, first_status) = runtime.begin_upload_session(peer.clone(), &file_hash).await;
    assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

    let (second_handle, second_status) = runtime.begin_upload_session(peer, &file_hash).await;
    assert_eq!(second_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(
        runtime.poll_upload_session(&first_handle, true).await,
        Ed2kUploadSessionStatus::Stale
    );
    runtime.release_upload_session(&first_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&second_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
}

#[tokio::test]
async fn upload_queue_same_peer_different_file_preserves_waiting_rank() {
    let root = unique_test_dir("ed2k-upload-queue-peer-file-switch");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let first_file_hash = Ed2kHash::from_bytes([0xA1; 16]);
    let second_file_hash = Ed2kHash::from_bytes([0xB2; 16]);
    let third_file_hash = Ed2kHash::from_bytes([0xC3; 16]);

    let (_first_handle, first_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 1), &first_file_hash)
        .await;
    assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);

    let waiting_peer = upload_peer(2, 0x22, 2);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session(waiting_peer.clone(), &first_file_hash)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let (trailing_handle, trailing_status) = runtime
        .begin_upload_session(upload_peer(3, 0x33, 3), &third_file_hash)
        .await;
    assert_eq!(
        trailing_status,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );

    let (replacement_handle, replacement_status) = runtime
        .begin_upload_session(waiting_peer, &second_file_hash)
        .await;
    assert_eq!(
        replacement_status,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime.poll_upload_session(&waiting_handle, true).await,
        Ed2kUploadSessionStatus::Stale
    );
    assert_eq!(
        runtime.poll_upload_session(&replacement_handle, true).await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime.poll_upload_session(&trailing_handle, true).await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}

#[tokio::test]
async fn upload_queue_friend_slot_ranks_before_older_waiter() {
    let root = unique_test_dir("ed2k-upload-queue-friend-slot");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xD4; 16]);

    let (active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 0x0A00_0001), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);

    let (regular_handle, regular_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 0x0A00_0002), &file_hash)
        .await;
    assert_eq!(regular_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let mut friend_peer = upload_peer(3, 0x33, 0x0A00_0003);
    friend_peer.friend_slot = true;
    let (friend_handle, friend_status) =
        runtime.begin_upload_session(friend_peer, &file_hash).await;
    assert_eq!(friend_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    assert_eq!(
        runtime.poll_upload_session(&regular_handle, true).await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );

    runtime.release_upload_session(&active_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&friend_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
}

#[tokio::test]
async fn upload_queue_connected_low_id_waiter_keeps_stock_rank() {
    let root = unique_test_dir("ed2k-upload-queue-low-id-rank");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xE5; 16]);

    let (active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x44, 0x0A00_0011), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);

    let (low_id_handle, low_id_status) = runtime
        .begin_upload_session(upload_peer(2, 0x55, 0x0000_1234), &file_hash)
        .await;
    assert_eq!(low_id_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let (high_id_handle, high_id_status) = runtime
        .begin_upload_session(upload_peer(3, 0x66, 0x0A00_0012), &file_hash)
        .await;
    assert_eq!(high_id_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });
    assert_eq!(
        runtime.poll_upload_session(&low_id_handle, true).await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );

    runtime.release_upload_session(&active_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&low_id_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime.poll_upload_session(&high_id_handle, true).await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
}

#[tokio::test]
async fn upload_queue_low_id_friend_slot_does_not_bypass_high_id_waiter() {
    let root = unique_test_dir("ed2k-upload-queue-low-id-friend-slot");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0xF6; 16]);

    let (active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x77, 0x0A00_0021), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);

    let (high_id_handle, high_id_status) = runtime
        .begin_upload_session(upload_peer(2, 0x88, 0x0A00_0022), &file_hash)
        .await;
    assert_eq!(high_id_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    let mut low_id_friend = upload_peer(3, 0x99, 0x0000_1234);
    low_id_friend.friend_slot = true;
    let (low_id_friend_handle, low_id_friend_status) = runtime
        .begin_upload_session(low_id_friend, &file_hash)
        .await;
    assert_eq!(
        low_id_friend_status,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );

    runtime.release_upload_session(&active_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&high_id_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime
            .poll_upload_session(&low_id_friend_handle, true)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
}
