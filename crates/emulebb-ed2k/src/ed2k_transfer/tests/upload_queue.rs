use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataStore;

use crate::{
    config::{Ed2kConfig, Ed2kUploadQueuePolicyConfig},
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadRangeAdmission, Ed2kUploadSessionPhaseSnapshot,
        Ed2kUploadSessionStatus,
    },
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

#[tokio::test]
async fn upload_queue_uses_configured_active_slot_limit_on_startup() {
    let root = unique_test_dir("ed2k-upload-queue-configured-slots");
    let metadata = MetadataStore::open(root.join("metadata.sqlite")).unwrap();
    let runtime = Ed2kTransferRuntime::load_or_create_with_metadata_and_config(
        &root,
        metadata,
        &Ed2kConfig {
            upload_queue: Ed2kUploadQueuePolicyConfig {
                active_slots: 2,
                elastic_percent: 0,
                upload_limit_bytes_per_sec: 0,
                elastic_underfill_bytes_per_sec: 0,
                elastic_underfill_secs: 10,
                waiting_capacity: 8,
                waiting_timeout_secs: 180,
                granted_timeout_secs: 30,
                upload_timeout_secs: 90,
            },
            ..Ed2kConfig::default()
        },
    )
    .unwrap();
    let file_hash = Ed2kHash::from_bytes([0x31; 16]);

    let (_first_handle, first_status) = runtime
        .begin_upload_session(upload_peer(1, 0x21, 0x0A00_0021), &file_hash)
        .await;
    let (_second_handle, second_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 0x0A00_0022), &file_hash)
        .await;
    let (_third_handle, third_status) = runtime
        .begin_upload_session(upload_peer(3, 0x23, 0x0A00_0023), &file_hash)
        .await;

    assert_eq!(first_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(second_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(third_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
}

#[tokio::test]
async fn upload_queue_reconfigures_active_slot_limit_live() {
    let root = unique_test_dir("ed2k-upload-queue-live-slots");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x32; 16]);

    let (_active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x24, 0x0A00_0024), &file_hash)
        .await;
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session(upload_peer(2, 0x25, 0x0A00_0025), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    runtime
        .apply_upload_queue_policy(&Ed2kUploadQueuePolicyConfig {
            active_slots: 2,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill_secs: 10,
            waiting_capacity: 8,
            waiting_timeout_secs: 180,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
        })
        .await;

    assert_eq!(
        runtime.poll_upload_session(&waiting_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
}

#[tokio::test]
async fn upload_queue_opens_elastic_slot_after_sustained_underfill() {
    let root = unique_test_dir("ed2k-upload-queue-elastic-underfill");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            active_slots: 1,
            elastic_percent: 100,
            upload_limit_bytes_per_sec: 128 * 1024,
            elastic_underfill_bytes_per_sec: 32 * 1024,
            elastic_underfill: std::time::Duration::from_secs(10),
            waiting_capacity: 8,
            soft_queue_size: 10_000,
            waiting_timeout: std::time::Duration::from_secs(60),
            granted_timeout: std::time::Duration::from_secs(60),
            upload_timeout: std::time::Duration::from_secs(60),
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x41; 16]);
    let now = std::time::Instant::now();

    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x41, 0x0A00_0041), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(
            upload_peer(2, 0x42, 0x0A00_0042),
            &file_hash,
            now + std::time::Duration::from_secs(1),
        )
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    assert_eq!(
        runtime
            .poll_upload_session_at(
                &waiting_handle,
                true,
                now + std::time::Duration::from_secs(11)
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    let capacity = runtime.upload_queue_capacity_snapshot().await;
    assert_eq!(capacity.base_slots, 1);
    assert_eq!(capacity.elastic_slots, 1);
}

#[tokio::test]
async fn upload_queue_keeps_elastic_slot_closed_when_upload_budget_is_full() {
    let root = unique_test_dir("ed2k-upload-queue-elastic-full-rate");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            active_slots: 1,
            elastic_percent: 100,
            upload_limit_bytes_per_sec: 128 * 1024,
            elastic_underfill_bytes_per_sec: 32 * 1024,
            elastic_underfill: std::time::Duration::from_secs(10),
            waiting_capacity: 8,
            soft_queue_size: 10_000,
            waiting_timeout: std::time::Duration::from_secs(60),
            granted_timeout: std::time::Duration::from_secs(60),
            upload_timeout: std::time::Duration::from_secs(60),
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x42; 16]);
    let now = std::time::Instant::now();

    let (active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x51, 0x0A00_0051), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(
        runtime
            .note_upload_payload_sent_at(
                &active_handle,
                256 * 1024,
                now + std::time::Duration::from_secs(1),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(
            upload_peer(2, 0x52, 0x0A00_0052),
            &file_hash,
            now + std::time::Duration::from_secs(2),
        )
        .await;

    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &waiting_handle,
                true,
                now + std::time::Duration::from_secs(12),
            )
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
}

#[tokio::test]
async fn upload_queue_reserves_global_payload_budget() {
    let root = unique_test_dir("ed2k-upload-queue-throttle-budget");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            active_slots: 1,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 1024,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill: std::time::Duration::from_secs(10),
            waiting_capacity: 8,
            soft_queue_size: 10_000,
            waiting_timeout: std::time::Duration::from_secs(60),
            granted_timeout: std::time::Duration::from_secs(60),
            upload_timeout: std::time::Duration::from_secs(60),
        })
        .await;
    let now = std::time::Instant::now();

    let first = runtime.reserve_upload_payload_budget_at(1024, now).await;
    let second = runtime.reserve_upload_payload_budget_at(1024, now).await;

    assert_eq!(first.delay, std::time::Duration::ZERO);
    assert_eq!(second.delay, std::time::Duration::from_secs(1));
}

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
    let now = std::time::Instant::now();

    let (handle, status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x14, 0x0A00_0014), &file_hash, now)
        .await;
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);

    assert_eq!(
        runtime
            .note_upload_payload_sent_at(&handle, 65_536, now + std::time::Duration::from_secs(1))
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime
            .note_upload_payload_sent_at(&handle, 32_768, now + std::time::Duration::from_secs(3))
            .await,
        Ed2kUploadSessionStatus::Granted
    );

    let snapshot = runtime
        .upload_queue
        .lock()
        .await
        .snapshot(now + std::time::Duration::from_secs(3));
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].uploaded_bytes, 98_304);
    assert_eq!(snapshot[0].upload_speed_bytes_per_sec, 49_152);
}

#[tokio::test]
async fn upload_queue_capacity_snapshot_classifies_active_sessions() {
    let root = unique_test_dir("ed2k-upload-queue-capacity-composition");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .apply_upload_queue_policy(&Ed2kUploadQueuePolicyConfig {
            active_slots: 2,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 0,
            elastic_underfill_bytes_per_sec: 0,
            elastic_underfill_secs: 10,
            waiting_capacity: 8,
            waiting_timeout_secs: 180,
            granted_timeout_secs: 30,
            upload_timeout_secs: 90,
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x3A; 16]);
    let now = std::time::Instant::now();

    let (_granted_handle, granted_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x15, 0x0A00_0015), &file_hash, now)
        .await;
    let (uploading_handle, uploading_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x16, 0x0A00_0016), &file_hash, now)
        .await;
    let (_waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0x17, 0x0A00_0017), &file_hash, now)
        .await;
    assert_eq!(granted_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(uploading_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    assert_eq!(
        runtime.note_upload_request_parts(&uploading_handle).await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime
            .note_upload_payload_sent_at(
                &uploading_handle,
                32_768,
                now + std::time::Duration::from_secs(1),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );

    let capacity = runtime.upload_queue_capacity_snapshot().await;
    assert_eq!(capacity.active_sessions, 2);
    assert_eq!(capacity.waiting_sessions, 1);
    assert_eq!(capacity.active_granted_sessions, 1);
    assert_eq!(capacity.active_uploading_sessions, 1);
    assert_eq!(capacity.active_never_uploaded_sessions, 1);
    assert_eq!(capacity.active_productive_sessions, 1);
}

#[tokio::test]
async fn upload_queue_detects_duplicate_completed_ranges_per_slot() {
    let root = unique_test_dir("ed2k-upload-queue-duplicate-range");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x35; 16]);
    let now = std::time::Instant::now();
    let peer = upload_peer(1, 0x35, 0x0A00_0035);

    let (handle, status) = runtime
        .begin_upload_session_at(peer.clone(), &file_hash, now)
        .await;
    assert_eq!(status, Ed2kUploadSessionStatus::Granted);

    assert_eq!(
        runtime
            .note_upload_range_request_at(&handle, 0, 1024, now + std::time::Duration::from_secs(1))
            .await,
        (
            Ed2kUploadSessionStatus::Granted,
            Ed2kUploadRangeAdmission::Accepted
        )
    );
    assert_eq!(
        runtime
            .note_upload_range_served_at(&handle, 0, 1024, now + std::time::Duration::from_secs(2))
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime
            .note_upload_range_request_at(&handle, 0, 1024, now + std::time::Duration::from_secs(3))
            .await,
        (
            Ed2kUploadSessionStatus::Granted,
            Ed2kUploadRangeAdmission::DuplicateDone
        )
    );

    let next_file_hash = Ed2kHash::from_bytes([0x36; 16]);
    let (next_handle, next_status) = runtime
        .begin_upload_session_at(
            peer,
            &next_file_hash,
            now + std::time::Duration::from_secs(4),
        )
        .await;
    assert_eq!(next_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(
        runtime
            .note_upload_range_request_at(
                &next_handle,
                0,
                1024,
                now + std::time::Duration::from_secs(5)
            )
            .await,
        (
            Ed2kUploadSessionStatus::Granted,
            Ed2kUploadRangeAdmission::Accepted
        )
    );
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
async fn upload_queue_recycles_granted_slot_without_real_upload_activity() {
    let root = unique_test_dir("ed2k-upload-queue-idle-granted-recycle");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            // Sustained underfill pressure so the no-request idle slot is recycled
            // (active slots are now reaped only under underfill, matching MFC, not on
            // a plain granted-timeout timer).
            upload_limit_bytes_per_sec: 100 * 1024,
            elastic_underfill_bytes_per_sec: 50 * 1024,
            elastic_underfill: std::time::Duration::from_secs(2),
            granted_timeout: std::time::Duration::from_secs(2),
            upload_timeout: std::time::Duration::from_secs(60),
            ..one_slot_config()
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x5B; 16]);
    let now = std::time::Instant::now();

    let (active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x12, 0x0A00_0012), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x13, 0x0A00_0013), &file_hash, now)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    assert_eq!(
        runtime
            .poll_upload_session_at(
                &active_handle,
                false,
                now + std::time::Duration::from_secs(1),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    // The idle granted slot is reclaimed, but the peer is DEMOTED to the back of
    // the waiting queue (mirroring MFC AddClientToQueue) rather than dropped, so it
    // reports Waiting (not Stale); the freed slot promotes the existing waiter.
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &active_handle,
                false,
                now + std::time::Duration::from_secs(3),
            )
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &waiting_handle,
                false,
                now + std::time::Duration::from_secs(3),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
}

#[tokio::test]
async fn upload_queue_recycles_slow_active_slot_during_sustained_underfill() {
    let root = unique_test_dir("ed2k-upload-queue-slow-active-recycle");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            active_slots: 1,
            elastic_percent: 0,
            upload_limit_bytes_per_sec: 100 * 1024,
            elastic_underfill_bytes_per_sec: 50 * 1024,
            elastic_underfill: std::time::Duration::from_secs(2),
            waiting_capacity: 8,
            soft_queue_size: 10_000,
            waiting_timeout: std::time::Duration::from_secs(60),
            granted_timeout: std::time::Duration::from_secs(2),
            upload_timeout: std::time::Duration::from_secs(5),
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x5C; 16]);
    let now = std::time::Instant::now();

    let (active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x14, 0x0A00_0014), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    assert_eq!(
        runtime
            .upload_queue
            .lock()
            .await
            .note_request_parts(&active_handle, now + std::time::Duration::from_secs(1)),
        Ed2kUploadSessionStatus::Granted
    );
    assert_eq!(
        runtime
            .note_upload_payload_sent_at(
                &active_handle,
                1024,
                now + std::time::Duration::from_secs(1),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(
            upload_peer(2, 0x15, 0x0A00_0015),
            &file_hash,
            now + std::time::Duration::from_secs(2),
        )
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    assert_eq!(
        runtime
            .note_upload_payload_sent_at(
                &active_handle,
                1024,
                now + std::time::Duration::from_secs(5),
            )
            .await,
        Ed2kUploadSessionStatus::Granted
    );
    // Slow active slot reclaimed during underfill: the peer is demoted to the
    // waiting queue (Waiting), not dropped (Stale), and the waiter is promoted.
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &active_handle,
                false,
                now + std::time::Duration::from_secs(7),
            )
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &waiting_handle,
                false,
                now + std::time::Duration::from_secs(7),
            )
            .await,
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

#[tokio::test]
async fn upload_queue_rejects_fourth_waiter_from_same_ip() {
    use super::upload_queue_support::same_ip_upload_peer;
    let root = unique_test_dir("ed2k-upload-queue-per-ip-cap");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x33; 16]);

    // One peer takes the single slot; subsequent same-IP peers queue as waiters.
    let (_slot_handle, slot_status) = runtime
        .begin_upload_session(upload_peer(1, 0x60, 0x0A00_0060), &file_hash)
        .await;
    assert_eq!(slot_status, Ed2kUploadSessionStatus::Granted);

    // Three waiters from the shared IP are admitted (master cSameIP < 3).
    for port_marker in 0..3u8 {
        let (_handle, status) = runtime
            .begin_upload_session(same_ip_upload_peer(port_marker), &file_hash)
            .await;
        assert!(
            matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
            "waiter {port_marker} should be admitted, got {status:?}"
        );
    }

    // The fourth same-IP waiter is refused (cSameIP >= 3).
    let (_handle, status) = runtime
        .begin_upload_session(same_ip_upload_peer(3), &file_hash)
        .await;
    assert_eq!(status, Ed2kUploadSessionStatus::Rejected);
}

#[tokio::test]
async fn upload_queue_friend_slot_bypasses_soft_limit_gate() {
    let root = unique_test_dir("ed2k-upload-queue-soft-limit-friend");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // soft_queue_size 0 puts every would-be waiter past the soft limit. With an
    // empty queue the average is 0, so a default-priority candidate's positive
    // combined score is admitted; once waiters exist the friend-slot bypass is
    // the deterministic admit path past the soft gate (the score-comparison
    // rejection itself is covered by the admission unit tests).
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            active_slots: 1,
            soft_queue_size: 0,
            ..one_slot_config()
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x34; 16]);

    let (_slot_handle, slot_status) = runtime
        .begin_upload_session(upload_peer(1, 0x70, 0x0A00_0070), &file_hash)
        .await;
    assert_eq!(slot_status, Ed2kUploadSessionStatus::Granted);

    // First waiter: positive score beats the empty-queue average of 0.
    let (_first_waiter, first_status) = runtime
        .begin_upload_session(upload_peer(2, 0x71, 0x0A00_0071), &file_hash)
        .await;
    assert!(matches!(
        first_status,
        Ed2kUploadSessionStatus::Waiting { .. }
    ));

    // A friend-slot waiter is admitted past the soft limit regardless of score.
    let mut friend = upload_peer(3, 0x72, 0x0A00_0072);
    friend.friend_slot = true;
    let (_friend_handle, friend_status) = runtime.begin_upload_session(friend, &file_hash).await;
    assert!(matches!(
        friend_status,
        Ed2kUploadSessionStatus::Waiting { .. }
    ));
}
