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
                session_transfer_percent: 0,
                session_time_limit_secs: 0,
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
            session_transfer_percent: 0,
            session_time_limit_secs: 0,
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
            session_transfer_percent: 0,
            session_time_limit: std::time::Duration::ZERO,
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
            session_transfer_percent: 0,
            session_time_limit: std::time::Duration::ZERO,
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
            session_transfer_percent: 0,
            session_time_limit: std::time::Duration::ZERO,
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
            session_transfer_percent: 0,
            session_time_limit_secs: 0,
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
            session_transfer_percent: 0,
            session_time_limit: std::time::Duration::ZERO,
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

#[tokio::test]
async fn upload_queue_waiter_survives_disconnect_with_wait_time_intact() {
    let root = unique_test_dir("ed2k-upload-queue-waiter-survives-disconnect");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x7C; 16]);
    // Timeline in the past so the synthetic instants stay comparable to the
    // real `Instant::now()` used by snapshot-style entry points.
    let t0 = std::time::Instant::now() - std::time::Duration::from_secs(20);

    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x11, 0x0A00_0001), &file_hash, t0)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // Older waiter: queued first, so its accumulated wait outranks the later one.
    let (older_handle, older_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x22, 0x0A00_0002), &file_hash, t0)
        .await;
    assert_eq!(older_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (younger_handle, younger_status) = runtime
        .begin_upload_session_at(
            upload_peer(3, 0x33, 0x0A00_0003),
            &file_hash,
            t0 + std::time::Duration::from_secs(5),
        )
        .await;
    assert_eq!(younger_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    // The older waiter's connection drops: its queue entry must survive with
    // its wait-start time (master keeps US_ONUPLOADQUEUE clients on disconnect,
    // BaseClient.cpp:1229) instead of being erased with the connection.
    runtime.release_upload_session(&older_handle).await;
    assert_eq!(
        runtime.upload_queue_snapshot().await.len(),
        3,
        "the disconnected waiter must keep its queue entry"
    );
    // Wait-start intact: the disconnected older waiter still outranks the
    // connected younger one (rank derives from the waiting-time score).
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &younger_handle,
                false,
                t0 + std::time::Duration::from_secs(10)
            )
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 },
        "a disconnected waiter with more accumulated wait must keep rank 1"
    );
}

#[tokio::test]
async fn upload_queue_reask_reattaches_disconnected_waiter_without_wait_reset() {
    let root = unique_test_dir("ed2k-upload-queue-reask-reattach");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x7D; 16]);
    let t0 = std::time::Instant::now() - std::time::Duration::from_secs(60);

    let (_active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x11, 0x0A00_0001), &file_hash, t0)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (older_handle, older_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x22, 0x0A00_0002), &file_hash, t0)
        .await;
    assert_eq!(older_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });
    let (_younger_handle, younger_status) = runtime
        .begin_upload_session_at(
            upload_peer(3, 0x33, 0x0A00_0003),
            &file_hash,
            t0 + std::time::Duration::from_secs(10),
        )
        .await;
    assert_eq!(younger_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    // The older waiter disconnects, then re-asks on a NEW connection with a new
    // server-assigned client id (same user hash) — the oracle resolves the same
    // client by user hash (CUpDownClient::Compare) and the re-ask lands on the
    // persisted entry WITHOUT resetting its wait time (UploadQueue.cpp:1865-1869).
    runtime.release_upload_session(&older_handle).await;
    let mut returning = upload_peer(2, 0x22, 0x0A00_0002);
    returning.client_id = Some(0x0B00_0099);
    let (reattached_handle, reattached_status) = runtime
        .begin_upload_session_at(
            returning,
            &file_hash,
            t0 + std::time::Duration::from_secs(30),
        )
        .await;
    assert_eq!(
        reattached_status,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "the re-ask must re-attach with the original wait time, not restart at the tail"
    );
    // The stale pre-disconnect handle no longer owns the session.
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &older_handle,
                false,
                t0 + std::time::Duration::from_secs(31)
            )
            .await,
        Ed2kUploadSessionStatus::Stale
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(
                &reattached_handle,
                false,
                t0 + std::time::Duration::from_secs(31)
            )
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 }
    );
}

#[tokio::test]
async fn upload_queue_slot_grant_to_disconnected_waiter_queues_outbound_promotion() {
    let root = unique_test_dir("ed2k-upload-queue-disconnected-promotion");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x7E; 16]);
    let t0 = std::time::Instant::now() - std::time::Duration::from_secs(20);

    let (active_handle, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x11, 0x0A00_0001), &file_hash, t0)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x22, 0x0A00_0002), &file_hash, t0)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // The waiter disconnects, then the active slot frees: the disconnected
    // waiter is promoted and handed to the outbound promote-connect path
    // (master AddUpNextClient US_CONNECTING connect-out, UploadQueue.cpp:327-361).
    runtime.release_upload_session(&waiting_handle).await;
    runtime.release_upload_session(&active_handle).await;

    let grants = runtime.take_pending_upload_promotions().await;
    assert_eq!(
        grants.len(),
        1,
        "one outbound promote-connect grant expected"
    );
    let grant = &grants[0];
    assert_eq!(grant.peer.user_hash, Some([0x22; 16]));
    assert_eq!(grant.file_hash, file_hash.to_string());
    assert_eq!(
        runtime.poll_upload_session(&grant.handle, false).await,
        Ed2kUploadSessionStatus::Granted,
        "the grant handle must own the promoted session"
    );
    // Draining is one-shot until another disconnected promotion happens.
    assert!(runtime.take_pending_upload_promotions().await.is_empty());

    // A failed outbound connect drops the grant entirely (master deletes the
    // client on a failed TryToConnect), freeing the slot for the next waiter.
    runtime.release_upload_session(&grant.handle).await;
    assert!(
        runtime.upload_queue_snapshot().await.is_empty(),
        "a dropped grant must not linger in the queue"
    );
}

#[tokio::test]
async fn upload_queue_connected_waiter_promotion_needs_no_outbound_connect() {
    let root = unique_test_dir("ed2k-upload-queue-connected-promotion");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x7F; 16]);

    let (active_handle, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x11, 0x0A00_0001), &file_hash)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (waiting_handle, waiting_status) = runtime
        .begin_upload_session(upload_peer(2, 0x22, 0x0A00_0002), &file_hash)
        .await;
    assert_eq!(waiting_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // The waiter still has its live connection when the slot frees: its own
    // session loop observes the grant and sends OP_ACCEPTUPLOADREQ inline
    // (master AddUpNextClient connected branch, UploadQueue.cpp:355-361), so
    // no outbound promote-connect is queued.
    runtime.release_upload_session(&active_handle).await;
    assert_eq!(
        runtime.poll_upload_session(&waiting_handle, true).await,
        Ed2kUploadSessionStatus::Granted
    );
    assert!(runtime.take_pending_upload_promotions().await.is_empty());
}

/// REG-3: a waiter whose requested file is no longer shared is purged on the
/// next maintenance tick (master `FindBestClientInQueue` walk, UploadQueue.cpp:223
/// `!GetFileByID(client->GetUploadFileID())`). A waiter for a still-shared file
/// and the active slot holder survive the purge.
#[tokio::test]
async fn waiter_for_an_unshared_file_is_purged_on_maintenance() {
    use crate::ed2k_transfer::Ed2kSharedEntry;

    let root = unique_test_dir("ed2k-upload-queue-unshared-purge");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;

    let shared_file = Ed2kHash::from_bytes([0xC1; 16]);
    let unshared_file = Ed2kHash::from_bytes([0xC2; 16]);

    // The active slot holder and one waiter both requested the shared file.
    let (_active, active_status) = runtime
        .begin_upload_session(upload_peer(1, 0x31, 0x0A00_0031), &shared_file)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    let (_shared_waiter, shared_waiter_status) = runtime
        .begin_upload_session(upload_peer(2, 0x32, 0x0A00_0032), &shared_file)
        .await;
    assert_eq!(shared_waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 1 });

    // A second waiter requested a file we do not (or no longer) serve.
    let (_unshared_waiter, unshared_waiter_status) = runtime
        .begin_upload_session(upload_peer(3, 0x33, 0x0A00_0033), &unshared_file)
        .await;
    assert_eq!(unshared_waiter_status, Ed2kUploadSessionStatus::Waiting { rank: 2 });

    // Only the shared file is servable in the catalog.
    runtime.shared_catalog().write().await.push(Ed2kSharedEntry {
        file_hash: shared_file.to_string(),
        canonical_name: "shared.bin".to_string(),
        file_size: 1_000_000,
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
        publish: Default::default(),
    });

    assert_eq!(runtime.purge_unshared_upload_waiters().await, 1);

    // The unshared waiter is gone; the shared waiter and the active slot remain.
    let snapshot = runtime.upload_queue_snapshot().await;
    assert_eq!(snapshot.len(), 2, "only the unshared waiter must be purged");
    assert!(
        snapshot
            .iter()
            .all(|entry| entry.file_hash.eq_ignore_ascii_case(&shared_file.to_string())),
        "no entry for the unshared file may remain"
    );
}
