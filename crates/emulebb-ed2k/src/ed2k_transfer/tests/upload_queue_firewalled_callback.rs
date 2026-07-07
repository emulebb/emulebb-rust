//! C5: the firewalled-LowID callback admission guard (master
//! `CUploadQueue::AddClientToQueue`, `UploadQueue.cpp:1815-1825`). When we are
//! connected and firewalled and the waiting queue already holds more than 50
//! clients, a non-Kad, non-friend, different-server candidate is rejected.

use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{Ed2kTransferRuntime, Ed2kUploadFirewallContext, Ed2kUploadSessionStatus},
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

fn firewalled_context() -> Ed2kUploadFirewallContext {
    Ed2kUploadFirewallContext {
        we_are_connected: true,
        we_are_firewalled: true,
        peer_on_same_server: false,
    }
}

/// Fill the waiting queue past the master 50-waiter threshold (the active slot is
/// taken by a separate granted peer), so the firewalled-callback guard engages.
async fn fill_queue_past_threshold(
    runtime: &Ed2kTransferRuntime,
    file_hash: &Ed2kHash,
    now: Instant,
) {
    let (_active, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x01, 0x0A00_0001), file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // 51 waiters (> 50) from distinct IPs/hashes (so the per-IP cap never
    // fires, and no waiter shares the granted peer's 0x01 user hash — a shared
    // hash now resolves to the SAME client, oracle CUpDownClient::Compare).
    for index in 0..51u32 {
        let octet = (index % 200) as u8 + 50;
        let user_marker = (index % 200) as u8 + 2;
        let client_id = 0x0A01_0000 + index;
        let (_handle, status) = runtime
            .begin_upload_session_at(upload_peer(octet, user_marker, client_id), file_hash, now)
            .await;
        assert_eq!(
            status,
            Ed2kUploadSessionStatus::Waiting {
                rank: index as u16 + 1
            }
        );
    }
}

#[tokio::test]
async fn firewalled_callback_guard_rejects_a_remote_lowid_candidate() {
    let root = unique_test_dir("ed2k-upload-queue-fw-callback-reject");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // Large structural capacity so the queue can hold > 50 waiters.
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            waiting_capacity: 1024,
            waiting_timeout: Duration::from_secs(600),
            ..one_slot_config()
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x90; 16]);

    let now = Instant::now();
    fill_queue_past_threshold(&runtime, &file_hash, now).await;

    // A LowID candidate with no Kad port, not a friend, on a different (unknown)
    // server, while we are firewalled: the guard rejects it.
    let mut candidate = upload_peer(250, 0xFE, 0x0000_4444);
    candidate.kad_port = 0;
    candidate.firewall_context = firewalled_context();
    let (_handle, status) = runtime
        .begin_upload_session_at(candidate, &file_hash, now)
        .await;
    assert_eq!(status, Ed2kUploadSessionStatus::Rejected);
}

#[tokio::test]
async fn firewalled_callback_guard_admits_a_kad_reachable_candidate() {
    let root = unique_test_dir("ed2k-upload-queue-fw-callback-kad");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            waiting_capacity: 1024,
            waiting_timeout: Duration::from_secs(600),
            ..one_slot_config()
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x91; 16]);

    let now = Instant::now();
    fill_queue_past_threshold(&runtime, &file_hash, now).await;

    // Same firewalled state, but the candidate advertises a Kad port: all Kad
    // callbacks are allowed (master exemption), so it is admitted as a waiter.
    let mut candidate = upload_peer(250, 0xFE, 0x0000_4444);
    candidate.kad_port = 4672;
    candidate.firewall_context = firewalled_context();
    let (_handle, status) = runtime
        .begin_upload_session_at(candidate, &file_hash, now)
        .await;
    assert!(
        matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
        "Kad-reachable candidate must be admitted, got {status:?}"
    );
}

#[tokio::test]
async fn firewalled_callback_guard_does_not_fire_when_not_firewalled() {
    let root = unique_test_dir("ed2k-upload-queue-fw-callback-highid");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime
        .configure_upload_queue(crate::ed2k_transfer::Ed2kUploadQueueConfig {
            waiting_capacity: 1024,
            waiting_timeout: Duration::from_secs(600),
            ..one_slot_config()
        })
        .await;
    let file_hash = Ed2kHash::from_bytes([0x92; 16]);

    let now = Instant::now();
    fill_queue_past_threshold(&runtime, &file_hash, now).await;

    // We are NOT firewalled (HighID): the guard never engages even for a remote
    // non-Kad candidate.
    let mut candidate = upload_peer(250, 0xFE, 0x0000_4444);
    candidate.kad_port = 0;
    candidate.firewall_context = Ed2kUploadFirewallContext {
        we_are_connected: true,
        we_are_firewalled: false,
        peer_on_same_server: false,
    };
    let (_handle, status) = runtime
        .begin_upload_session_at(candidate, &file_hash, now)
        .await;
    assert!(
        matches!(status, Ed2kUploadSessionStatus::Waiting { .. }),
        "a non-firewalled host must not apply the callback guard, got {status:?}"
    );
}
