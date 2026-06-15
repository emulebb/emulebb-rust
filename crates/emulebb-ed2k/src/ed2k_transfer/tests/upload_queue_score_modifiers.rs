//! C6: end-to-end coverage of the upload-score modifiers (master
//! `CUpDownClient::GetScoreBreakdown` + `BuildUploadScoreBreakdown`) driven
//! through the live transfer runtime: bad-guy / GPL-evildoer / banned zeroing,
//! the old-client penalty, and the all-time-upload-ratio low-ratio bonus.

use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_transfer::{
        Ed2kTransferRuntime, Ed2kUploadPeerIdentity, Ed2kUploadSessionStatus, new_transfer_job,
    },
    paths::unique_test_dir,
};

use super::upload_queue_support::{one_slot_config, upload_peer};

/// A waiter whose secure-ident verification FAILED (eMule `IS_IDBADGUY`).
fn bad_guy_peer(octet: u8, user_marker: u8, client_id: u32) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        ident_bad_guy: true,
        ..upload_peer(octet, user_marker, client_id)
    }
}

/// A waiter flagged as a known GPL-breaker mod (eMule `m_bGPLEvildoer`).
fn gpl_peer(octet: u8, user_marker: u8, client_id: u32) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        gpl_evildoer: true,
        ..upload_peer(octet, user_marker, client_id)
    }
}

/// A waiter on the local ban list (eMule `IsBanned()`).
fn banned_peer(octet: u8, user_marker: u8, client_id: u32) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        banned: true,
        ..upload_peer(octet, user_marker, client_id)
    }
}

/// An old eMule client (`m_byEmuleVersion <= 0x19`) that earns the x0.5 penalty.
fn old_client_peer(octet: u8, user_marker: u8, client_id: u32) -> Ed2kUploadPeerIdentity {
    Ed2kUploadPeerIdentity {
        emule_version: 0x10,
        is_emule_client: true,
        ..upload_peer(octet, user_marker, client_id)
    }
}

/// Assert that a flagged-zero waiter (bad-guy / GPL / banned) always ranks below
/// a plain waiter that registered AFTER it, since its score is forced to 0.
async fn flagged_waiter_ranks_below_plain(
    label: &str,
    flagged: Ed2kUploadPeerIdentity,
) {
    let root = unique_test_dir(&format!("ed2k-upload-queue-{label}"));
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x5A; 16]);

    let now = Instant::now();
    // Slot holder.
    let (_active, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x01, 0x0A00_0001), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // The flagged (score-zeroed) waiter enqueues FIRST.
    let (flagged_handle, _flagged_status) = runtime
        .begin_upload_session_at(flagged, &file_hash, now)
        .await;
    // A plain waiter enqueues second; despite accumulating less waiting time it
    // outranks the zeroed waiter.
    let (plain_handle, _plain_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0x03, 0x0A00_0003), &file_hash, now)
        .await;

    let scored_at = now + Duration::from_secs(5);
    assert_eq!(
        runtime
            .poll_upload_session_at(&plain_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "{label}: plain waiter must outrank the zeroed waiter"
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&flagged_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 },
        "{label}: zeroed waiter must rank last"
    );
}

#[tokio::test]
async fn ident_bad_guy_score_is_zeroed() {
    flagged_waiter_ranks_below_plain("bad-guy", bad_guy_peer(2, 0x02, 0x0A00_0002)).await;
}

#[tokio::test]
async fn gpl_evildoer_score_is_zeroed() {
    flagged_waiter_ranks_below_plain("gpl", gpl_peer(2, 0x02, 0x0A00_0002)).await;
}

#[tokio::test]
async fn banned_score_is_zeroed() {
    flagged_waiter_ranks_below_plain("banned", banned_peer(2, 0x02, 0x0A00_0002)).await;
}

#[tokio::test]
async fn old_client_penalty_drops_score_below_modern_peer() {
    // An old eMule client (x0.5 penalty) ranks below a modern peer with the same
    // priority/credit once both have accrued the same waiting time.
    let root = unique_test_dir("ed2k-upload-queue-old-client");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let file_hash = Ed2kHash::from_bytes([0x6B; 16]);

    let now = Instant::now();
    let (_active, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x01, 0x0A00_0061), &file_hash, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // The old client enqueues FIRST (so registration order would favour it on a
    // tie), the modern peer second.
    let (old_handle, _old_status) = runtime
        .begin_upload_session_at(old_client_peer(2, 0x02, 0x0A00_0062), &file_hash, now)
        .await;
    let (modern_handle, _modern_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0x03, 0x0A00_0063), &file_hash, now)
        .await;

    let scored_at = now + Duration::from_secs(10);
    assert_eq!(
        runtime
            .poll_upload_session_at(&modern_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "modern peer outranks the x0.5-penalised old client"
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&old_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}

#[tokio::test]
async fn low_ratio_bonus_promotes_an_underserved_file() {
    // Two files, identical waiters: the file we have barely uploaded (all-time
    // ratio below the 0.5 threshold) earns the additive low-ratio bonus, so its
    // waiter outranks the waiter for a well-served file (ratio above threshold).
    let root = unique_test_dir("ed2k-upload-queue-low-ratio-bonus");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.configure_upload_queue(one_slot_config()).await;
    let underserved = Ed2kHash::from_bytes([0x71; 16]);
    let well_served = Ed2kHash::from_bytes([0x72; 16]);
    let slot_file = Ed2kHash::from_bytes([0x73; 16]);

    for (hash, name) in [
        (underserved, "Underserved.bin"),
        (well_served, "WellServed.bin"),
        (slot_file, "Slot.bin"),
    ] {
        runtime
            .ensure_job(&new_transfer_job(hash, name.to_string(), 1_000))
            .await
            .unwrap();
    }
    // The well-served file has uploaded 2x its size (ratio 2.0 >> 0.5): no bonus.
    runtime
        .add_file_all_time_uploaded(&well_served, 2_000)
        .unwrap();
    // The underserved file has uploaded only 0.1x its size (ratio 0.1 < 0.5):
    // the low-ratio bonus applies.
    runtime
        .add_file_all_time_uploaded(&underserved, 100)
        .unwrap();

    let now = Instant::now();
    let (_active, active_status) = runtime
        .begin_upload_session_at(upload_peer(1, 0x01, 0x0A00_0071), &slot_file, now)
        .await;
    assert_eq!(active_status, Ed2kUploadSessionStatus::Granted);
    // The well-served file's waiter enqueues first.
    let (well_handle, _well_status) = runtime
        .begin_upload_session_at(upload_peer(2, 0x02, 0x0A00_0072), &well_served, now)
        .await;
    // The underserved file's waiter enqueues second.
    let (under_handle, _under_status) = runtime
        .begin_upload_session_at(upload_peer(3, 0x03, 0x0A00_0073), &underserved, now)
        .await;

    let scored_at = now + Duration::from_secs(1);
    assert_eq!(
        runtime
            .poll_upload_session_at(&under_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 1 },
        "underserved file's waiter wins the low-ratio bonus"
    );
    assert_eq!(
        runtime
            .poll_upload_session_at(&well_handle, false, scored_at)
            .await,
        Ed2kUploadSessionStatus::Waiting { rank: 2 }
    );
}
