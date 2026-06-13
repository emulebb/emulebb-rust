//! Standalone scoring and snapshot helpers for the ED2K upload queue.

use std::time::Instant;

use super::{
    DEFAULT_CREDIT_SCORE_PERMILLE, DEFAULT_FILE_PRIORITY_SCORE, Ed2kUploadPeerIdentity,
    Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionEntry, Ed2kUploadSessionPhase,
    Ed2kUploadSessionPhaseSnapshot, FRIEND_SLOT_SCORE_BONUS, HIGH_FILE_PRIORITY_SCORE,
    LOW_FILE_PRIORITY_SCORE, RELEASE_FILE_PRIORITY_SCORE, VERY_LOW_FILE_PRIORITY_SCORE,
};

pub(super) fn friend_slot_score(friend_slot: bool) -> i128 {
    if friend_slot {
        FRIEND_SLOT_SCORE_BONUS
    } else {
        0
    }
}

pub(crate) fn upload_priority_score(priority: &str) -> i128 {
    match priority {
        "verylow" => VERY_LOW_FILE_PRIORITY_SCORE,
        "low" => LOW_FILE_PRIORITY_SCORE,
        "high" => HIGH_FILE_PRIORITY_SCORE,
        "release" | "veryhigh" => RELEASE_FILE_PRIORITY_SCORE,
        "normal" | "auto" => DEFAULT_FILE_PRIORITY_SCORE,
        _ => DEFAULT_FILE_PRIORITY_SCORE,
    }
}

pub(crate) fn credit_score_permille(uploaded_bytes: u64, downloaded_bytes: u64) -> i128 {
    const CREDIT_THRESHOLD_BYTES: u64 = 1_048_576;
    const CREDIT_LINEAR_CAP_BYTES: u64 = 9_646_899;
    if downloaded_bytes < CREDIT_THRESHOLD_BYTES {
        return DEFAULT_CREDIT_SCORE_PERMILLE;
    }
    let uploaded = uploaded_bytes as f64;
    let downloaded = downloaded_bytes as f64;
    let ratio_by_transfer = if uploaded > 0.0 {
        downloaded * 2.0 / uploaded
    } else {
        10.0
    };
    let exponential_cap = (downloaded / CREDIT_THRESHOLD_BYTES as f64 + 2.0).sqrt();
    let linear_cap = if downloaded_bytes < CREDIT_LINEAR_CAP_BYTES {
        (downloaded - CREDIT_THRESHOLD_BYTES as f64) / 8_598_323.0 * 2.34 + 1.0
    } else {
        10.0
    };
    let ratio = ratio_by_transfer
        .min(exponential_cap)
        .min(linear_cap)
        .clamp(1.0, 10.0);
    (ratio * DEFAULT_CREDIT_SCORE_PERMILLE as f64).round() as i128
}

pub(super) fn is_low_id_client_id(client_id: u32) -> bool {
    client_id != 0 && client_id < 0x0100_0000
}

pub(super) fn phase_snapshot(phase: Ed2kUploadSessionPhase) -> Ed2kUploadSessionPhaseSnapshot {
    match phase {
        Ed2kUploadSessionPhase::Waiting => Ed2kUploadSessionPhaseSnapshot::Waiting,
        Ed2kUploadSessionPhase::Granted => Ed2kUploadSessionPhaseSnapshot::Granted,
        Ed2kUploadSessionPhase::Uploading => Ed2kUploadSessionPhaseSnapshot::Uploading,
    }
}

pub(super) fn upload_snapshot_sort_key(entry: &Ed2kUploadQueueSnapshotEntry) -> (u8, u16) {
    match entry.phase {
        Ed2kUploadSessionPhaseSnapshot::Uploading => (0, 0),
        Ed2kUploadSessionPhaseSnapshot::Granted => (1, 0),
        Ed2kUploadSessionPhaseSnapshot::Waiting => (2, entry.queue_rank.unwrap_or(u16::MAX)),
    }
}

pub(super) fn upload_speed_bytes_per_sec(session: &Ed2kUploadSessionEntry, now: Instant) -> u64 {
    let Some(started_at) = session.upload_started_at else {
        return 0;
    };
    if session.uploaded_bytes == 0 {
        return 0;
    }
    let elapsed_ms = now.saturating_duration_since(started_at).as_millis().max(1);
    ((u128::from(session.uploaded_bytes) * 1_000) / elapsed_ms)
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn upload_client_id_matches(peer: &Ed2kUploadPeerIdentity, client_id: &str) -> bool {
    peer.user_hash
        .is_some_and(|user_hash| hex::encode(user_hash) == client_id)
        || format!("{}:{}", peer.ip, peer.tcp_port) == client_id
}
