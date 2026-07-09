//! Standalone scoring and snapshot helpers for the ED2K upload queue.

use std::time::Instant;

use super::{
    DEFAULT_CREDIT_SCORE_PERMILLE, DEFAULT_FILE_PRIORITY_SCORE, Ed2kUploadPeerIdentity,
    Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionEntry, Ed2kUploadSessionPhase,
    Ed2kUploadSessionPhaseSnapshot, HIGH_FILE_PRIORITY_SCORE, LOW_FILE_PRIORITY_SCORE,
    RELEASE_FILE_PRIORITY_SCORE, VERY_LOW_FILE_PRIORITY_SCORE,
};

/// The upload-queue waiting-score priority multiplier
/// (`CUpDownClient::GetFilePrioAsNumber`, UploadClient.cpp:401-425): PR_VERYHIGH
/// ->18, PR_HIGH->9, PR_LOW->6, PR_VERYLOW->2, default (PR_NORMAL) ->7. An auto
/// file is resolved to its dynamic tier first (`UpdateAutoUpPriority`,
/// KnownFile.cpp:1377-1392) exactly as the publish ranker does, so `auto` and the
/// publish ranker stay consistent — an empty/short queue resolves to HIGH (9),
/// not the NORMAL (7) it used to collapse to.
pub(crate) fn upload_priority_score(priority: &str, auto: bool, queued_count: u64) -> i128 {
    let effective = if auto || priority == "auto" {
        crate::shared_publish_rank::resolve_auto_up_priority_tier(queued_count)
    } else {
        priority
    };
    match effective {
        "verylow" => VERY_LOW_FILE_PRIORITY_SCORE,
        "low" => LOW_FILE_PRIORITY_SCORE,
        "high" => HIGH_FILE_PRIORITY_SCORE,
        "release" | "veryhigh" => RELEASE_FILE_PRIORITY_SCORE,
        "normal" => DEFAULT_FILE_PRIORITY_SCORE,
        _ => DEFAULT_FILE_PRIORITY_SCORE,
    }
}

pub(crate) fn credit_score_permille(
    uploaded_bytes: u64,
    downloaded_bytes: u64,
    ident_verified: bool,
) -> i128 {
    const CREDIT_THRESHOLD_BYTES: u64 = 1_048_576;
    const CREDIT_LINEAR_CAP_BYTES: u64 = 9_646_899;
    // eMule `CClientCredits::GetScoreRatio`: with crypto available (we always
    // have a secure ident) a peer that is not IS_IDENTIFIED gets the neutral 1.0
    // ratio (no credit benefit), since its user-hash-keyed stored bytes are
    // spoofable until the secure-ident signature is verified.
    if !ident_verified {
        return DEFAULT_CREDIT_SCORE_PERMILLE;
    }
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

pub(crate) fn is_low_id_client_id(client_id: u32) -> bool {
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

/// Per-slot upload datarate: the 10 s sliding-window meter (oracle
/// `CUpDownClient::GetUploadDatarate` = `m_nUpDatarate`, computed over
/// `m_AverageUDR_hist`, UploadClient.cpp:860-878) -- NOT a lifetime cumulative
/// average. This is the value the oracle's slow-slot recycle
/// (`GetUploadDatarate() < slowThreshold`, UploadQueue.cpp:519/544/1539) and the
/// productive-slot retention read, so a slot that burst then stalled reads its
/// decayed recent rate here, not its lifetime average.
pub(super) fn upload_speed_bytes_per_sec(session: &Ed2kUploadSessionEntry, now: Instant) -> u64 {
    session.rate_meter.rate_bytes_per_sec(now)
}

pub(super) fn upload_client_id_matches(peer: &Ed2kUploadPeerIdentity, client_id: &str) -> bool {
    peer.user_hash
        .is_some_and(|user_hash| hex::encode(user_hash) == client_id)
        || format!("{}:{}", peer.ip, peer.tcp_port) == client_id
}
