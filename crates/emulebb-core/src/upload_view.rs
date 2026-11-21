//! REST `Upload` view builders.
//!
//! Pure helpers that build the REST `Upload` / `UploadPolicyMetrics` response
//! structs from queue snapshots, capacity and cached scalar file metadata.
//! Re-exported `pub(crate)` from the crate root so the `EmulebbCore` impl
//! reaches them by their bare names.

use emulebb_ed2k::ed2k_transfer::{
    Ed2kUploadQueueCapacitySnapshot, Ed2kUploadQueueSnapshotEntry, Ed2kUploadSessionPhaseSnapshot,
};

use crate::{Upload, UploadPolicyMetrics, UploadScoreBreakdown};
use emulebb_metadata::MetadataUploadFileSummary;

pub(crate) fn upload_from_snapshot(
    entry: Ed2kUploadQueueSnapshotEntry,
    view: Option<&MetadataUploadFileSummary>,
) -> Upload {
    let user_hash = entry.user_hash.map(hex::encode);
    let upload_state = upload_state_name(entry.phase).to_string();
    let score_breakdown = UploadScoreBreakdown {
        score: entry.score as f64,
        credit_ratio: entry.credit_score_permille as f64 / 1000.0,
        file_priority_score: entry.file_priority_score as f64,
        low_ratio_applied: entry.low_ratio_applied,
        low_ratio_bonus: entry.low_ratio_bonus,
        low_id_penalty_applied: entry.low_id_penalty_applied,
        low_id_divisor: entry.low_id_divisor,
        old_client_penalty_applied: entry.old_client_penalty_applied,
    };
    Upload {
        id: entry.id.to_string(),
        user_hash,
        client_software: entry.client_software,
        upload_state,
        upload_rate_bytes_per_sec: entry.upload_speed_bytes_per_sec,
        session_uploaded_bytes: entry.uploaded_bytes,
        wait_time_seconds: entry.wait_duration_seconds,
        upload_duration_seconds: entry.upload_duration_seconds,
        score_breakdown: Some(score_breakdown),
        address: entry.ip.to_string(),
        port: entry.tcp_port,
        low_id: entry
            .client_id
            .filter(|id| *id != 0)
            .map(is_low_id_client_id),
        friend_slot: entry.friend_slot,
        connected: entry.connected,
        requested_file_hash: entry.file_hash,
        requested_file_name: view.map(|view| view.display_name.clone()),
        requested_file_size_bytes: view.map(|view| view.file_size),
        file_parts_available: view.map(|view| view.parts_obtained),
        file_parts_total: view.map(|view| view.parts_total),
        queue_rank: entry.management_rank,
    }
}

pub(crate) fn upload_policy_metrics_from_capacity(
    capacity: Ed2kUploadQueueCapacitySnapshot,
) -> UploadPolicyMetrics {
    UploadPolicyMetrics {
        base_slots: capacity.base_slots,
        elastic_slots: capacity.elastic_slots,
        active_slots: capacity.active_slots,
        active_sessions: capacity.active_sessions,
        waiting_sessions: capacity.waiting_sessions,
        upload_rate_bytes_per_sec: capacity.upload_rate_bytes_per_sec,
        upload_limit_bytes_per_sec: capacity.upload_limit_bytes_per_sec,
        elastic_underfill_bytes_per_sec: capacity.elastic_underfill_bytes_per_sec,
        elastic_underfill: capacity.elastic_underfill,
        underfill_since_ms: capacity.underfill_since_ms,
    }
}

fn upload_state_name(phase: Ed2kUploadSessionPhaseSnapshot) -> &'static str {
    match phase {
        Ed2kUploadSessionPhaseSnapshot::Waiting => "queued",
        Ed2kUploadSessionPhaseSnapshot::Granted => "connecting",
        Ed2kUploadSessionPhaseSnapshot::Uploading => "uploading",
    }
}

fn is_low_id_client_id(client_id: u32) -> bool {
    client_id != 0 && client_id < 0x0100_0000
}
