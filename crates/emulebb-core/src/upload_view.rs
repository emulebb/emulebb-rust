//! REST `Upload` view builders.
//!
//! Pure helpers that build the REST `Upload` / `UploadPolicyMetrics` response
//! structs from the lower-layer upload-queue snapshot entries + capacity
//! snapshot + resume manifest, plus the small upload-state/part-count helpers
//! they rely on. Moved verbatim out of `lib.rs` during the maintainability
//! restructuring; they carry no behavior beyond what they had inline.
//! Re-exported `pub(crate)` from the crate root so the `EmulebbCore` impl
//! reaches them by their bare names.

use emulebb_ed2k::ed2k_transfer::{
    Ed2kResumeManifest, Ed2kUploadQueueCapacitySnapshot, Ed2kUploadQueueSnapshotEntry,
    Ed2kUploadSessionPhaseSnapshot,
};

use crate::{Upload, UploadPolicyMetrics, UploadScoreBreakdown};

pub(crate) fn upload_from_snapshot(
    entry: Ed2kUploadQueueSnapshotEntry,
    manifest: Option<&Ed2kResumeManifest>,
) -> Upload {
    let user_hash = entry.user_hash.map(hex::encode);
    let client_id = user_hash
        .clone()
        .unwrap_or_else(|| format!("{}:{}", entry.ip, entry.tcp_port));
    let requested_parts_total = manifest
        .map(|manifest| manifest.pieces.len() as u32)
        .unwrap_or_default();
    let requested_parts_obtained = manifest.map(upload_obtained_part_count).unwrap_or_default();
    let requested_parts_progress_text = if requested_parts_total == 0 {
        String::new()
    } else {
        format!("{requested_parts_obtained}/{requested_parts_total}")
    };
    let upload_state = upload_state_name(entry.phase).to_string();
    let waiting_queue = matches!(entry.phase, Ed2kUploadSessionPhaseSnapshot::Waiting);
    let uploading = matches!(
        entry.phase,
        Ed2kUploadSessionPhaseSnapshot::Granted | Ed2kUploadSessionPhaseSnapshot::Uploading
    );
    let score = entry.score.clamp(0, i128::from(u32::MAX)) as u32;
    let availability = if entry.friend_slot {
        "friendSlot"
    } else if uploading || waiting_queue {
        "available"
    } else {
        "unavailable"
    };
    let score_breakdown = UploadScoreBreakdown {
        availability: availability.to_string(),
        base_score: score,
        effective_score: score,
        core_score: entry.score as f64,
        effective_score_float: entry.score as f64,
        credit_ratio: entry.credit_score_permille as f64 / 1000.0,
        file_priority: entry.file_priority_score as i64,
        low_ratio_applied: entry.low_ratio_applied,
        low_ratio_bonus: entry.low_ratio_bonus,
        low_id_penalty_applied: entry.low_id_penalty_applied,
        low_id_divisor: entry.low_id_divisor,
        old_client_penalty_applied: entry.old_client_penalty_applied,
        cooldown_remaining_ms: 0,
    };
    Upload {
        client_id,
        user_name: format!("{}:{}", entry.ip, entry.tcp_port),
        user_hash,
        client_software: entry
            .client_software
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        client_mod: String::new(),
        upload_state,
        upload_speed_ki_bps: entry.upload_speed_bytes_per_sec as f64 / 1024.0,
        uploaded_bytes: entry.uploaded_bytes,
        queue_session_uploaded: entry.uploaded_bytes,
        payload_buffered: 0,
        wait_time_ms: entry.wait_time_ms,
        wait_started_tick: 0,
        score: u64::from(score),
        score_breakdown: Some(score_breakdown),
        address: entry.ip.to_string(),
        port: entry.tcp_port,
        server_ip: String::new(),
        server_port: 0,
        low_id: entry.client_id.is_some_and(is_low_id_client_id),
        friend_slot: entry.friend_slot,
        uploading,
        waiting_queue,
        requested_file_hash: Some(entry.file_hash),
        requested_file_name: manifest.map(|manifest| manifest.canonical_name.clone()),
        requested_file_size_bytes: manifest.map(|manifest| manifest.file_size),
        requested_parts_obtained,
        requested_parts_total,
        requested_parts_progress_text,
        queue_rank: entry.queue_rank,
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

fn upload_obtained_part_count(manifest: &Ed2kResumeManifest) -> u32 {
    if manifest.completed {
        return manifest.pieces.len() as u32;
    }
    manifest
        .pieces
        .iter()
        .filter(|piece| {
            piece.bytes_written >= upload_expected_piece_length(manifest, piece.piece_index)
        })
        .count() as u32
}

fn upload_expected_piece_length(manifest: &Ed2kResumeManifest, piece_index: u32) -> u64 {
    let start = u64::from(piece_index).saturating_mul(manifest.piece_size);
    if start >= manifest.file_size {
        return 0;
    }
    manifest
        .file_size
        .saturating_sub(start)
        .min(manifest.piece_size)
}

fn is_low_id_client_id(client_id: u32) -> bool {
    client_id != 0 && client_id < 0x0100_0000
}
