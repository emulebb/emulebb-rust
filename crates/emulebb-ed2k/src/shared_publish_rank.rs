use std::cmp::Ordering;

const KADEMLIA_PUBLISH_JITTER_WINDOW_SECS: i64 = 2;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedPublishRank {
    priority: i32,
    balanced_score: f64,
    all_time_upload_ratio: f64,
    session_upload_ratio: f64,
    last_publish_unix_ms: i64,
    sequence: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct SharedPublishRankInput<'a> {
    pub file_hash: &'a str,
    pub file_size: u64,
    pub upload_priority: &'a str,
    pub auto_upload_priority: bool,
    pub queued_count: u64,
    pub session_request_count: u64,
    pub session_accept_count: u64,
    pub all_time_request_count: u64,
    pub all_time_accept_count: u64,
    pub all_time_uploaded_bytes: u64,
    pub session_uploaded_bytes: u64,
    pub last_request_unix_ms: i64,
    pub last_publish_unix_ms: i64,
    pub sequence: usize,
    pub now_unix_ms: i64,
}

pub fn shared_publish_rank(input: SharedPublishRankInput<'_>) -> SharedPublishRank {
    let all_time_upload_ratio =
        publish_upload_ratio(input.all_time_uploaded_bytes, input.file_size);
    let session_upload_ratio = publish_upload_ratio(input.session_uploaded_bytes, input.file_size);
    SharedPublishRank {
        priority: mfc_real_upload_priority(
            input.upload_priority,
            input.auto_upload_priority,
            input.queued_count,
        ),
        balanced_score: publish_balanced_score(input, all_time_upload_ratio, session_upload_ratio),
        all_time_upload_ratio,
        session_upload_ratio,
        last_publish_unix_ms: input.last_publish_unix_ms,
        sequence: input.sequence,
    }
}

pub fn compare_shared_publish_rank(
    left: &SharedPublishRank,
    right: &SharedPublishRank,
) -> Ordering {
    left.priority
        .cmp(&right.priority)
        .then_with(|| left.balanced_score.total_cmp(&right.balanced_score))
        .then_with(|| {
            right
                .all_time_upload_ratio
                .total_cmp(&left.all_time_upload_ratio)
        })
        .then_with(|| {
            right
                .session_upload_ratio
                .total_cmp(&left.session_upload_ratio)
        })
        .then_with(|| right.last_publish_unix_ms.cmp(&left.last_publish_unix_ms))
        .then_with(|| left.sequence.cmp(&right.sequence))
        .reverse()
}

/// Resolve an auto-upload-priority file's effective tier from its upload-queue
/// depth, mirroring `CKnownFile::UpdateAutoUpPriority` (KnownFile.cpp:1377-1392):
/// `GetQueuedCount() > 20 -> PR_LOW`, `> 1 -> PR_NORMAL`, else `-> PR_HIGH`. An
/// auto file's `m_iUpPriority` is dynamically overwritten with this resolved tier
/// (a separate `m_bAutoUpPriority` flag records that it is auto), so every ranker
/// that reads `GetUpPriority()` sees the resolved tier — NOT a distinct auto
/// sentinel. A freshly shared auto file with no queue therefore resolves to HIGH.
pub fn resolve_auto_up_priority_tier(queued_count: u64) -> &'static str {
    if queued_count > 20 {
        "low"
    } else if queued_count > 1 {
        "normal"
    } else {
        "high"
    }
}

/// The oracle's realprio used for publish/offer ordering:
/// `CSharedFileList::GetRealPrio(GetUpPriority())` (SharedFileList.h:350,
/// `(in < 4) ? in + 1 : 0`) over the priority enum
/// (PartFile.h:41-46 — PR_LOW=0, PR_NORMAL=1, PR_HIGH=2, PR_VERYHIGH=3,
/// PR_VERYLOW=4). An auto file is resolved to its dynamic tier first
/// (`UpdateAutoUpPriority`), so `GetUpPriority()` already yields LOW/NORMAL/HIGH;
/// with an empty/short queue that is HIGH -> realprio 3 (near the FRONT), never 0.
pub fn mfc_real_upload_priority(
    priority: &str,
    auto_upload_priority: bool,
    queued_count: u64,
) -> i32 {
    let effective = if auto_upload_priority || priority == "auto" {
        resolve_auto_up_priority_tier(queued_count)
    } else {
        priority
    };
    match effective {
        // GetRealPrio: PR_LOW(0)->1, PR_NORMAL(1)->2, PR_HIGH(2)->3,
        // PR_VERYHIGH(3)->4, PR_VERYLOW(4)->0.
        "low" => 1,
        "normal" => 2,
        "high" => 3,
        "release" | "veryhigh" => 4,
        "verylow" => 0,
        _ => 2,
    }
}

fn publish_upload_ratio(uploaded_bytes: u64, file_size: u64) -> f64 {
    if file_size == 0 {
        return 0.0;
    }
    uploaded_bytes as f64 / file_size as f64
}

fn publish_log_score(value: u64, weight: f64) -> f64 {
    if value == 0 {
        0.0
    } else {
        (value as f64).ln_1p() * weight
    }
}

fn publish_age_score(last_publish_unix_ms: i64, now_unix_ms: i64) -> f64 {
    if last_publish_unix_ms <= 0 {
        return 80.0;
    }
    let hours_since_publish = ((now_unix_ms - last_publish_unix_ms).max(0) as f64) / 3_600_000.0;
    (hours_since_publish * 2.0).min(80.0)
}

fn publish_under_shared_score(
    all_time_upload_ratio: f64,
    session_upload_ratio: f64,
    all_time_uploaded_bytes: u64,
    all_time_request_count: u64,
    all_time_accept_count: u64,
) -> f64 {
    let mut score = 0.0;
    if all_time_upload_ratio < 1.0 {
        score += (1.0 - all_time_upload_ratio) * 70.0;
    }
    if session_upload_ratio < 1.0 {
        score += (1.0 - session_upload_ratio) * 35.0;
    }
    if all_time_uploaded_bytes == 0 {
        score += 35.0;
    }
    if all_time_request_count > 0 && all_time_accept_count == 0 {
        score += 20.0;
    }
    score
}

fn publish_recent_request_score(last_request_unix_ms: i64, now_unix_ms: i64) -> f64 {
    if last_request_unix_ms <= 0 {
        return 0.0;
    }
    let hours_since_request = ((now_unix_ms - last_request_unix_ms).max(0) as f64) / 3_600_000.0;
    (60.0 - hours_since_request * 2.0).max(0.0)
}

fn publish_deterministic_jitter(file_hash: &str, now_unix_ms: i64, sequence: usize) -> f64 {
    let mut hash =
        2_166_136_261u32 ^ ((now_unix_ms / 1000) / KADEMLIA_PUBLISH_JITTER_WINDOW_SECS) as u32;
    for byte in decode_hash_bytes(file_hash) {
        hash = (hash ^ u32::from(byte)).wrapping_mul(16_777_619);
    }
    hash = (hash ^ sequence as u32).wrapping_mul(16_777_619);
    f64::from(hash % 1000) / 1000.0 * 15.0
}

fn decode_hash_bytes(file_hash: &str) -> Vec<u8> {
    hex::decode(file_hash).unwrap_or_else(|_| file_hash.as_bytes().to_vec())
}

fn publish_balanced_score(
    input: SharedPublishRankInput<'_>,
    all_time_upload_ratio: f64,
    session_upload_ratio: f64,
) -> f64 {
    publish_log_score(input.queued_count, 70.0)
        + publish_log_score(input.session_request_count, 45.0)
        + publish_log_score(input.session_accept_count, 30.0)
        + publish_log_score(input.all_time_request_count, 20.0)
        + publish_log_score(input.all_time_accept_count, 12.0)
        + publish_recent_request_score(input.last_request_unix_ms, input.now_unix_ms)
        + publish_under_shared_score(
            all_time_upload_ratio,
            session_upload_ratio,
            input.all_time_uploaded_bytes,
            input.all_time_request_count,
            input.all_time_accept_count,
        )
        + publish_age_score(input.last_publish_unix_ms, input.now_unix_ms)
        + publish_deterministic_jitter(input.file_hash, input.now_unix_ms, input.sequence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(priority: &'static str, uploaded: u64, sequence: usize) -> SharedPublishRank {
        shared_publish_rank(SharedPublishRankInput {
            file_hash: "00112233445566778899aabbccddeeff",
            file_size: 1_000,
            upload_priority: priority,
            auto_upload_priority: false,
            queued_count: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_request_count: 0,
            all_time_accept_count: 0,
            all_time_uploaded_bytes: uploaded,
            session_uploaded_bytes: 0,
            last_request_unix_ms: 0,
            last_publish_unix_ms: 0,
            sequence,
            now_unix_ms: 4_000,
        })
    }

    #[test]
    fn upload_priority_matches_mfc_real_priority_order() {
        assert!(compare_shared_publish_rank(&rank("release", 0, 0), &rank("high", 0, 1)).is_lt());
        assert!(compare_shared_publish_rank(&rank("high", 0, 0), &rank("normal", 0, 1)).is_lt());
        assert!(compare_shared_publish_rank(&rank("normal", 0, 0), &rank("low", 0, 1)).is_lt());
        // GetRealPrio over the explicit tiers (PartFile.h:41-46, SharedFileList.h:350).
        assert_eq!(mfc_real_upload_priority("verylow", false, 0), 0);
        assert_eq!(mfc_real_upload_priority("low", false, 0), 1);
        assert_eq!(mfc_real_upload_priority("normal", false, 0), 2);
        assert_eq!(mfc_real_upload_priority("high", false, 0), 3);
        assert_eq!(mfc_real_upload_priority("veryhigh", false, 0), 4);
        assert_eq!(mfc_real_upload_priority("release", false, 0), 4);
    }

    #[test]
    fn auto_priority_resolves_through_queue_depth_like_update_auto_up_priority() {
        // Freshly shared auto file, empty queue -> PR_HIGH -> realprio 3 (near the
        // FRONT), NOT the bottom 0 that verylow/auto used to share.
        assert_eq!(mfc_real_upload_priority("normal", true, 0), 3);
        assert_eq!(mfc_real_upload_priority("auto", false, 0), 3);
        assert_eq!(mfc_real_upload_priority("normal", true, 1), 3);
        // GetQueuedCount() > 1 -> PR_NORMAL -> realprio 2.
        assert_eq!(mfc_real_upload_priority("normal", true, 2), 2);
        // GetQueuedCount() > 20 -> PR_LOW -> realprio 1.
        assert_eq!(mfc_real_upload_priority("normal", true, 21), 1);
        // An empty-queue auto file outranks an explicit normal file in publish order.
        let auto = shared_publish_rank(SharedPublishRankInput {
            file_hash: "00112233445566778899aabbccddeeff",
            file_size: 1_000,
            upload_priority: "normal",
            auto_upload_priority: true,
            queued_count: 0,
            session_request_count: 0,
            session_accept_count: 0,
            all_time_request_count: 0,
            all_time_accept_count: 0,
            all_time_uploaded_bytes: 0,
            session_uploaded_bytes: 0,
            last_request_unix_ms: 0,
            last_publish_unix_ms: 0,
            sequence: 1,
            now_unix_ms: 4_000,
        });
        assert!(compare_shared_publish_rank(&auto, &rank("normal", 0, 0)).is_lt());
    }

    #[test]
    fn underserved_files_win_within_same_priority() {
        assert!(
            compare_shared_publish_rank(&rank("normal", 0, 0), &rank("normal", 2_000, 1)).is_lt()
        );
    }

    #[test]
    fn recent_demand_wins_within_same_priority() {
        let quiet = rank("normal", 0, 0);
        let requested = shared_publish_rank(SharedPublishRankInput {
            file_hash: "00112233445566778899aabbccddeeff",
            file_size: 1_000,
            upload_priority: "normal",
            auto_upload_priority: false,
            queued_count: 0,
            session_request_count: 3,
            session_accept_count: 0,
            all_time_request_count: 3,
            all_time_accept_count: 0,
            all_time_uploaded_bytes: 0,
            session_uploaded_bytes: 0,
            last_request_unix_ms: 3_000,
            last_publish_unix_ms: 0,
            sequence: 1,
            now_unix_ms: 4_000,
        });
        assert!(compare_shared_publish_rank(&requested, &quiet).is_lt());
    }
}
