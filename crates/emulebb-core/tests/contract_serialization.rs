//! Exact JSON surfaces for populated download sources, summaries and uploads.

use std::collections::BTreeSet;

use emulebb_core::{
    DownloadSource, DownloadState, DownloadSummary, SharedFileKadKeywordPublish,
    SharedFilePublicationStatus, SharedFilePublishLane, SharedFilePublishState, Upload,
    UploadScoreBreakdown,
};
use serde_json::{Value, json};

/// Collect the top-level object keys of a serialized value.
fn object_keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("expected a JSON object")
        .keys()
        .cloned()
        .collect()
}

fn populated_download_source() -> DownloadSource {
    DownloadSource {
        client_id: "0102030405060708090a0b0c0d0e0f10".to_string(),
        // Internal-only fields that must never leak into the contract JSON.
        hash: "00112233445566778899aabbccddeeff".to_string(),
        ip: "192.0.2.10".to_string(),
        tcp_port: 4662,
        endpoint: "192.0.2.10:4662".to_string(),
        file_comment: "helpful".to_string(),
        file_rating: 4,
        banned: true,
        status: "remembered".to_string(),
        // Contract fields.
        port: 4662,
        user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        user_name: "peer".to_string(),
        client_software: "eMule".to_string(),
        reported_file_names: Vec::new(),
        reported_file_names_has_more: false,
        download_state: "downloading".to_string(),
        download_rate_bytes_per_second: 12_800,
        available_parts: 3,
        part_count: 9,
        address: "192.0.2.10".to_string(),
        server_ip: "203.0.113.1".to_string(),
        server_port: 4661,
        low_id: false,
        queue_rank: 7,
        view_shared_files: true,
        shared_files_request_pending: false,
    }
}

#[test]
fn download_source_serializes_only_contract_keys() {
    let value = serde_json::to_value(populated_download_source()).unwrap();
    let keys = object_keys(&value);

    let expected: BTreeSet<String> = [
        "clientId",
        "userName",
        "userHash",
        "address",
        "port",
        "downloadState",
        "clientSoftware",
        "reportedFileNames",
        "reportedFileNamesHasMore",
        "downloadRateBytesPerSecond",
        "availableParts",
        "partCount",
        "serverIp",
        "serverPort",
        "lowId",
        "queueRank",
        "viewSharedFiles",
        "sharedFilesRequestPending",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(keys, expected, "DownloadSource emitted non-contract keys");

    // The six internal-only fields must be absent.
    for forbidden in ["hash", "ip", "tcpPort", "endpoint", "banned", "status"] {
        assert!(
            value.get(forbidden).is_none(),
            "DownloadSource must not serialize `{forbidden}`"
        );
    }
}

#[test]
fn download_summary_has_decimal_identity_seconds_and_no_nested_execution_history() {
    let summary = DownloadSummary {
        id: emulebb_metadata::JobId::new(1).unwrap(),
        hash: "00112233445566778899aabbccddeeff".into(),
        name: "Sample.bin".into(),
        size_bytes: Some(4096),
        progress: Some(0.0),
        intent: emulebb_metadata::DownloadIntent::Stopped,
        state: DownloadState::Stopped,
        waiting_reason: None,
        category: Some("Sample-Category".into()),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_001,
        completed_at: None,
    };
    let value = serde_json::to_value(summary).unwrap();
    assert_eq!(
        object_keys(&value),
        [
            "id",
            "hash",
            "name",
            "sizeBytes",
            "progress",
            "intent",
            "state",
            "waitingReason",
            "category",
            "createdAt",
            "updatedAt",
            "completedAt"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
    assert_eq!(value["id"], json!("1"));
    assert_eq!(value["createdAt"], json!(1_700_000_000));
    assert_eq!(value["intent"], json!("stopped"));
}

fn score_breakdown() -> UploadScoreBreakdown {
    UploadScoreBreakdown {
        score: 100.0,
        credit_ratio: 1.0,
        file_priority_score: 1.0,
        low_ratio_applied: false,
        low_ratio_bonus: 0,
        low_id_penalty_applied: false,
        low_id_divisor: 1,
        old_client_penalty_applied: false,
    }
}

fn populated_upload(score_breakdown: Option<UploadScoreBreakdown>) -> Upload {
    Upload {
        id: "12345678-1234-4234-8234-123456789abc".into(),
        user_hash: Some("0102030405060708090a0b0c0d0e0f10".into()),
        client_software: Some("Sample Client".into()),
        upload_state: "uploading".into(),
        upload_rate_bytes_per_sec: 8192,
        session_uploaded_bytes: 1024,
        wait_time_seconds: 5,
        upload_duration_seconds: Some(2),
        address: "192.0.2.10".into(),
        port: 4662,
        low_id: None,
        friend_slot: false,
        connected: true,
        requested_file_hash: "00112233445566778899aabbccddeeff".into(),
        requested_file_name: Some("Sample.bin".into()),
        requested_file_size_bytes: Some(4096),
        file_parts_available: Some(1),
        file_parts_total: Some(1),
        score_breakdown,
        queue_rank: None,
    }
}

#[test]
fn active_upload_serializes_canonical_units_and_nullable_rank() {
    let value = serde_json::to_value(populated_upload(Some(score_breakdown()))).unwrap();
    assert_eq!(
        value,
        json!({
            "id":"12345678-1234-4234-8234-123456789abc",
            "userHash":"0102030405060708090a0b0c0d0e0f10","clientSoftware":"Sample Client",
            "uploadState":"uploading","uploadRateBytesPerSec":8192,"sessionUploadedBytes":1024,
            "waitTimeSeconds":5,"uploadDurationSeconds":2,"address":"192.0.2.10","port":4662,
            "lowId":null,"friendSlot":false,"connected":true,
            "requestedFileHash":"00112233445566778899aabbccddeeff","requestedFileName":"Sample.bin",
            "requestedFileSizeBytes":4096,"filePartsAvailable":1,"filePartsTotal":1,"queueRank":null,
            "scoreBreakdown":{"score":100.0,"creditRatio":1.0,"filePriorityScore":1.0,
                "lowRatioApplied":false,"lowRatioBonus":0,"lowIdPenaltyApplied":false,
                "lowIdDivisor":1,"oldClientPenaltyApplied":false}
        })
    );
}

#[test]
fn upload_summary_contains_only_scalar_fields() {
    let value = serde_json::to_value(populated_upload(None)).unwrap();
    assert_eq!(
        object_keys(&value),
        [
            "id",
            "userHash",
            "clientSoftware",
            "uploadState",
            "uploadRateBytesPerSec",
            "sessionUploadedBytes",
            "waitTimeSeconds",
            "uploadDurationSeconds",
            "address",
            "port",
            "lowId",
            "friendSlot",
            "connected",
            "requestedFileHash",
            "requestedFileName",
            "requestedFileSizeBytes",
            "filePartsAvailable",
            "filePartsTotal",
            "queueRank"
        ]
        .into_iter()
        .map(String::from)
        .collect()
    );
}

#[test]
fn shared_file_publication_states_use_stable_contract_tokens() {
    let value = serde_json::to_value(SharedFilePublicationStatus {
        ed2k: SharedFilePublishLane {
            state: SharedFilePublishState::Queued,
            last_success_at_ms: None,
        },
        kad_keyword: SharedFileKadKeywordPublish {
            state: SharedFilePublishState::Partial,
            published_keywords: 1,
            total_keywords: 2,
            last_success_at_ms: Some(42),
        },
        kad_source: SharedFilePublishLane {
            state: SharedFilePublishState::Unavailable,
            last_success_at_ms: None,
        },
    })
    .unwrap();

    assert_eq!(value["ed2k"]["state"], "queued");
    assert_eq!(value["kadKeyword"]["state"], "partial");
    assert_eq!(value["kadSource"]["state"], "unavailable");
}
