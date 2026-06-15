//! REST-contract serialization guards for populated `TransferSource` / `Upload`
//! values. The in-process REST smoke tests create no sources or uploads, so a
//! struct that serialized extra (non-contract) fields would slip through schema
//! validation. These tests construct populated values and assert the emitted
//! JSON carries ONLY the eMuleBB-contract keys.

use std::collections::BTreeSet;

use emulebb_core::{TransferSource, Upload, UploadScoreBreakdown};
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

fn populated_transfer_source() -> TransferSource {
    TransferSource {
        client_id: "0102030405060708090a0b0c0d0e0f10".to_string(),
        // Internal-only fields that must never leak into the contract JSON.
        hash: "00112233445566778899aabbccddeeff".to_string(),
        ip: "192.0.2.10".to_string(),
        tcp_port: 4662,
        endpoint: "192.0.2.10:4662".to_string(),
        banned: true,
        status: "remembered".to_string(),
        // Contract fields.
        port: 4662,
        user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        user_name: "peer".to_string(),
        client_software: "eMule".to_string(),
        download_state: "downloading".to_string(),
        download_speed_ki_bps: 12.5,
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
fn transfer_source_serializes_only_contract_keys() {
    let value = serde_json::to_value(populated_transfer_source()).unwrap();
    let keys = object_keys(&value);

    let expected: BTreeSet<String> = [
        "clientId",
        "userName",
        "userHash",
        "address",
        "port",
        "downloadState",
        "clientSoftware",
        "downloadSpeedKiBps",
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
    assert_eq!(keys, expected, "TransferSource emitted non-contract keys");

    // The six internal-only fields must be absent.
    for forbidden in ["hash", "ip", "tcpPort", "endpoint", "banned", "status"] {
        assert!(
            value.get(forbidden).is_none(),
            "TransferSource must not serialize `{forbidden}`"
        );
    }
}

fn score_breakdown() -> UploadScoreBreakdown {
    UploadScoreBreakdown {
        availability: "available".to_string(),
        base_score: 100,
        effective_score: 100,
        core_score: 100.0,
        effective_score_float: 100.0,
        credit_ratio: 1.0,
        file_priority: 1,
        low_ratio_applied: false,
        low_ratio_bonus: 0,
        low_id_penalty_applied: false,
        low_id_divisor: 1,
        old_client_penalty_applied: false,
        cooldown_remaining_ms: 0,
    }
}

fn populated_upload(score_breakdown: Option<UploadScoreBreakdown>) -> Upload {
    Upload {
        client_id: "0102030405060708090a0b0c0d0e0f10".to_string(),
        user_name: "peer".to_string(),
        user_hash: Some("0102030405060708090a0b0c0d0e0f10".to_string()),
        client_software: "eMule".to_string(),
        client_mod: String::new(),
        upload_state: "uploading".to_string(),
        upload_speed_ki_bps: 8.0,
        uploaded_bytes: 1024,
        queue_session_uploaded: 1024,
        payload_buffered: 0,
        wait_time_ms: 5000,
        wait_started_tick: 0,
        score: 100,
        address: "192.0.2.10".to_string(),
        port: 4662,
        server_ip: String::new(),
        server_port: 0,
        low_id: false,
        friend_slot: false,
        uploading: true,
        waiting_queue: false,
        requested_file_hash: Some("00112233445566778899aabbccddeeff".to_string()),
        requested_file_name: Some("file.bin".to_string()),
        requested_file_size_bytes: Some(4096),
        requested_parts_obtained: 1,
        requested_parts_total: 1,
        requested_parts_progress_text: "1/1".to_string(),
        score_breakdown,
        // Internal-only: must never leak into the contract JSON.
        queue_rank: Some(3),
    }
}

#[test]
fn upload_serializes_without_queue_rank() {
    let value = serde_json::to_value(populated_upload(Some(score_breakdown()))).unwrap();
    assert!(
        value.get("queueRank").is_none(),
        "Upload must not serialize `queueRank` (it belongs to source JSON)"
    );
    // Sanity: a representative contract field is present.
    assert_eq!(value["clientId"], json!("0102030405060708090a0b0c0d0e0f10"));
}

#[test]
fn upload_score_breakdown_is_gated_on_the_flag() {
    // Present when the caller opts in (single-client lookups / flagged list).
    let with = serde_json::to_value(populated_upload(Some(score_breakdown()))).unwrap();
    assert!(
        with.get("scoreBreakdown").is_some(),
        "scoreBreakdown must be present when requested"
    );

    // Absent otherwise (default list behaviour).
    let without = serde_json::to_value(populated_upload(None)).unwrap();
    assert!(
        without.get("scoreBreakdown").is_none(),
        "scoreBreakdown must be omitted when not requested"
    );
}
