//! REST-contract serialization guards for populated `TransferSource` / `Upload`
//! values. The in-process REST smoke tests create no sources or uploads, so a
//! struct that serialized extra (non-contract) fields would slip through schema
//! validation. These tests construct populated values and assert the emitted
//! JSON carries ONLY the eMuleBB-contract keys.

use std::collections::BTreeSet;

use emulebb_core::TransferSource;
use serde_json::Value;

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
