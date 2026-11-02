//! Authenticated diagnostics-only protocol fixture routes.
//!
//! These routes are compiled only into the packet-diagnostics daemon. They
//! establish narrow state-machine prerequisites; they do not inject packets or
//! bypass production protocol handlers.

use std::net::Ipv4Addr;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use emulebb_core::{
    BuddyRelayEligibilityFixtureError, BuddyRelayEligibilityFixtureErrorKind,
    QueuedLowIdSourceFixture, QueuedLowIdSourceFixtureError, QueuedLowIdSourceFixtureErrorKind,
};
use serde::{Deserialize, Serialize};

use crate::RestState;
use crate::envelope::{api_error, parse_required_json_body};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QueuedLowIdSourceFixtureRequest {
    file_hash: String,
    source_ip: Ipv4Addr,
    source_tcp_port: u16,
    source_udp_port: u16,
    source_user_hash: String,
    source_udp_version: u8,
    buddy_ip: Ipv4Addr,
    buddy_udp_port: u16,
    buddy_id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueuedLowIdSourceFixtureResponse {
    accepted: bool,
    file_hash: String,
    source_endpoint: String,
    source_tcp_port: u16,
    source_user_hash: String,
    source_udp_version: u8,
    buddy_endpoint: String,
    buddy_id: String,
    state: &'static str,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuddyRelayEligibilityFixtureResponse {
    prepared: bool,
    tcp_firewalled: bool,
    udp_verified: bool,
    udp_open: bool,
    state: &'static str,
}

struct ValidatedFixture {
    core: QueuedLowIdSourceFixture,
    response: QueuedLowIdSourceFixtureResponse,
}

pub(crate) async fn create_queued_lowid_source_fixture(
    State(state): State<RestState>,
    body: Bytes,
) -> Response {
    let request = match parse_required_json_body::<QueuedLowIdSourceFixtureRequest>(&body) {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let fixture = match validate_fixture(request) {
        Ok(fixture) => fixture,
        Err(message) => {
            return api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response();
        }
    };
    match state
        .core
        .register_queued_lowid_source_fixture(&fixture.core)
        .await
    {
        Ok(()) => fixture_success_response(fixture.response),
        Err(error) => fixture_error_response(error),
    }
}

pub(crate) async fn prepare_buddy_relay_eligibility_fixture(
    State(state): State<RestState>,
) -> Response {
    match state.core.prepare_buddy_relay_eligibility_fixture().await {
        Ok(fixture) => Json(BuddyRelayEligibilityFixtureResponse {
            prepared: true,
            tcp_firewalled: fixture.tcp_firewalled,
            udp_verified: fixture.udp_verified,
            udp_open: fixture.udp_open,
            state: "buddy-relay-eligible",
        })
        .into_response(),
        Err(error) => buddy_relay_fixture_error_response(error),
    }
}

fn fixture_success_response(response: QueuedLowIdSourceFixtureResponse) -> Response {
    Json(response).into_response()
}

fn validate_fixture(request: QueuedLowIdSourceFixtureRequest) -> Result<ValidatedFixture, String> {
    let file_hash = parse_lower_hex_16("fileHash", &request.file_hash)?;
    let source_user_hash = parse_lower_hex_16("sourceUserHash", &request.source_user_hash)?;
    let buddy_id = parse_lower_hex_16("buddyId", &request.buddy_id)?;
    if request.source_tcp_port == 0 {
        return Err("sourceTcpPort must be in the range 1..65535".to_string());
    }
    if request.source_udp_port == 0 {
        return Err("sourceUdpPort must be in the range 1..65535".to_string());
    }
    if !(1..=4).contains(&request.source_udp_version) {
        return Err("sourceUdpVersion must be in the range 1..4".to_string());
    }
    if request.buddy_udp_port == 0 {
        return Err("buddyUdpPort must be in the range 1..65535".to_string());
    }

    let response = QueuedLowIdSourceFixtureResponse {
        accepted: true,
        file_hash: request.file_hash.clone(),
        source_endpoint: format!("{}:{}", request.source_ip, request.source_udp_port),
        source_tcp_port: request.source_tcp_port,
        source_user_hash: request.source_user_hash.clone(),
        source_udp_version: request.source_udp_version,
        buddy_endpoint: format!("{}:{}", request.buddy_ip, request.buddy_udp_port),
        buddy_id: request.buddy_id.clone(),
        state: "queued-lowid-source",
    };
    Ok(ValidatedFixture {
        core: QueuedLowIdSourceFixture {
            file_hash,
            source_ip: request.source_ip,
            source_tcp_port: request.source_tcp_port,
            source_udp_port: request.source_udp_port,
            source_user_hash,
            source_udp_version: request.source_udp_version,
            buddy_ip: request.buddy_ip,
            buddy_udp_port: request.buddy_udp_port,
            buddy_id,
        },
        response,
    })
}

fn parse_lower_hex_16(field: &str, value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{field} must be exactly 32 lowercase hexadecimal characters"
        ));
    }
    let mut output = [0u8; 16];
    let bytes = value.as_bytes();
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2]);
        let low = hex_nibble(bytes[index * 2 + 1]);
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal byte"),
    }
}

fn fixture_error_response(error: QueuedLowIdSourceFixtureError) -> Response {
    let (status, code) = match error.kind {
        QueuedLowIdSourceFixtureErrorKind::TransferNotFound => (StatusCode::NOT_FOUND, "NOT_FOUND"),
        QueuedLowIdSourceFixtureErrorKind::TransferNotActive
        | QueuedLowIdSourceFixtureErrorKind::Ed2kRuntimeNotRunning
        | QueuedLowIdSourceFixtureErrorKind::Ed2kNotConnected
        | QueuedLowIdSourceFixtureErrorKind::UdpReaskDisabled => {
            (StatusCode::CONFLICT, "FIXTURE_PRECONDITION_FAILED")
        }
        QueuedLowIdSourceFixtureErrorKind::RegistrationRejected
        | QueuedLowIdSourceFixtureErrorKind::WakeFailed => {
            (StatusCode::SERVICE_UNAVAILABLE, "FIXTURE_UNAVAILABLE")
        }
    };
    api_error(status, code, error.to_string()).into_response()
}

fn buddy_relay_fixture_error_response(error: BuddyRelayEligibilityFixtureError) -> Response {
    let (status, code) = match error.kind {
        BuddyRelayEligibilityFixtureErrorKind::Ed2kRuntimeNotRunning => {
            (StatusCode::CONFLICT, "FIXTURE_PRECONDITION_FAILED")
        }
    };
    api_error(status, code, error.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> QueuedLowIdSourceFixtureRequest {
        QueuedLowIdSourceFixtureRequest {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            source_ip: Ipv4Addr::new(192, 0, 2, 20),
            source_tcp_port: 4662,
            source_udp_port: 4672,
            source_user_hash: "11223344556677889900aabbccddeeff".to_string(),
            source_udp_version: 4,
            buddy_ip: Ipv4Addr::new(198, 51, 100, 30),
            buddy_udp_port: 5000,
            buddy_id: "ffeeddccbbaa00998877665544332211".to_string(),
        }
    }

    #[test]
    fn success_response_has_the_exact_normalized_contract() {
        let fixture = validate_fixture(request()).unwrap();

        assert_eq!(
            serde_json::to_value(fixture.response).unwrap(),
            json!({
                "accepted": true,
                "fileHash": "00112233445566778899aabbccddeeff",
                "sourceEndpoint": "192.0.2.20:4672",
                "sourceTcpPort": 4662,
                "sourceUserHash": "11223344556677889900aabbccddeeff",
                "sourceUdpVersion": 4,
                "buddyEndpoint": "198.51.100.30:5000",
                "buddyId": "ffeeddccbbaa00998877665544332211",
                "state": "queued-lowid-source"
            })
        );
    }

    #[tokio::test]
    async fn success_http_body_is_the_unwrapped_normalized_contract() {
        let fixture = validate_fixture(request()).unwrap();
        let response = fixture_success_response(fixture.response);

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["accepted"], true);
        assert_eq!(value["state"], "queued-lowid-source");
        assert!(value.get("data").is_none());
        assert!(value.get("meta").is_none());
        assert_eq!(value.as_object().unwrap().len(), 9);
    }

    #[test]
    fn hashes_must_already_be_lowercase_canonical() {
        let mut request = request();
        request.file_hash = request.file_hash.to_ascii_uppercase();

        assert_eq!(
            validate_fixture(request).err().unwrap(),
            "fileHash must be exactly 32 lowercase hexadecimal characters"
        );
    }

    #[test]
    fn udp_version_is_bounded_to_supported_wire_versions() {
        let mut request = request();
        request.source_udp_version = 5;

        assert_eq!(
            validate_fixture(request).err().unwrap(),
            "sourceUdpVersion must be in the range 1..4"
        );
    }
}
