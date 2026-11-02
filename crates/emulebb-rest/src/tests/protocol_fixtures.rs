use crate::rest_test_support::*;

const ROUTE: &str = "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources";

fn valid_body() -> Value {
    json!({
        "fileHash": "00112233445566778899aabbccddeeff",
        "sourceIp": "192.0.2.20",
        "sourceTcpPort": 4662,
        "sourceUdpPort": 4672,
        "sourceUserHash": "11223344556677889900aabbccddeeff",
        "sourceUdpVersion": 4,
        "buddyIp": "198.51.100.30",
        "buddyUdpPort": 5000,
        "buddyId": "ffeeddccbbaa00998877665544332211"
    })
}

#[tokio::test]
async fn queued_lowid_fixture_route_requires_api_key() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ROUTE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(valid_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn queued_lowid_fixture_route_rejects_unknown_fields() {
    let mut body = valid_body();
    body["packetHex"] = json!("c594");

    assert_invalid_json_response(
        test_router(),
        "POST",
        ROUTE,
        body.to_string(),
        "unknown JSON field: packetHex",
    )
    .await;
}

#[tokio::test]
async fn queued_lowid_fixture_route_rejects_noncanonical_hashes() {
    let mut body = valid_body();
    body["buddyId"] = json!("FFEEDDCCBBAA00998877665544332211");

    assert_invalid_json_response(
        test_router(),
        "POST",
        ROUTE,
        body.to_string(),
        "buddyId must be exactly 32 lowercase hexadecimal characters",
    )
    .await;
}

#[tokio::test]
async fn queued_lowid_fixture_route_reaches_core_preconditions() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ROUTE)
                .header("X-API-Key", "secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(valid_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "NOT_FOUND");
    assert_eq!(value["error"]["message"], "transfer does not exist");
}
