use crate::rest_test_support::*;

#[tokio::test]
async fn write_routes_use_canonical_json_error_envelope() {
    let cases = [
        ("POST", "/api/v1/app/shutdown"),
        ("POST", "/api/v1/diagnostics/dumps"),
        ("POST", "/api/v1/diagnostics/crash-tests"),
        ("POST", "/api/v1/categories"),
        ("PATCH", "/api/v1/categories/1"),
        ("POST", "/api/v1/friends"),
        ("POST", "/api/v1/servers"),
        ("PATCH", "/api/v1/servers/local:4661"),
        ("POST", "/api/v1/searches"),
        ("PATCH", "/api/v1/shared-directories"),
        (
            "PATCH",
            "/api/v1/shared-files/00112233445566778899aabbccddeeff",
        ),
        ("POST", "/api/v1/transfers"),
        ("POST", "/api/v1/transfers/operations/clear-completed"),
        (
            "PATCH",
            "/api/v1/transfers/00112233445566778899aabbccddeeff",
        ),
        ("POST", "/api/v1/logs/operations/clear"),
    ];
    for (method, uri) in cases {
        assert_invalid_json_response(
            test_router(),
            method,
            uri,
            r#"{"unsupportedJsonField":true}"#,
            "unknown JSON field: unsupportedJsonField",
        )
        .await;
    }
}

#[tokio::test]
async fn malformed_json_uses_canonical_error_envelope() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(value["error"]["message"].as_str().unwrap().contains("EOF"));
}

#[tokio::test]
async fn json_body_requires_json_content_type() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "text/plain")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Alpha.bin|1|00112233445566778899aabbccddeeff|/"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "Content-Type must be application/json for JSON request bodies"
    );

    let missing_content_type = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Gamma.bin|1|0123456789abcdeffedcba9876543210|/"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_content_type.status(), StatusCode::BAD_REQUEST);

    let empty_without_content_type = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_without_content_type.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(empty_without_content_type.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_ne!(
        value["error"]["message"],
        "Content-Type must be application/json for JSON request bodies"
    );

    let accepted = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json; charset=utf-8")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Beta.bin|1|ffeeddccbbaa99887766554433221100|/"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_routes_reject_request_bodies_after_route_query_validation() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/searches?confirm=true")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "DELETE request bodies are not supported"
    );

    let without_content_type = test_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/searches?confirm=true")
                .header("X-API-Key", "secret")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(without_content_type.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(without_content_type.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["error"]["message"],
        "DELETE request bodies are not supported"
    );

    let query_error = test_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/searches?unsupportedQuery=true")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(query_error.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(query_error.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["error"]["message"],
        "unknown query parameter: unsupportedQuery"
    );

    let unknown_route = test_router()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/unknown")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_route.status(), StatusCode::NOT_FOUND);

    let method_not_allowed = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/app")
                .header("X-API-Key", "secret")
                .header("Content-Type", "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(method_not_allowed.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn query_routes_use_canonical_error_envelope() {
    let cases = [
        ("GET", "/api/v1/snapshot?unsupportedQuery=true"),
        ("GET", "/api/v1/searches/search-1?unsupportedQuery=true"),
        ("DELETE", "/api/v1/searches?unsupportedQuery=true"),
        ("GET", "/api/v1/shared-files?unsupportedQuery=true"),
        (
            "DELETE",
            "/api/v1/shared-files/00112233445566778899aabbccddeeff/file?unsupportedQuery=true",
        ),
        ("GET", "/api/v1/transfers?unsupportedQuery=true"),
        ("GET", "/api/v1/upload-queue?unsupportedQuery=true"),
        ("GET", "/api/v1/logs?unsupportedQuery=true"),
        ("GET", "/api/v1/app?unsupportedQuery=true"),
        ("GET", "/api/v1/uploads?unsupportedQuery=true"),
        ("POST", "/api/v1/kad/operations/start?unsupportedQuery=true"),
        (
            "DELETE",
            "/api/v1/transfers/00112233445566778899aabbccddeeff/files?unsupportedQuery=true",
        ),
    ];
    for (method, uri) in cases {
        assert_invalid_query_response(test_router(), method, uri).await;
    }

    let allowed = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/uploads")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);

    let allowed_query = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue?includeScoreBreakdown=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed_query.status(), StatusCode::OK);

    let decoded_allowed_query = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue?includeScore%42reakdown=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decoded_allowed_query.status(), StatusCode::OK);

    let decoded_unknown_query = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue?unsupported%51uery=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(decoded_unknown_query.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(decoded_unknown_query.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["error"]["message"],
        "unknown query parameter: unsupportedQuery"
    );

    let duplicate_query = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue?limit=1&limit=2")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate_query.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(duplicate_query.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value["error"]["message"],
        "duplicate query parameter: limit"
    );

    let unknown_operation = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(
                    "/api/v1/transfers/00112233445566778899aabbccddeeff/operations/unknown?unsupportedQuery=true",
                )
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_operation.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_missing_api_key() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/app")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "UNAUTHORIZED");
    assert_eq!(value["error"]["details"], json!({}));
}

#[tokio::test]
async fn method_not_allowed_sets_allow_header_and_error_envelope() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/app")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    // The Allow header must advertise the method registered for this path.
    let allow = response
        .headers()
        .get(header::ALLOW)
        .expect("405 must carry an Allow header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(allow.contains("GET"), "Allow header was {allow}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "METHOD_NOT_ALLOWED");
    assert_eq!(
        value["error"]["message"],
        "HTTP method is not allowed for this API route"
    );
    assert_eq!(value["error"]["details"], json!({}));
}

#[tokio::test]
async fn pagination_rejects_out_of_range_bounds_with_details() {
    async fn error_value(uri: &str) -> (StatusCode, Value) {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    // limit above the maximum.
    let (status, value) = error_value("/api/v1/transfers?limit=5000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], "limit is out of range");
    assert_eq!(value["error"]["details"]["field"], "limit");
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");

    // limit below the minimum is rejected, not clamped.
    let (status, value) = error_value("/api/v1/transfers?limit=0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");

    // offset above INT_MAX.
    let (status, value) = error_value("/api/v1/transfers?offset=2147483648").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["message"], "offset is out of range");
    assert_eq!(value["error"]["details"]["field"], "offset");
    assert_eq!(value["error"]["details"]["constraint"], "0..2147483647");

    // Valid pagination succeeds.
    let (status, _value) = error_value("/api/v1/transfers?limit=10&offset=5").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn transfers_reject_unknown_state_query_values() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers?state=bogus")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "state must be one of downloading, paused, queued, checking, completing, completed, error, missingfiles"
    );

    let accepted = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers?state=paused")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}
