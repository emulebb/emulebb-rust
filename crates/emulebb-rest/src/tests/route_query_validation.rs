use crate::rest_test_support::*;

async fn query_error_value(uri: &str) -> (StatusCode, Value) {
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

#[tokio::test]
async fn pagination_rejects_out_of_range_bounds_with_details() {
    let (status, value) = query_error_value("/api/v1/transfers?limit=5000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], "limit is out of range");
    assert_eq!(value["error"]["details"]["field"], "limit");
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");

    let (status, value) = query_error_value("/api/v1/transfers?limit=0").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["message"], "limit is out of range");
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");

    let (status, value) = query_error_value("/api/v1/transfers?limit=-1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"]["message"],
        "limit must be an unsigned number"
    );
    assert_eq!(value["error"]["details"], json!({}));

    let (status, value) = query_error_value("/api/v1/transfers?limit=abc").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"]["message"],
        "limit must be an unsigned number"
    );

    let (status, value) = query_error_value("/api/v1/transfers?offset=2147483648").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["error"]["message"], "offset is out of range");
    assert_eq!(value["error"]["details"]["field"], "offset");
    assert_eq!(value["error"]["details"]["constraint"], "0..2147483647");

    let (status, value) = query_error_value("/api/v1/transfers?offset=-1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"]["message"],
        "offset must be an unsigned number"
    );

    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers?limit=10&offset=5")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn search_result_sort_query_is_strict() {
    for (uri, expected_message) in [
        (
            "/api/v1/searches/1?sort=availability",
            "sort must be one of name, sizeBytes, sources, completeSources, rating",
        ),
        (
            "/api/v1/searches/1?sort=sources&order=descending",
            "order must be one of asc, desc",
        ),
        ("/api/v1/searches/1?order=desc", "order requires sort"),
    ] {
        let (status, value) = query_error_value(uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(value["error"]["message"], expected_message);
    }
}

#[tokio::test]
async fn all_limited_routes_reject_out_of_range_limit_with_canonical_bounds() {
    for uri in [
        "/api/v1/snapshot?limit=0",
        "/api/v1/logs?limit=5000",
        "/api/v1/shared-files?limit=0",
        "/api/v1/upload-queue?limit=5000",
        "/api/v1/kad/nodes?limit=0",
    ] {
        let (status, value) = query_error_value(uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], "limit is out of range");
        assert_eq!(value["error"]["details"]["field"], "limit");
        assert_eq!(value["error"]["details"]["constraint"], "1..1000");
    }
}

#[tokio::test]
async fn shared_files_keyset_cursor_is_validated_and_exclusive_with_offset() {
    let (status, value) = query_error_value("/api/v1/shared-files?afterHash=abc&limit=10").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ED2K after hash")
    );

    let (status, value) = query_error_value(
        "/api/v1/shared-files?afterHash=00112233445566778899aabbccddeeff&offset=1",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["error"]["message"],
        "afterHash cannot be combined with a non-zero offset"
    );

    let (status, value) = query_error_value(
        "/api/v1/shared-files?afterHash=00112233445566778899aabbccddeeff&limit=10",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["data"]["nextAfterHash"], Value::Null);
}

#[tokio::test]
async fn transfers_category_id_query_uses_canonical_unsigned_validation() {
    let cases = [
        (
            "/api/v1/transfers?categoryId=-1",
            "categoryId must be an unsigned number",
        ),
        (
            "/api/v1/transfers?categoryId=abc",
            "categoryId must be an unsigned number",
        ),
        (
            "/api/v1/transfers?categoryId=4294967296",
            "categoryId is out of range",
        ),
    ];
    for (uri, expected_message) in cases {
        let (status, value) = query_error_value(uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
    }

    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers?categoryId=0")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn destructive_query_confirmations_use_canonical_validation() {
    let cases = [
        ("DELETE", "/api/v1/searches"),
        ("DELETE", "/api/v1/searches?confirm=false"),
        (
            "DELETE",
            "/api/v1/transfers/00112233445566778899aabbccddeeff/files",
        ),
    ];

    for (method, uri) in cases {
        let response = test_router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], "confirm must be true");
    }
}
