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
async fn all_limited_routes_reject_out_of_range_limit_like_mfc() {
    for uri in [
        "/api/v1/snapshot?limit=0",
        "/api/v1/logs?limit=5000",
        "/api/v1/shared-files?limit=0",
        "/api/v1/upload-queue?limit=5000",
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
async fn transfers_category_id_query_uses_mfc_unsigned_validation() {
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
