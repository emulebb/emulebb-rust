use crate::rest_test_support::*;

async fn path_error_value(method: &str, uri: &str) -> (StatusCode, Value) {
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
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn category_path_uses_name_validation() {
    let cases = [
        (
            "/api/v1/categories/-invalid",
            "categoryName must be a valid category name",
        ),
        (
            "/api/v1/categories/invalid_name",
            "categoryName must be a valid category name",
        ),
        (
            "/api/v1/categories/invalid.name",
            "categoryName must be a valid category name",
        ),
    ];
    for (uri, expected_message) in cases {
        let (status, value) = path_error_value("GET", uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
        assert_eq!(value["error"]["details"], json!({}));
    }
}

#[tokio::test]
async fn search_id_path_uses_positive_exact_i64_validation() {
    let cases = [
        (
            "GET",
            "/api/v1/searches/0",
            "searchId must be a positive decimal i64 string",
        ),
        (
            "DELETE",
            "/api/v1/searches/01",
            "searchId must be a positive decimal i64 string",
        ),
        (
            "POST",
            "/api/v1/searches/9223372036854775808/results/1/download",
            "searchId must be a positive decimal i64 string",
        ),
    ];
    for (method, uri, expected_message) in cases {
        let (status, value) = path_error_value(method, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
        assert_eq!(value["error"]["details"], json!({}));
    }
}

#[tokio::test]
async fn result_ids_use_exact_positive_i64_and_reach_lookup() {
    for id in ["0", "01", "-1", "9223372036854775808"] {
        let (status, value) =
            path_error_value("POST", &format!("/api/v1/searches/1/results/{id}/download")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            value["error"]["message"],
            "resultId must be a positive decimal i64 string"
        );
    }
    for id in ["4294967296", "9007199254740993", "9223372036854775807"] {
        let (status, _) =
            path_error_value("POST", &format!("/api/v1/searches/1/results/{id}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn full_i64_search_ids_reach_resource_lookup_without_number_rounding() {
    for id in ["4294967296", "9007199254740993", "9223372036854775807"] {
        let (status, _) = path_error_value("GET", &format!("/api/v1/searches/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn hash_path_parameters_use_canonical_lowercase_hex_validation() {
    let cases = [
        (
            "GET",
            "/api/v1/library/files/abc",
            "hash must be a 32-character lowercase hex string",
        ),
        (
            "DELETE",
            "/api/v1/friends/abc",
            "userHash must be a 32-character lowercase hex string",
        ),
    ];
    for (method, uri, expected_message) in cases {
        let (status, value) = path_error_value(method, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
    }
}

#[tokio::test]
async fn resource_path_parameters_use_canonical_identity_validation() {
    let cases = [
        (
            "GET",
            "/api/v1/servers/01",
            "serverId must be a positive decimal i64 string",
        ),
        (
            "GET",
            "/api/v1/servers/0",
            "serverId must be a positive decimal i64 string",
        ),
        (
            "GET",
            "/api/v1/uploads/not-a-uuid",
            "id must be a lowercase hyphenated UUID",
        ),
        (
            "GET",
            "/api/v1/upload-queue/not-a-uuid",
            "id must be a lowercase hyphenated UUID",
        ),
    ];
    for (method, uri, expected_message) in cases {
        let (status, value) = path_error_value(method, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
        assert_eq!(value["error"]["message"], expected_message);
    }
}

#[tokio::test]
async fn valid_path_parameters_still_reach_handlers() {
    let accepted_routes = [
        ("GET", "/api/v1/categories/Media"),
        ("GET", "/api/v1/searches/1"),
        ("GET", "/api/v1/servers/9223372036854775807"),
        ("POST", "/api/v1/servers/1/operations/connect"),
        (
            "GET",
            "/api/v1/uploads/12345678-1234-4234-8234-123456789abc",
        ),
        (
            "GET",
            "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc",
        ),
        ("GET", "/api/v1/downloads/1"),
    ];
    for (method, uri) in accepted_routes {
        let (status, value) = path_error_value(method, uri).await;
        assert_ne!(status, StatusCode::BAD_REQUEST, "{method} {uri}: {value}");
    }
}
