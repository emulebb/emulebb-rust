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
async fn category_id_path_uses_mfc_unsigned_validation() {
    let cases = [
        (
            "/api/v1/categories/abc",
            "categoryId must be an unsigned decimal string",
        ),
        (
            "/api/v1/categories/-1",
            "categoryId must be an unsigned decimal string",
        ),
        (
            "/api/v1/categories/4294967296",
            "categoryId is out of range",
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
async fn hash_path_parameters_use_mfc_lowercase_hex_validation() {
    let cases = [
        (
            "GET",
            "/api/v1/transfers/00112233445566778899AABBCCDDEEFF",
            "hash must be a 32-character lowercase hex string",
        ),
        (
            "GET",
            "/api/v1/shared-files/abc",
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
async fn endpoint_path_parameters_use_mfc_address_port_validation() {
    let cases = [
        (
            "GET",
            "/api/v1/servers/local",
            "serverId must use address:port with a port in the range 1..65535",
        ),
        (
            "GET",
            "/api/v1/servers/local:0",
            "serverId must use address:port with a port in the range 1..65535",
        ),
        (
            "GET",
            "/api/v1/uploads/client",
            "clientId must be a 32-character lowercase hex string or address:port",
        ),
        (
            "GET",
            "/api/v1/upload-queue/192.0.2.1:0",
            "clientId must be a 32-character lowercase hex string or address:port",
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
        ("GET", "/api/v1/categories/0"),
        ("GET", "/api/v1/servers/local:4661"),
        ("GET", "/api/v1/uploads/192.0.2.1:4662"),
        ("GET", "/api/v1/transfers/00112233445566778899aabbccddeeff"),
    ];
    for (method, uri) in accepted_routes {
        let (status, value) = path_error_value(method, uri).await;
        assert_ne!(status, StatusCode::BAD_REQUEST, "{method} {uri}: {value}");
    }
}
