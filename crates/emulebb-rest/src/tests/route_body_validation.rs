use crate::rest_test_support::*;

#[tokio::test]
async fn category_create_body_uses_canonical_validation() {
    let app = test_router();
    let cases = [
        (r#"{}"#, "name must be a non-empty string"),
        (
            r#"{"name":"Media","tempDir":1}"#,
            "tempDir must be a non-empty string path",
        ),
        (
            r#"{"name":"Media","destinationDir":"   "}"#,
            "destinationDir must not be empty",
        ),
        (
            r#"{"name":"Media","comment":1}"#,
            "comment must be a string",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/categories",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn category_patch_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/categories/Media";
    let cases = [
        (r#"{}"#, "category PATCH requires at least one field"),
        (
            r#"{"tempDir":1}"#,
            "tempDir must be a non-empty string path",
        ),
        (
            r#"{"destinationDir":"   "}"#,
            "destinationDir must not be empty",
        ),
        (r#"{"comment":1}"#, "comment must be a string"),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn friend_create_body_uses_canonical_validation() {
    let app = test_router();
    let user_hash = "00112233445566778899aabbccddeeff";
    let long_name = "a".repeat(129);
    let cases = [
        (
            r#"{}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":1}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":"00112233445566778899AABBCCDDEEFF"}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            r#"{"userHash":"00112233445566778899aabbccddee"}"#.to_string(),
            "userHash must be a 32-character lowercase hex string",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":1}}"#),
            "name must be a string",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":"bad\u0001name"}}"#),
            "name must be valid UTF-8 without control characters",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","name":"{long_name}"}}"#),
            "name must be at most 128 characters",
        ),
        (
            format!(r#"{{"userHash":"{user_hash}","browseKeySha256":"bad"}}"#),
            "browseKeySha256 must be a 64-character hex string",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/friends",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn search_create_body_uses_canonical_validation() {
    let app = test_router();
    let long_query = "a".repeat(161);
    let cases = [
        (r#"{}"#.to_string(), "query must be a string"),
        (r#"{"query":1}"#.to_string(), "query must be a string"),
        (
            r#"{"query":"   \t   "}"#.to_string(),
            "query must not be empty",
        ),
        (
            r#"{"query":"bad\u0001query"}"#.to_string(),
            "query must be valid UTF-8 without control characters",
        ),
        (
            format!(r#"{{"query":"{long_query}"}}"#),
            "query must be at most 160 characters",
        ),
        (
            r#"{"query":"sample","method":1}"#.to_string(),
            "method must be a string",
        ),
        (
            r#"{"query":"sample","method":"local"}"#.to_string(),
            "method must be one of automatic, server, global, kad",
        ),
        (
            r#"{"query":"sample","type":1}"#.to_string(),
            "type must be a string",
        ),
        (
            r#"{"query":"sample","type":"archive"}"#.to_string(),
            "type is not supported",
        ),
        (
            r#"{"query":"sample","extension":1}"#.to_string(),
            "extension must be a string",
        ),
        (
            r#"{"query":"sample","minSizeBytes":"1"}"#.to_string(),
            "minSizeBytes must be an unsigned number",
        ),
        (
            r#"{"query":"sample","maxSizeBytes":-1}"#.to_string(),
            "maxSizeBytes must be an unsigned number",
        ),
        (
            r#"{"query":"sample","minSizeBytes":10,"maxSizeBytes":9}"#.to_string(),
            "maxSizeBytes must be greater than or equal to minSizeBytes",
        ),
        (
            r#"{"query":"sample","minAvailability":"1"}"#.to_string(),
            "minAvailability must be an unsigned number",
        ),
        (
            r#"{"query":"sample","minAvailability":1000001}"#.to_string(),
            "minAvailability must be an unsigned number in the range 0..1000000",
        ),
        (
            r#"{"query":"sample","artist":1}"#.to_string(),
            "artist must be a string",
        ),
        (
            r#"{"query":"sample","codec":"bad\u0001codec"}"#.to_string(),
            "codec must not contain control characters",
        ),
        (
            r#"{"query":"sample","minCompleteSources":1000001}"#.to_string(),
            "minCompleteSources must be an unsigned number in the range 0..1000000",
        ),
        (
            r#"{"query":"sample","minBitrateKbps":4294967296}"#.to_string(),
            "minBitrateKbps must be an unsigned 32-bit number",
        ),
        (
            r#"{"query":"sample","minLengthSeconds":"60"}"#.to_string(),
            "minLengthSeconds must be an unsigned number",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/searches",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn settings_patch_requires_the_current_revision_and_typed_document_shape() {
    let app = test_router();
    for body in [
        r#"{}"#,
        r#"{"expectedRevision":"1"}"#,
        r#"{"expectedRevision":1,"set":{"network":{"nickname":"Sample"}}}"#,
        r#"{"expectedRevision":"1","set":{"network":{"nat":{"enabled":null}}}}"#,
        r#"{"expectedRevision":"1","set":{"network":{"p2p":{"tcpPort":"20019"}}}}"#,
        r#"{"expectedRevision":"1","set":{"network":[]}}"#,
        r#"{"expectedRevision":"1","reset":["network.nickname","network.nickname"]}"#,
        r#"{"expectedRevision":"1","set":{"network":{"nickname":"Sample"}},"reset":["network.nickname"]}"#,
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/settings")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["error"]["code"], "INVALID_ARGUMENT");
    }
}

#[tokio::test]
async fn library_file_patch_body_uses_canonical_priority_validation() {
    let app = test_router();
    let uri = "/api/v1/library/files/00112233445566778899aabbccddeeff";
    let cases = [
        (
            r#"{}"#,
            "library file PATCH requires uploadPriority, comment, or rating",
        ),
        (r#"{"uploadPriority":1}"#, "uploadPriority must be a string"),
        (
            r#"{"uploadPriority":"urgent"}"#,
            "uploadPriority must be one of auto, verylow, low, normal, high, release",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn library_file_patch_body_uses_canonical_comment_rating_validation() {
    let app = test_router();
    let uri = "/api/v1/library/files/00112233445566778899aabbccddeeff";
    let cases = [
        (r#"{"rating":5}"#, "comment must be a string"),
        (r#"{"comment":1,"rating":5}"#, "comment must be a string"),
        (
            r#"{"comment":"verified"}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":"5"}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":6}"#,
            "rating must be an integer between 0 and 5",
        ),
        (
            r#"{"comment":"verified","rating":-1}"#,
            "rating must be an integer between 0 and 5",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn library_root_patch_requires_a_boolean_watch_policy() {
    let app = test_router();
    for body in [
        r#"{}"#,
        r#"{"watchEnabled":null}"#,
        r#"{"watchEnabled":1}"#,
        r#"{"watchEnabled":"true"}"#,
    ] {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            "/api/v1/library/roots/1",
            body.to_string(),
            "watchEnabled must be a boolean",
        )
        .await;
    }
}

#[tokio::test]
async fn library_root_create_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/library/roots";
    let cases = [
        (r#"{}"#, "path must be a non-empty string path"),
        (r#"{"path":1}"#, "path must be a non-empty string path"),
        (r#"{"path":"   "}"#, "path must not be empty"),
        (
            r#"{"path":"C:/Shared","unexpected":true}"#,
            "unknown JSON field: unexpected",
        ),
        (
            r#"{"path":"C:/Shared","watchEnabled":null}"#,
            "watchEnabled must be a boolean",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), "POST", uri, body.to_string(), expected_message)
            .await;
    }
}

#[tokio::test]
async fn shared_file_ignore_pattern_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/library/ignores";
    let cases = [
        (r#"{}"#, "pattern must be a non-empty string"),
        (r#"{"pattern":1}"#, "pattern must be a non-empty string"),
        (r#"{"pattern":""}"#, "pattern must be a non-empty string"),
        (
            r#"{"pattern":"*.private.bin","recursive":true}"#,
            "unknown JSON field: recursive",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), "POST", uri, body.to_string(), expected_message)
            .await;
    }
}

#[tokio::test]
async fn shared_file_ignore_rule_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/library/ignores/defaults/temporary-file";
    let cases = [
        (r#"{}"#, "enabled is required"),
        (r#"{"enabled":"true"}"#, "enabled must be a boolean"),
        (
            r#"{"enabled":true,"pattern":"*.tmp"}"#,
            "unknown JSON field: pattern",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn destructive_confirmation_bodies_use_canonical_validation() {
    let app = test_router();
    let cases = [
        (
            "POST",
            "/api/v1/app/shutdown",
            r#"{}"#,
            "confirmShutdown must be true",
        ),
        (
            "POST",
            "/api/v1/diagnostics/bundles",
            r#"{"confirmCapture":false,"maxBytes":4194304}"#,
            "confirmCapture must be true",
        ),
        (
            "POST",
            "/api/v1/diagnostics/crash-tests",
            r#"{"confirmCrash":"true"}"#,
            "confirmCrash must be true",
        ),
        (
            "POST",
            "/api/v1/logs/operations/clear",
            r#"{"confirmClearLogs":false}"#,
            "confirmClearLogs must be true",
        ),
    ];

    for (method, uri, body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), method, uri, body.to_string(), expected_message)
            .await;
    }
}

#[tokio::test]
async fn server_create_body_uses_canonical_validation() {
    let app = test_router();
    let cases = [
        (r#"{}"#, "address must be a non-empty string"),
        (
            r#"{"address":1,"port":4661}"#,
            "address must be a non-empty string",
        ),
        (
            r#"{"address":"   ","port":4661}"#,
            "address must not be empty",
        ),
        (
            r#"{"address":"127.0.0.1"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":"4661"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":0}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":65536}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"priority":1}"#,
            "priority must be a string",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"priority":"urgent"}"#,
            "priority must be one of low, normal, high",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"static":"true"}"#,
            "static must be a boolean",
        ),
        (
            r#"{"address":"127.0.0.1","port":4661,"enabled":"true"}"#,
            "enabled must be a boolean",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/servers",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn server_patch_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/servers/1";
    let cases = [
        (
            r#"{}"#,
            "server PATCH requires priority, static, or enabled",
        ),
        (r#"{"priority":1}"#, "priority must be a string"),
        (
            r#"{"priority":"release"}"#,
            "priority must be one of low, normal, high",
        ),
        (r#"{"static":"true"}"#, "static must be a boolean"),
        (r#"{"enabled":"true"}"#, "enabled must be a boolean"),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "PATCH",
            uri,
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn url_import_body_uses_canonical_validation() {
    let app = test_router();
    let routes = [
        "POST /api/v1/servers/operations/import-met-url",
        "POST /api/v1/kad/operations/import-nodes-url",
    ];
    let cases = [
        (r#"{}"#, "url must be a non-empty string"),
        (r#"{"url":1}"#, "url must be a non-empty string"),
        (r#"{"url":"   "}"#, "url must not be empty"),
        (
            r#"{"url":"http://example.invalid/\u0001"}"#,
            "url must be valid UTF-8 without control characters",
        ),
        (
            r#"{"url":"http://example.invalid/file name"}"#,
            "url must not contain whitespace",
        ),
        (
            r#"{"url":"ftp://example.invalid/nodes.dat"}"#,
            "url must start with http:// or https://",
        ),
        (r#"{"url":"http:///nodes.dat"}"#, "url must include a host"),
        (r#"{"url":"https://#fragment"}"#, "url must include a host"),
    ];

    for route in routes {
        let (method, uri) = route.split_once(' ').unwrap();
        for (body, expected_message) in cases {
            assert_invalid_json_response(
                app.clone(),
                method,
                uri,
                body.to_string(),
                expected_message,
            )
            .await;
        }
    }
}

#[tokio::test]
async fn kad_bootstrap_body_uses_canonical_validation() {
    let app = test_router();
    let uri = "/api/v1/kad/operations/bootstrap";
    let cases = [
        (r#"{}"#, "address must be a non-empty string"),
        (
            r#"{"address":1,"port":4672}"#,
            "address must be a non-empty string",
        ),
        (
            r#"{"address":"   ","port":4672}"#,
            "address must not be empty",
        ),
        (
            r#"{"address":"203.0.113.10"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":"4672"}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":0}"#,
            "port must be in the range 1..65535",
        ),
        (
            r#"{"address":"203.0.113.10","port":65536}"#,
            "port must be in the range 1..65535",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(app.clone(), "POST", uri, body.to_string(), expected_message)
            .await;
    }
}
