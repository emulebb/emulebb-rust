use crate::rest_test_support::*;

#[tokio::test]
async fn category_id_body_uses_mfc_unsigned_validation() {
    let app = test_router();
    let routes = [
        ("POST", "/api/v1/transfers", r#"{"categoryId":%s}"#),
        (
            "PATCH",
            "/api/v1/transfers/00112233445566778899aabbccddeeff",
            r#"{"categoryId":%s}"#,
        ),
        (
            "POST",
            "/api/v1/searches/search-1/results/00112233445566778899aabbccddeeff/operations/download",
            r#"{"categoryId":%s}"#,
        ),
    ];
    let cases = [
        (r#""1""#, "categoryId must be an unsigned number"),
        ("-1", "categoryId must be an unsigned number"),
        ("null", "categoryId must be an unsigned number"),
        ("4294967296", "categoryId is out of range"),
    ];

    for (method, uri, body_template) in routes {
        for (value, expected_message) in cases {
            let body = body_template.replace("%s", value);
            assert_invalid_json_response(app.clone(), method, uri, body, expected_message).await;
        }
    }
}

#[tokio::test]
async fn paused_body_uses_mfc_boolean_validation() {
    let app = test_router();
    let link = "ed2k://|file|PausedBody.bin|1|00112233445566778899aabbccddeeff|/";
    let cases = [r#""true""#, "1", "null"];

    for value in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            format!(r#"{{"link":"{link}","paused":{value}}}"#),
            "paused must be a boolean",
        )
        .await;
    }

    for value in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/searches/search-1/results/00112233445566778899aabbccddeeff/operations/download",
            format!(r#"{{"paused":{value}}}"#),
            "paused must be a boolean",
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_body_keeps_mfc_link_validation_before_paused() {
    let app = test_router();
    let link = "ed2k://|file|PausedOrder.bin|1|00112233445566778899aabbccddeeff|/";
    let cases = [
        (
            r#"{"paused":"true"}"#.to_string(),
            "link or links is required",
        ),
        (
            format!(r#"{{"link":"{link}","links":[],"paused":"true"}}"#),
            "link and links are mutually exclusive",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body.to_string(),
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_link_body_uses_mfc_shape_validation() {
    let app = test_router();
    let cases = [
        (r#"{"link":1}"#.to_string(), "link must be a string"),
        (r#"{"link":"   "}"#.to_string(), "link must not be empty"),
        (
            r#"{"link":"ed2k://|file|Bad Link.bin|1|00112233445566778899aabbccddeeff|/"}"#
                .to_string(),
            "link must not contain whitespace",
        ),
        (
            r#"{"link":"http://example.invalid/file"}"#.to_string(),
            "link must start with ed2k://",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body,
            expected_message,
        )
        .await;
    }
}

#[tokio::test]
async fn transfer_add_links_body_uses_mfc_array_validation() {
    let app = test_router();
    let too_many_links = std::iter::repeat_n(
        r#""ed2k://|file|Many.bin|1|00112233445566778899aabbccddeeff|/""#,
        101,
    )
    .collect::<Vec<_>>()
    .join(",");
    let cases = [
        (
            r#"{"links":"ed2k://"}"#.to_string(),
            "links must be a string array",
        ),
        (r#"{"links":[]}"#.to_string(), "links must not be empty"),
        (
            r#"{"links":[1]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            r#"{"links":[""]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            r#"{"links":["not-ed2k"]}"#.to_string(),
            "links must be a non-empty string array",
        ),
        (
            format!(r#"{{"links":[{too_many_links}]}}"#),
            "links contains too many items",
        ),
    ];

    for (body, expected_message) in cases {
        assert_invalid_json_response(
            app.clone(),
            "POST",
            "/api/v1/transfers",
            body,
            expected_message,
        )
        .await;
    }
}
