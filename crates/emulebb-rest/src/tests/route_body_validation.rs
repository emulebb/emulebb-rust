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
