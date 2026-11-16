use crate::rest_test_support::{assert_invalid_json_response, test_router};

#[tokio::test]
async fn category_selector_uses_name_grammar() {
    let app = test_router();
    let routes = [
        (
            "POST",
            "/api/v1/transfers",
            r#"{"link":"ed2k://|file|A.bin|1|00112233445566778899aabbccddeeff|/","category":%s}"#,
        ),
        (
            "PATCH",
            "/api/v1/transfers/00112233445566778899aabbccddeeff",
            r#"{"category":%s}"#,
        ),
        (
            "POST",
            "/api/v1/searches/1/results/00112233445566778899aabbccddeeff/operations/download",
            r#"{"category":%s}"#,
        ),
    ];
    for (value, message) in [
        ("1", "category must be a string or null"),
        (r#""bad name""#, "category must be a valid category name"),
        (r#""-bad""#, "category must be a valid category name"),
    ] {
        for (method, uri, template) in routes {
            assert_invalid_json_response(
                app.clone(),
                method,
                uri,
                template.replace("%s", value),
                message,
            )
            .await;
        }
    }
}
