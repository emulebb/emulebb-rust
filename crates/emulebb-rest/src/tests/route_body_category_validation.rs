use crate::rest_test_support::{assert_invalid_json_response, test_router};

#[tokio::test]
async fn category_selector_uses_name_grammar() {
    let app = test_router();
    let routes = [
        (
            "POST",
            "/api/v1/downloads",
            r#"{"source":{"type":"content","hash":"00112233445566778899aabbccddeeff","name":"A.bin","sizeBytes":1},"category":%s}"#,
        ),
        ("PATCH", "/api/v1/downloads/1", r#"{"category":%s}"#),
        (
            "POST",
            "/api/v1/searches/1/results/1/download",
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
