use super::*;
use crate::rest_test_support::*;

#[tokio::test]
async fn copyless_client_content_has_an_empty_location_page() {
    let app = test_router();
    let hash = known_library_hash(&app, 0x44).await;
    let (status, body) = request(
        &app,
        "GET",
        &format!("/api/v1/library/files/{hash}/locations"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], json!([]));
    assert_eq!(body["meta"]["hasMore"], false);
    assert!(body["meta"]["nextCursor"].is_null());
    assert!(body["meta"].get("total").is_none());
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/library/files/{}/locations", "ff".repeat(16)),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn location_query_validates_hash_limit_and_cursor_scope() {
    let app = test_router();
    let hash = known_library_hash(&app, 0x45).await;
    for path in [
        "/api/v1/library/files/bad/locations".into(),
        format!("/api/v1/library/files/{hash}/locations?limit=0"),
        format!("/api/v1/library/files/{hash}/locations?limit=201"),
        format!("/api/v1/library/files/{hash}/locations?cursor=bad"),
        format!(
            "/api/v1/library/files/{hash}/locations?cursor={}",
            encode_cursor("library-locations:other", "1")
        ),
        format!(
            "/api/v1/library/files/{hash}/locations?cursor={}",
            encode_cursor(&format!("library-locations:{hash}"), "0")
        ),
    ] {
        let (status, body) = request(&app, "GET", &path, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body["error"]["code"], "INVALID_ARGUMENT");
    }
}
