use crate::rest_test_support::*;

async fn known(app: &Router, byte: u8) -> String {
    let hash = format!("{byte:02x}").repeat(16);
    let (status, _) = request(app,"POST","/api/v1/downloads",Some(json!({
        "source":{"type":"content","hash":hash,"name":"Sample.bin","sizeBytes":123},"intent":"stopped"
    }))).await;
    assert_eq!(status, StatusCode::CREATED);
    hash
}

#[tokio::test]
async fn tags_have_name_identity_creation_location_and_case_insensitive_conflicts() {
    let app = test_router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/library/tags")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"Media-1"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response.headers()[header::LOCATION],
        "/api/v1/library/tags/Media-1"
    );
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
    assert_eq!(body["data"], json!({"name":"Media-1"}));
    let (status, duplicate) = request(
        &app,
        "POST",
        "/api/v1/library/tags",
        Some(json!({"name":"MEDIA-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(duplicate["error"]["code"], "TAG_NAME_CONFLICT");
    let (status, read) = request(&app, "GET", "/api/v1/library/tags/media-1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["data"], body["data"]);
    assert_eq!(
        request(&app, "DELETE", "/api/v1/library/tags/MEDIA-1", None).await,
        (StatusCode::NO_CONTENT, Value::Null)
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/library/tags/Media-1", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn tag_pages_have_scoped_live_continuations_and_default_one_hundred_rows() {
    let app = test_router();
    let hash = known(&app, 1).await;
    for index in 0..102 {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/library/tags",
                Some(json!({"name":format!("Tag-{index:03}")}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    let (status, first) = request(&app, "GET", "/api/v1/library/tags", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["data"].as_array().unwrap().len(), 100);
    assert_eq!(first["meta"]["hasMore"], true);
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    request(&app, "DELETE", "/api/v1/library/tags/Tag-099", None).await;
    let (status, last) = request(
        &app,
        "GET",
        &format!("/api/v1/library/tags?cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(last["data"], json!([{"name":"Tag-100"},{"name":"Tag-101"}]));
    assert_eq!(last["meta"]["hasMore"], false);
    assert!(last["meta"]["nextCursor"].is_null());
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/library/files/{hash}/tags?cursor={cursor}"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    for query in [
        "limit=0",
        "limit=201",
        "limit=1&limit=2",
        "unknown=1",
        "cursor=bad",
        "cursor=00",
    ] {
        assert_eq!(
            request(&app, "GET", &format!("/api/v1/library/tags?{query}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
}

#[tokio::test]
async fn tag_bulk_actions_report_ordered_hash_outcomes_without_affecting_jobs() {
    let app = test_router();
    let first = known(&app, 1).await;
    let second = known(&app, 2).await;
    let missing = "ff".repeat(16);
    request(
        &app,
        "POST",
        "/api/v1/library/tags",
        Some(json!({"name":"Rotate"})),
    )
    .await;
    let (status, assigned) = request(
        &app,
        "POST",
        "/api/v1/library/files/tags/add",
        Some(json!({"tag":"rotate","hashes":[first,missing,second]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(
        assigned["data"],
        json!([
            {"hash":first,"status":"accepted","httpStatus":200},
            {"hash":missing,"status":"failed","httpStatus":404,"error":{"code":"NOT_FOUND","message":"library file not found","details":{}}},
            {"hash":second,"status":"accepted","httpStatus":200}
        ])
    );
    let (status, unchanged) = request(
        &app,
        "POST",
        "/api/v1/library/files/tags/add",
        Some(json!({"tag":"Rotate","hashes":[first]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(
        unchanged["data"][0],
        json!({"hash":first,"status":"unchanged","httpStatus":200})
    );
    let (status, tags) = request(
        &app,
        "GET",
        &format!("/api/v1/library/files/{first}/tags"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tags["data"], json!([{"name":"Rotate"}]));
    let (status, removed) = request(
        &app,
        "POST",
        "/api/v1/library/files/tags/remove",
        Some(json!({"tag":"Rotate","hashes":[first]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(removed["data"][0]["status"], "accepted");
    request(&app, "DELETE", "/api/v1/library/tags/Rotate", None).await;
    let (_, tags) = request(
        &app,
        "GET",
        &format!("/api/v1/library/files/{second}/tags"),
        None,
    )
    .await;
    assert_eq!(tags["data"], json!([]));
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/library/files/{missing}/tags"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for id in ["1", "2"] {
        let (_, job) = request(&app, "GET", &format!("/api/v1/downloads/{id}"), None).await;
        assert_eq!(job["data"]["intent"], "stopped");
        assert!(job["data"]["category"].is_null());
    }
}

#[tokio::test]
async fn malformed_tag_batches_are_rejected_before_any_assignment() {
    let app = test_router();
    let hash = known(&app, 1).await;
    request(
        &app,
        "POST",
        "/api/v1/library/tags",
        Some(json!({"name":"Valid"})),
    )
    .await;
    for body in [
        json!({"tag":"Valid","hashes":[]}),
        json!({"tag":"Valid","hashes":[hash,hash]}),
        json!({"tag":"Valid","hashes":vec![hash.clone();101]}),
        json!({"tag":"Valid","hashes":[hash,"BAD"]}),
        json!({"tag":"Valid","hashes":[hash],"unexpected":true}),
        json!({"tag":"two words","hashes":[hash]}),
    ] {
        assert_eq!(
            request(&app, "POST", "/api/v1/library/files/tags/add", Some(body))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/library/files/tags/add",
            Some(json!({"tag":"Missing","hashes":[hash]}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, tags) = request(
        &app,
        "GET",
        &format!("/api/v1/library/files/{hash}/tags"),
        None,
    )
    .await;
    assert_eq!(tags["data"], json!([]));
    assert_eq!(
        request(&app, "GET", "/api/v1/library/tags/Missing", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}
