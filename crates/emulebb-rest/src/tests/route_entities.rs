use crate::rest_test_support::*;

#[tokio::test]
async fn servers_use_canonical_crud_routes() {
    let app = test_router();
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/servers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"address":"  192.0.2.20  ","port":4661,"name":"local","priority":"low","static":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"].get("endpoint").is_none());
    assert_eq!(value["data"]["address"], "192.0.2.20");
    assert_eq!(value["data"]["port"], 4661);
    assert_eq!(value["data"]["priority"], "low");
    assert_eq!(value["data"]["static"], true);

    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"renamed","priority":"high"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["name"], "renamed");
    assert_eq!(value["data"]["priority"], "high");

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    let missing = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn categories_use_canonical_crud_routes() {
    let runtime_dir = unique_test_dir("categories");
    let app = test_router();

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/categories")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"][0]["id"], 0);

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/categories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"name":" Media ","path":"{}","comment":"queue","color":65280,"priority":"high"}}"#,
                    runtime_dir.display().to_string().replace('\\', "\\\\")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["id"], 1);
    assert_eq!(value["data"]["name"], "Media");
    assert_eq!(value["data"]["priority"], 2);
    assert_eq!(value["data"]["color"], 65280);

    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/categories/1")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"Archive","path":null,"color":null,"priority":"verylow"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["name"], "Archive");
    assert_eq!(value["data"]["path"], Value::Null);
    assert_eq!(value["data"]["color"], Value::Null);
    assert_eq!(value["data"]["priority"], 4);

    let protected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/categories/0")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(protected.status(), StatusCode::BAD_REQUEST);

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/categories/1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    let missing = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/categories/1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn friends_use_canonical_crud_routes() {
    let app = test_router();
    let user_hash = "00112233445566778899aabbccddeeff";

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/friends")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/friends")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"userHash":"{user_hash}","name":"Harness Peer"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["userHash"], user_hash);
    assert_eq!(value["data"]["name"], "Harness Peer");
    assert_eq!(value["data"]["lastSeen"], Value::Null);
    assert_eq!(value["data"]["address"], Value::Null);
    assert_eq!(value["data"]["port"], 0);

    let duplicate = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/friends")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"userHash":"{user_hash}","name":"Ignored Rename"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    let body = to_bytes(duplicate.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["name"], "Harness Peer");

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/friends")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"userHash":"00112233445566778899AABBCCDDEEFF"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/friends/{user_hash}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    let missing = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/friends/{user_hash}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn search_clear_requires_canonical_query_confirmation() {
    let app = test_router();

    for query in ["first", "second"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/searches")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"query":"{query}","method":"automatic","type":""}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let cleared = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/searches?confirm=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn search_results_use_canonical_paging_query() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Paged.Result.One.iso".to_string(),
        size_bytes: 42,
        content_type: "iso".to_string(),
        availability_score: 2,
    })
    .await
    .unwrap();
    core.index_file(IndexedFile {
        ed2k_hash: "ffeeddccbbaa99887766554433221100".to_string(),
        name: "Paged.Result.Two.iso".to_string(),
        size_bytes: 84,
        content_type: "iso".to_string(),
        availability_score: 3,
    })
    .await
    .unwrap();
    let app = router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
        },
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"query":"  paged\tresult  ","method":"automatic","type":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["query"], "paged result");
    let search_id = value["data"]["id"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/searches/{search_id}?offset=1&limit=1&includeEvidence=false&exactTotal=true"
                ))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["id"], search_id);
    // The eMuleBB master returns paged search results under "items" with
    // total/offset/limit (search/results shares the common page shape).
    assert_eq!(value["data"]["total"], 2);
    assert_eq!(value["data"]["offset"], 1);
    assert_eq!(value["data"]["limit"], 1);
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);

    // An out-of-range limit is rejected (matching the emulebb master), not
    // silently clamped, and carries field/constraint details.
    let rejected = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/searches/{search_id}?limit=5000"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(rejected.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], "limit is out of range");
    assert_eq!(value["error"]["details"]["field"], "limit");
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");
}

#[tokio::test]
async fn search_to_download_flow_uses_local_index() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Indexed.Result.iso".to_string(),
        size_bytes: 42,
        content_type: "iso".to_string(),
        availability_score: 2,
    })
    .await
    .unwrap();
    let app = router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
        },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"query":"indexed result","method":"automatic","type":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let search_id = value["data"]["id"].as_str().unwrap();
    // search/start returns an empty first page; the seeded index result is
    // still recorded on the search and downloadable by hash.
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

    let download_uri = format!(
        "/api/v1/searches/{search_id}/results/00112233445566778899aabbccddeeff/operations/download"
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(download_uri)
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["searchId"], search_id);
    assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");
}

#[tokio::test]
async fn search_result_download_accepts_paused_request_body() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.index_file(IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Paused.Indexed.Result.iso".to_string(),
        size_bytes: 42,
        content_type: "iso".to_string(),
        availability_score: 2,
    })
    .await
    .unwrap();
    let app = router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
        },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"query":"paused indexed","method":"automatic","type":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let search_id = value["data"]["id"].as_str().unwrap();

    let download_uri = format!(
        "/api/v1/searches/{search_id}/results/00112233445566778899aabbccddeeff/operations/download"
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(download_uri)
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"paused":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["searchId"], search_id);
    assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");
}
