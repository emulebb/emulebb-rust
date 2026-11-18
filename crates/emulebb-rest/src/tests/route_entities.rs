use crate::rest_test_support::*;

#[tokio::test]
async fn download_source_friend_routes_report_closed_persistence() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let (_, download) = core.create_download(serde_json::from_value(json!({
        "source":{"type":"ed2k-link","link":"ed2k://|file|Sample.bin|4096|00112233445566778899aabbccddeeff|sources,192.0.2.10:4662:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|/"},
        "intent":"stopped"
    })).unwrap()).await.unwrap();
    let id = download.id;
    drop(download);
    core.drain_persistence().await.unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    for action in ["add-friend", "remove-friend"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/api/v1/downloads/{}/sources/{}/operations/{action}",
                        id,
                        "aa".repeat(16)
                    ))
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING");
    }
}

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
    assert_eq!(value["data"]["enabled"], true);

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

    let disable = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"enabled":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disable.status(), StatusCode::OK);
    let body = to_bytes(disable.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);

    let enable = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enable.status(), StatusCode::OK);
    let body = to_bytes(enable.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], true);

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
    let body = to_bytes(delete.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);

    let disabled = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/servers/192.0.2.20:4661")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disabled.status(), StatusCode::OK);
    let body = to_bytes(disabled.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);
    assert_eq!(value["data"]["name"], "renamed");
}

#[tokio::test]
async fn categories_use_canonical_crud_routes() {
    let app = test_router();
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/categories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"name":"Media","tempDir":null,"destinationDir":null,"comment":"queue"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);
    let body = to_bytes(create.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["name"], "Media");
    assert!(value["data"]["tempDir"].is_null());
    let conflict = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/categories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"MEDIA"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let body = to_bytes(conflict.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "CATEGORY_NAME_CONFLICT");
    let updated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/categories/media")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"tempDir":null}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let deleted = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/categories/Media")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
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
    let app = test_search_router();

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
async fn search_delete_uses_canonical_ok_response() {
    let app = test_search_router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/searches")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"query":"delete single","method":"automatic","type":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let search_id = value["data"]["id"].as_str().unwrap();

    let deleted = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/searches/{search_id}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let body = to_bytes(deleted.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert!(value["data"].get("deleted").is_none());
}

#[tokio::test]
async fn search_results_use_canonical_paging_query() {
    let core = test_search_core(&[
        IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Paged.Result.One.iso".to_string(),
            size_bytes: 42,
            content_type: "iso".to_string(),
            availability_score: 2,
        },
        IndexedFile {
            ed2k_hash: "ffeeddccbbaa99887766554433221100".to_string(),
            name: "Paged.Result.Two.iso".to_string(),
            size_bytes: 84,
            content_type: "iso".to_string(),
            availability_score: 3,
        },
        IndexedFile {
            ed2k_hash: "11223344556677889900aabbccddeeff".to_string(),
            name: "Paged.Result.Three.iso".to_string(),
            size_bytes: 126,
            content_type: "iso".to_string(),
            availability_score: 4,
        },
    ]);
    let observed_search_id = core.searches().await.into_iter().next().unwrap().id;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
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
                    r#"{"query":"  paged\tresult  ","method":"automatic","type":"","extension":"iso","minSizeBytes":1,"maxSizeBytes":1000,"minAvailability":2,"minCompleteSources":0}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["query"], "paged result");
    assert_eq!(value["data"]["requestedMethod"], "automatic");
    assert_eq!(value["data"]["resolvedMethod"], Value::Null);
    assert!(value["data"].get("method").is_none());
    assert_eq!(value["data"]["criteria"]["extension"], "iso");
    assert_eq!(value["data"]["criteria"]["minSizeBytes"], 1);
    assert_eq!(value["data"]["criteria"]["maxSizeBytes"], 1000);
    assert_eq!(value["data"]["criteria"]["minAvailability"], 2);
    assert_eq!(value["data"]["criteria"]["minCompleteSources"], Value::Null);
    assert_eq!(value["data"]["criteria"]["minBitrateKbps"], Value::Null);
    assert_eq!(value["data"]["criteria"]["minLengthSeconds"], Value::Null);
    assert_eq!(value["data"]["criteria"]["codec"], "");
    assert_eq!(value["data"]["criteria"]["title"], "");
    assert_eq!(value["data"]["criteria"]["album"], "");
    assert_eq!(value["data"]["criteria"]["artist"], "");
    assert_eq!(value["data"]["progress"]["phase"], "queued");
    assert_eq!(value["data"]["progress"]["completedUnits"], 0);
    assert!(value["data"]["progress"].get("totalUnits").is_none());
    assert_eq!(value["data"]["progress"]["unit"], "");
    let created_id = value["data"]["id"].as_str().unwrap();
    let empty = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/searches/{created_id}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    let empty: Value =
        serde_json::from_slice(&to_bytes(empty.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(empty["data"]["total"], 0);
    assert_eq!(empty["data"]["items"], json!([]));
    let search_id = observed_search_id.as_str();

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
    assert_eq!(value["data"]["requestedMethod"], "automatic");
    assert_eq!(value["data"]["resolvedMethod"], "server");
    assert!(value["data"].get("method").is_none());
    assert_eq!(value["data"]["criteria"]["extension"], "iso");
    assert_eq!(value["data"]["criteria"]["artist"], "");
    assert!(value["data"]["progress"].is_object());
    // The eMuleBB master returns paged search results under "items" with
    // total/offset/limit (search/results shares the common page shape).
    assert_eq!(value["data"]["total"], 3);
    assert_eq!(value["data"]["offset"], 1);
    assert_eq!(value["data"]["limit"], 1);
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    assert!(value["data"]["items"][0].get("method").is_none());
    assert!(value["data"]["items"][0].get("knownType").is_none());
    assert!(value["data"]["items"][0].get("evidence").is_none());

    let sorted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/searches/{search_id}?sort=sizeBytes&order=desc&offset=0&limit=2"
                ))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sorted.status(), StatusCode::OK);
    let body = to_bytes(sorted.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["sort"], "sizeBytes");
    assert_eq!(value["data"]["order"], "desc");
    assert_eq!(value["data"]["items"][0]["sizeBytes"], 126);
    assert_eq!(value["data"]["items"][1]["sizeBytes"], 84);

    let estimated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/searches/{search_id}?offset=0&limit=1&exactTotal=false"
                ))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(estimated.status(), StatusCode::OK);
    let body = to_bytes(estimated.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 2);
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    assert!(value["data"]["items"][0].get("evidence").is_some());

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
async fn search_to_download_flow_uses_recorded_network_observation() {
    let core = test_search_core(&[
        IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Indexed.Result.iso".to_string(),
            size_bytes: 42,
            content_type: "iso".to_string(),
            availability_score: 2,
        },
        IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".into(),
            name: "Conflicting.Size.iso".into(),
            size_bytes: 84,
            content_type: "iso".into(),
            availability_score: 2,
        },
    ]);
    let observed_search_id = core.searches().await.into_iter().next().unwrap().id;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/searches/{observed_search_id}"))
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let search_id = value["data"]["id"].as_str().unwrap();
    let items = value["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_ne!(items[0]["id"], items[1]["id"]);
    let result_id = items.iter().find(|item| item["sizeBytes"] == 84).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let download_uri = format!("/api/v1/searches/{search_id}/results/{result_id}/download");
    let response = app
        .clone()
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
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"]["id"].is_string());
    let admitted_id = value["data"]["id"].clone();
    assert_eq!(value["data"]["sizeBytes"], 84);
    assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");

    let duplicate = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/searches/{search_id}/results/{result_id}/download"
                ))
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"redownload":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate.status(), StatusCode::OK);
    let body = to_bytes(duplicate.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["id"], admitted_id);
}

#[tokio::test]
async fn search_result_download_accepts_stopped_intent() {
    let core = test_search_core(&[IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
        name: "Stopped.Indexed.Result.iso".to_string(),
        size_bytes: 42,
        content_type: "iso".to_string(),
        availability_score: 2,
    }]);
    let observed_search_id = core.searches().await.into_iter().next().unwrap().id;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/searches/{observed_search_id}"))
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let search_id = value["data"]["id"].as_str().unwrap();
    let result_id = value["data"]["items"][0]["id"].as_str().unwrap().to_owned();

    let download_uri = format!("/api/v1/searches/{search_id}/results/{result_id}/download");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(download_uri)
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"intent":"stopped"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"]["id"].is_string());
    assert_eq!(value["data"]["intent"], "stopped");
    assert_eq!(value["data"]["hash"], "00112233445566778899aabbccddeeff");
}

#[tokio::test]
async fn kad_import_frontdoor_reports_closed_persistence() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.drain_persistence().await.unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/kad/operations/import-nodes-url")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"url":"http://127.0.0.1:1/nodes.dat"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING");
}

#[tokio::test]
async fn server_connect_frontdoors_report_closed_persistence() {
    let root = unique_test_dir("server-persistence-fault");
    let mut network = test_network_config(&root);
    network.egress_route = emulebb_ed2k::networking::EgressRoute::DirectSystemRoute;
    network.vpn_guard.mode = "off".into();
    network.p2p_bind_ip = None;
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.kad_bind_addr = "127.0.0.1:0".parse().unwrap();
    network.listen_port = 0;
    network.nat_config.enabled = false;
    let core = Arc::new(
        EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &root,
            Some(network),
        )
        .unwrap(),
    );
    core.add_server(emulebb_core::ServerCreate {
        address: "127.0.0.1".into(),
        port: 1,
        name: None,
        priority: None,
        static_server: None,
        connect: None,
    })
    .await
    .unwrap();
    core.drain_persistence().await.unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    for (uri, body) in [
        ("/api/v1/servers/operations/connect", ""),
        ("/api/v1/servers/127.0.0.1%3A1/operations/connect", ""),
        (
            "/api/v1/servers",
            r#"{"address":"127.0.0.2","port":1,"connect":true}"#,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING", "{uri}");
    }
}

#[tokio::test]
async fn kad_stop_frontdoor_reports_closed_persistence() {
    let root = unique_test_dir("kad-stop-persistence-fault");
    let mut network = test_network_config(&root);
    network.egress_route = emulebb_ed2k::networking::EgressRoute::DirectSystemRoute;
    network.vpn_guard.mode = "off".into();
    network.p2p_bind_ip = None;
    network.bind_ip = Ipv4Addr::LOCALHOST;
    network.kad_bind_addr = "127.0.0.1:0".parse().unwrap();
    network.listen_port = 0;
    network.nat_config.enabled = false;
    network.ed2k.server_endpoints = vec!["127.0.0.1:1".into()];
    let core = Arc::new(
        EmulebbCore::new_with_network(
            "test",
            FileIndex::in_memory().unwrap(),
            &root,
            Some(network),
        )
        .unwrap(),
    );
    core.connect_ed2k().await.unwrap();
    core.drain_persistence().await.unwrap();
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/kad/operations/stop")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING");
    core.disconnect_ed2k_after_persistence().await.unwrap();
}

#[tokio::test]
async fn search_removal_reports_closed_admission_and_preserves_sessions() {
    let core = test_search_core(&[IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".into(),
        name: "Preserved.bin".into(),
        size_bytes: 42,
        content_type: "pro".into(),
        availability_score: 2,
    }]);
    let id = core.searches().await[0].id.clone();
    core.drain_persistence().await.unwrap();
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    for uri in [
        format!("/api/v1/searches/{id}"),
        "/api/v1/searches?confirm=true".into(),
    ] {
        let (status, body) = request(&app, "DELETE", &uri, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "PERSISTENCE_CLOSING");
        assert!(core.search(&id).await.is_some());
    }
}
