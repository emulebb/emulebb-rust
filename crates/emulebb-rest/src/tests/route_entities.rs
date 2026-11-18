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
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/searches",
                Some(json!({"query":query,"method":"automatic"}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    assert_eq!(
        request(&app, "DELETE", "/api/v1/searches", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&app, "DELETE", "/api/v1/searches?confirm=true", None)
            .await
            .0,
        StatusCode::OK
    );
    let (status, body) = request(&app, "GET", "/api/v1/searches", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn search_delete_uses_canonical_ok_response() {
    let app = test_search_router();
    let (status, created) = request(
        &app,
        "POST",
        "/api/v1/searches",
        Some(json!({"query":"sample query"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["data"]["id"].as_str().unwrap();
    let (status, deleted) = request(&app, "DELETE", &format!("/api/v1/searches/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(deleted["data"]["ok"], true);
    assert_eq!(
        request(&app, "GET", &format!("/api/v1/searches/{id}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn search_resources_use_bounded_scoped_cursors_and_all_twelve_global_sorts() {
    let core = test_search_core(&[
        IndexedFile {
            ed2k_hash: "11".repeat(16),
            name: "Alpha.bin".into(),
            size_bytes: 42,
            content_type: "pro".into(),
            availability_score: 2,
        },
        IndexedFile {
            ed2k_hash: "22".repeat(16),
            name: "Beta.bin".into(),
            size_bytes: 84,
            content_type: "pro".into(),
            availability_score: 3,
        },
        IndexedFile {
            ed2k_hash: "33".repeat(16),
            name: "Gamma.bin".into(),
            size_bytes: 126,
            content_type: "pro".into(),
            availability_score: 4,
        },
    ]);
    let headers = core.search_headers_page(None, 1).await.unwrap();
    let id = headers.value().items[0].id;
    drop(headers);
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let (status, metadata) = request(&app, "GET", &format!("/api/v1/searches/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata["data"]["resultCount"], 3);
    assert_eq!(metadata["data"]["status"], "completed");
    assert!(metadata["data"]["createdAt"].is_number());
    let path = format!("/api/v1/searches/{id}/results");
    let (status, first) = request(
        &app,
        "GET",
        &format!("{path}?sort=displayName&order=asc&limit=1"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["data"][0]["displayName"], "Alpha.bin");
    assert_eq!(first["meta"]["hasMore"], true);
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    assert!(cursor.len() <= 512);
    let (status, next) = request(
        &app,
        "GET",
        &format!("{path}?sort=displayName&order=asc&limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["data"][0]["displayName"], "Beta.bin");
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("{path}?sort=sizeBytes&order=asc&cursor={cursor}"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let claim = first["data"][0]["id"].as_str().unwrap();
    let (status, selected) = request(&app, "GET", &format!("{path}/{claim}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(selected["data"], first["data"][0]);
    for sort in [
        "displayName",
        "sizeBytes",
        "sources",
        "completeSources",
        "rating",
        "fileType",
        "artist",
        "album",
        "title",
        "lengthSeconds",
        "bitrateKbps",
        "codec",
    ] {
        for order in ["asc", "desc"] {
            let (status, page) = request(
                &app,
                "GET",
                &format!("{path}?sort={sort}&order={order}&limit=1"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{sort} {order}: {page}");
            assert_eq!(page["data"].as_array().unwrap().len(), 1);
        }
    }
    assert_eq!(
        request(&app, "GET", &format!("{path}?limit=201"), None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
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
                .uri(format!("/api/v1/searches/{observed_search_id}/results"))
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
    let search_id = &observed_search_id;
    let items = value["data"].as_array().unwrap();
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
                .uri(format!("/api/v1/searches/{observed_search_id}/results"))
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
    let search_id = &observed_search_id;
    let result_id = value["data"][0]["id"].as_str().unwrap().to_owned();

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
async fn search_mutations_report_closed_admission_and_preserve_sessions() {
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
    let (status, body) = request(
        &app,
        "POST",
        "/api/v1/searches",
        Some(json!({
            "query": "closed admission", "method": "server",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "PERSISTENCE_CLOSING");
    assert_eq!(core.searches().await.len(), 1);
}

#[tokio::test]
async fn search_creation_returns_committed_metadata_and_its_location() {
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
                    r#"{"query":"sample query","method":"automatic"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let location = response.headers()["Location"].to_str().unwrap().to_owned();
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(
        location,
        format!("/api/v1/searches/{}", body["data"]["id"].as_str().unwrap())
    );
    assert_eq!(body["data"]["resultCount"], 0);
    assert!(body["data"]["createdAt"].is_number());
    let (status, metadata) = request(&app, "GET", &location, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata["data"]["id"], body["data"]["id"]);
}
