use crate::rest_test_support::*;

#[tokio::test]
async fn diagnostic_search_capture_reads_bounded_durable_summaries() {
    let files = (0..260)
        .map(|index| IndexedFile {
            ed2k_hash: format!("{index:032x}"),
            name: format!("Sample-{index:03}.bin"),
            size_bytes: 4096,
            content_type: "pro".into(),
            availability_score: index + 1,
        })
        .collect::<Vec<_>>();
    let core = test_search_core(&files);
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let (status, bundle) = request(
        &app,
        "POST",
        "/api/v1/diagnostics/bundles",
        Some(json!({"confirmCapture":true,"maxBytes":4194304})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let searches = &bundle["operationalSnapshots"]["searches"];
    assert!(searches["total"].is_null());
    assert_eq!(searches["included"], 1);
    assert_eq!(searches["hasMore"], false);
    let snapshot = &searches["items"][0];
    assert_eq!(snapshot["session"]["resultCount"], 260);
    assert!(snapshot["session"]["createdAt"].is_i64());
    let results = &snapshot["results"];
    assert_eq!(results["included"], 128);
    assert_eq!(results["total"], 260);
    assert_eq!(results["omittedAfterLimit"], 132);
    assert_eq!(results["hasMore"], true);
    assert_eq!(results["items"][0]["displayName"], "Sample-259.bin");
    assert!(serde_json::to_vec(&searches["items"]).unwrap().len() <= 1024 * 1024);
}

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
    let payload = json!({"address":" 192.0.2.20 ","port":4661,"priority":"low","static":true});
    let (status, created) = request(&app, "POST", "/api/v1/servers", Some(payload.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["data"]["id"].as_str().unwrap();
    let path = format!("/api/v1/servers/{id}");
    let (status, resource) = request(&app, "GET", &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resource["data"]["id"], id);
    assert_eq!(resource["data"]["address"], "192.0.2.20");
    assert_eq!(resource["data"]["name"], "");
    assert_eq!(resource["data"]["priority"], "low");
    assert_eq!(resource["data"]["static"], true);
    for enabled in [false, true] {
        let (status, _) = request(
            &app,
            "PATCH",
            &path,
            Some(json!({"priority":"high", "enabled": enabled})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, value) = request(&app, "GET", &path, None).await;
        assert_eq!(value["data"]["enabled"], enabled);
        assert_eq!(value["data"]["priority"], "high");
    }
    let (status, _) = request(&app, "POST", "/api/v1/servers", Some(payload.clone())).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, unchanged) = request(&app, "GET", &path, None).await;
    assert_eq!(unchanged["data"]["priority"], "high");
    let (status, body) = request(&app, "DELETE", &path, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_null());
    assert_eq!(
        request(&app, "GET", &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "DELETE", &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, recreated) = request(&app, "POST", "/api/v1/servers", Some(payload)).await;
    assert!(
        recreated["data"]["id"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > id.parse::<i64>().unwrap()
    );
}

#[tokio::test]
async fn server_pages_continue_after_deleted_anchor_and_count_only_live_resources() {
    let app = test_router();
    for last in 1..=3 {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/servers",
                Some(json!({"address":format!("192.0.2.{last}"),"port":4661,"enabled":false}))
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    let (status, first) =
        request(&app, "GET", "/api/v1/servers?limit=1&countTotal=true", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["data"].as_array().unwrap().len(), 1);
    assert_eq!(first["meta"]["total"], 3);
    assert_eq!(first["meta"]["hasMore"], true);
    let id = first["data"][0]["id"].as_str().unwrap();
    assert_eq!(
        request(&app, "DELETE", &format!("/api/v1/servers/{id}"), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let (status, next) = request(
        &app,
        "GET",
        &format!("/api/v1/servers?limit=2&countTotal=true&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(next["data"].as_array().unwrap().len(), 2);
    assert_eq!(next["meta"]["total"], 2);
    assert_eq!(next["meta"]["hasMore"], false);
    assert!(next["meta"]["nextCursor"].is_null());
    let (_, default) = request(&app, "GET", "/api/v1/servers", None).await;
    assert!(default["meta"].get("total").is_none());
    for query in ["limit=0", "limit=201", "cursor=00"] {
        assert_eq!(
            request(&app, "GET", &format!("/api/v1/servers?{query}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
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
    let observed_search_id = core
        .search_headers_page(None, 1)
        .await
        .unwrap()
        .value()
        .items[0]
        .id
        .to_string();
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
    let observed_search_id = core
        .search_headers_page(None, 1)
        .await
        .unwrap()
        .value()
        .items[0]
        .id
        .to_string();
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
    core.create_server_resource(&emulebb_metadata::MetadataServerCreate {
        address: "127.0.0.1".into(),
        port: 1,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
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
        ("/api/v1/servers/1/operations/connect", ""),
        ("/api/v1/servers", r#"{"address":"127.0.0.2","port":1}"#),
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
    let root = unique_test_dir("search-closed-admission");
    let index = FileIndex::open(root.join("metadata.sqlite")).unwrap();
    let metadata = index.metadata_store();
    let core = Arc::new(
        EmulebbCore::new_with_network("test", index, &root, Some(test_network_config(&root)))
            .unwrap(),
    );
    let id = core
        .create_search(
            serde_json::from_value(json!({"query":"preserved session", "method":"server"}))
                .unwrap(),
        )
        .await
        .unwrap()
        .id;
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
        assert!(
            metadata
                .search_header(id.parse().unwrap())
                .unwrap()
                .is_some()
        );
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
    assert_eq!(
        metadata.search_headers_page(None, 10).unwrap().items.len(),
        1
    );
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

#[tokio::test]
async fn stop_search_preserves_collected_results_and_returns_no_content() {
    let core = test_search_core(&[]);
    let created = core
        .create_search(
            serde_json::from_value(json!({"query":"stop proof", "method":"server"})).unwrap(),
        )
        .await
        .unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let path = format!("/api/v1/searches/{}/stop", created.id);
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::post(&path)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty()
        );
    }
    let (_, metadata) = request(
        &app,
        "GET",
        &format!("/api/v1/searches/{}", created.id),
        None,
    )
    .await;
    assert_eq!(metadata["data"]["status"], "stopped");
    assert_eq!(metadata["data"]["resultCount"], 0);
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/searches/9223372036854775807/stop",
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn linked_creation_uses_supplied_criteria_and_unlinks_without_deleting_children() {
    let core = test_search_core(&[IndexedFile {
        ed2k_hash: "11".repeat(16),
        name: "Parent.bin".into(),
        size_bytes: 42,
        content_type: "pro".into(),
        availability_score: 1,
    }]);
    let parent = core
        .search_headers_page(None, 1)
        .await
        .unwrap()
        .value()
        .items[0]
        .id
        .to_string();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let (status, created) = request(
        &app,
        "POST",
        "/api/v1/searches",
        Some(json!({"parentSearchId":parent,"query":"edited child", "method":"server"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let child = created["data"]["id"].as_str().unwrap();
    assert_eq!(created["data"]["parentSearchId"], parent);
    assert_eq!(created["data"]["query"], "edited child");
    assert_eq!(created["data"]["resultCount"], 0);
    assert_eq!(
        request(&app, "DELETE", &format!("/api/v1/searches/{parent}"), None)
            .await
            .0,
        StatusCode::OK
    );
    let (status, metadata) = request(&app, "GET", &format!("/api/v1/searches/{child}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(metadata["data"]["parentSearchId"].is_null());
    assert_eq!(metadata["data"]["query"], "edited child");
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/searches",
            Some(json!({"parentSearchId":parent,"query":"missing parent", "method":"server"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for invalid in [
        json!(1),
        json!("0"),
        json!("01"),
        json!("9223372036854775808"),
    ] {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/searches",
                Some(json!({"parentSearchId":invalid,"query":"invalid parent", "method":"server"}))
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
}
