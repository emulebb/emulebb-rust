use crate::rest_test_support::*;

#[tokio::test]
async fn app_shutdown_requires_confirmation_and_signals_daemon() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let app = router_with_shutdown(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
        Some(shutdown_tx),
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/app/shutdown")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmShutdown":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert!(!*shutdown_rx.borrow());

    let accepted = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/app/shutdown")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmShutdown":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert!(shutdown_rx.changed().await.is_ok());
    assert!(*shutdown_rx.borrow());
}

#[tokio::test]
async fn diagnostic_dump_uses_canonical_route_and_confirmation() {
    let runtime_dir = unique_test_dir("diagnostic-dump");
    let transfer_root = runtime_dir.join("transfers");
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/diagnostics/dumps")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmDump":false,"fullMemory":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let accepted = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/diagnostics/dumps")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmDump":true,"fullMemory":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["fullMemory"], false);
    let path = value["data"]["path"].as_str().unwrap();
    assert!(std::path::Path::new(path).is_file());
    let keys = value["data"].as_object().unwrap();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains_key("ok"));
    assert!(keys.contains_key("path"));
    assert!(keys.contains_key("fullMemory"));
}

#[tokio::test]
async fn diagnostic_crash_test_requires_confirmation() {
    let denied = test_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/diagnostics/crash-tests")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmCrash":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn settings_use_typed_get_and_patch_route() {
    let app = test_router();
    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let body = to_bytes(read.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["core"]["uploadLimitKiBps"], 6200);
    assert_eq!(value["data"]["core"]["reconnect"], true);
    assert_eq!(value["data"]["daemon"]["p2pBindInterface"], Value::Null);
    assert_eq!(value["data"]["ed2k"]["obfuscationEnabled"], true);
    assert_eq!(value["data"]["kad"]["bootstrapMinRoutingContacts"], 10);
    assert_eq!(value["data"]["nat"]["enabled"], false);
    assert_eq!(value["data"]["vpnGuard"]["enabled"], false);
    assert_eq!(value["data"]["ipFilter"]["level"], 127);

    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"core":{"uploadLimitKiBps":2048,"uploadClientDataRate":64,"maxUploadSlots":4,"queueSize":3000,"reconnect":false,"networkEd2k":false},"daemon":{"p2pBindInterface":"hide.me","ed2kUserHash":"00112233440e66778899aabbccdd6fff"},"vpnGuard":{"enabled":true,"mode":"block","allowedPublicIpCidrs":"8.8.8.0/24 1.1.1.1"},"nat":{"enabled":true,"requireInitialMapping":true,"backendOrder":["upnp_miniupnpc"],"discoveryTimeoutSecs":5,"leaseDurationSecs":3600,"renewMarginSecs":300}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["core"]["uploadLimitKiBps"], 2048);
    assert_eq!(value["data"]["core"]["uploadClientDataRate"], 64);
    assert_eq!(value["data"]["core"]["maxUploadSlots"], 4);
    assert_eq!(value["data"]["core"]["queueSize"], 3000);
    assert_eq!(value["data"]["core"]["reconnect"], false);
    assert_eq!(value["data"]["core"]["networkEd2k"], false);
    assert_eq!(value["data"]["daemon"]["p2pBindInterface"], "hide.me");
    assert_eq!(
        value["data"]["daemon"]["ed2kUserHash"],
        "00112233440e66778899aabbccdd6fff"
    );
    assert_eq!(value["data"]["vpnGuard"]["enabled"], true);
    assert_eq!(value["data"]["vpnGuard"]["mode"], "block");
    assert_eq!(
        value["data"]["vpnGuard"]["allowedPublicIpCidrs"],
        "8.8.8.0/24 1.1.1.1"
    );
    assert_eq!(value["data"]["nat"]["enabled"], true);

    let empty_patch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_patch.status(), StatusCode::BAD_REQUEST);

    let unknown_section = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"legacyNetwork":{}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_section.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(unknown_section.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "unknown JSON field: legacyNetwork"
    );

    let unknown_core_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"core":{"unsupportedSetting":true}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_core_key.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(unknown_core_key.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "unknown settings.core field: unsupportedSetting"
    );

    let removed_core_route = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/app/core_settings")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(removed_core_route.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn settings_patch_rejects_incoming_dir_that_is_not_directory() {
    let app = test_router();
    let temp = unique_test_dir("settings-incoming-dir-file");
    let file = temp.join("not-a-directory.txt");
    std::fs::write(&file, b"not a directory").unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"daemon":{"incomingDir": file.display().to_string()}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], "incomingDir is not a directory");
    std::fs::remove_dir_all(temp).ok();
}

#[tokio::test]
async fn settings_patch_preserves_unspecified_section_fields() {
    let app = test_router();

    let initial = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"nat":{"backendOrder":["upnp_miniupnpc"],"leaseDurationSecs":7200,"externalIpOverride":"198.51.100.24"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);

    let partial = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"nat":{"enabled":true}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(partial.status(), StatusCode::OK);
    let body = to_bytes(partial.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["nat"]["enabled"], true);
    assert_eq!(
        value["data"]["nat"]["backendOrder"],
        json!(["upnp_miniupnpc"])
    );
    assert_eq!(value["data"]["nat"]["leaseDurationSecs"], 7200);
    assert_eq!(value["data"]["nat"]["externalIpOverride"], "198.51.100.24");
}

#[tokio::test]
async fn snapshot_returns_bounded_emulebb_polling_shape() {
    let runtime_dir = unique_test_dir("snapshot");
    let transfer_root = runtime_dir.join("transfers");
    let first_file = runtime_dir.join("First.Snapshot.bin");
    let second_file = runtime_dir.join("Second.Snapshot.bin");
    std::fs::write(&first_file, b"first snapshot payload").unwrap();
    std::fs::write(&second_file, b"second snapshot payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    core.share_local_file(LocalShareCreate {
        path: first_file.display().to_string(),
        name: None,
    })
    .await
    .unwrap();
    core.share_local_file(LocalShareCreate {
        path: second_file.display().to_string(),
        name: None,
    })
    .await
    .unwrap();
    core.add_server(emulebb_core::ServerCreate {
        address: "192.0.2.20".to_string(),
        port: 4661,
        name: Some("snapshot-server".to_string()),
        priority: None,
        static_server: Some(true),
        connect: None,
    })
    .await
    .unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/snapshot?limit=1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let data = &value["data"];
    assert_eq!(data["app"]["name"], "eMuleBB");
    assert_eq!(data["status"]["lifecycle"]["state"], "running");
    assert_eq!(data["transfers"].as_array().unwrap().len(), 0);
    assert_eq!(data["sharedFiles"].as_array().unwrap().len(), 1);
    assert_eq!(data["servers"].as_array().unwrap().len(), 1);
    assert_eq!(data["uploads"].as_array().unwrap().len(), 0);
    assert_eq!(data["uploadQueue"].as_array().unwrap().len(), 0);
    assert!(data["kad"].is_object());
    assert!(data["network"]["ports"].is_object());
    assert!(data["network"]["binding"].is_object());
    assert!(data["network"]["vpnGuard"].is_object());
    assert!(data["logs"].as_array().unwrap().len() <= 1);
}

#[tokio::test]
async fn uploads_and_upload_queue_use_canonical_envelopes() {
    let app = test_router();
    for path in ["/api/v1/uploads", "/api/v1/upload-queue"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
    }

    let paged_queue = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue?offset=1&limit=1&includeScoreBreakdown=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged_queue.status(), StatusCode::OK);
    let body = to_bytes(paged_queue.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 0);
    assert_eq!(value["data"]["offset"], 1);
    assert_eq!(value["data"]["limit"], 1);

    for (path, expected_message) in [
        (
            "/api/v1/uploads/192.0.2.44:4662",
            "active upload client not found",
        ),
        (
            "/api/v1/upload-queue/192.0.2.44:4662",
            "upload queue client not found",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["message"], expected_message);
    }

    for path in [
        "/api/v1/uploads/192.0.2.44:4662/operations/remove",
        "/api/v1/uploads/192.0.2.44:4662/operations/release-slot",
        "/api/v1/uploads/192.0.2.44:4662/operations/add-friend",
        "/api/v1/uploads/192.0.2.44:4662/operations/remove-friend",
        "/api/v1/uploads/192.0.2.44:4662/operations/ban",
        "/api/v1/uploads/192.0.2.44:4662/operations/unban",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/remove",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/release-slot",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/add-friend",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/remove-friend",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/ban",
        "/api/v1/upload-queue/192.0.2.44:4662/operations/unban",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
