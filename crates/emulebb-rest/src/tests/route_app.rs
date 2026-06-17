use crate::rest_test_support::*;

#[tokio::test]
async fn app_shutdown_requires_confirmation_and_signals_daemon() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let app = router_with_shutdown(
        core,
        RestConfig {
            api_key: "secret".to_string(),
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
        RestConfig {
            api_key: "secret".to_string(),
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
    assert_eq!(value["data"]["kind"], "json");
    let path = value["data"]["path"].as_str().unwrap();
    assert!(std::path::Path::new(path).is_file());
    assert_eq!(
        value["data"]["sizeBytes"].as_u64().unwrap(),
        std::fs::metadata(path).unwrap().len()
    );
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
async fn preferences_use_canonical_get_and_patch_route() {
    let app = test_router();
    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/app/preferences")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::OK);
    let body = to_bytes(read.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    // Master-aligned default (Preferences.cpp kDefaultConfiguredUploadLimitKiB).
    assert_eq!(value["data"]["uploadLimitKiBps"], 6200);
    assert_eq!(value["data"]["downloadAutoBroadbandIo"], true);

    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/preferences")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"uploadLimitKiBps":2048,"uploadClientDataRate":64,"maxUploadSlots":4,"queueSize":3000,"networkEd2k":false,"downloadAutoBroadbandIo":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let body = to_bytes(update.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["uploadLimitKiBps"], 2048);
    assert_eq!(value["data"]["uploadClientDataRate"], 64);
    assert_eq!(value["data"]["maxUploadSlots"], 4);
    assert_eq!(value["data"]["queueSize"], 3000);
    assert_eq!(value["data"]["networkEd2k"], false);
    assert_eq!(value["data"]["downloadAutoBroadbandIo"], false);

    let empty_patch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/preferences")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(empty_patch.status(), StatusCode::BAD_REQUEST);

    let unknown_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/preferences")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"unsupportedPreference":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_key.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(unknown_key.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "unknown JSON field: unsupportedPreference"
    );

    let invalid_range = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/app/preferences")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"queueSize":1999}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_range.status(), StatusCode::BAD_REQUEST);
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
        RestConfig {
            api_key: "secret".to_string(),
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
    assert_eq!(data["transfers"].as_array().unwrap().len(), 1);
    assert_eq!(data["sharedFiles"].as_array().unwrap().len(), 1);
    assert_eq!(data["servers"].as_array().unwrap().len(), 1);
    assert_eq!(data["uploads"].as_array().unwrap().len(), 0);
    assert_eq!(data["uploadQueue"].as_array().unwrap().len(), 0);
    assert!(data["kad"].is_object());
    assert!(data["network"]["ports"].is_object());
    assert!(data["network"]["binding"].is_object());
    assert!(data["network"]["vpnGuard"].is_object());
    assert_eq!(data["logs"].as_array().unwrap().len(), 0);
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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/upload-queue/unknown")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    for path in [
        "/api/v1/uploads/unknown/operations/remove",
        "/api/v1/uploads/unknown/operations/release-slot",
        "/api/v1/uploads/unknown/operations/add-friend",
        "/api/v1/uploads/unknown/operations/remove-friend",
        "/api/v1/uploads/unknown/operations/ban",
        "/api/v1/uploads/unknown/operations/unban",
        "/api/v1/upload-queue/unknown/operations/remove",
        "/api/v1/upload-queue/unknown/operations/release-slot",
        "/api/v1/upload-queue/unknown/operations/add-friend",
        "/api/v1/upload-queue/unknown/operations/remove-friend",
        "/api/v1/upload-queue/unknown/operations/ban",
        "/api/v1/upload-queue/unknown/operations/unban",
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
