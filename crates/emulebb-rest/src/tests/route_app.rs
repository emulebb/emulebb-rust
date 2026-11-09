use crate::rest_test_support::*;

fn atomic_settings_router() -> (
    Router,
    Arc<EmulebbCore>,
    std::path::PathBuf,
    rusqlite::Connection,
) {
    let root = unique_test_dir("atomic-settings");
    let database = root.join("metadata.sqlite");
    let core = Arc::new(
        EmulebbCore::new(
            "test",
            FileIndex::open(&database).unwrap(),
            root.join("transfers"),
        )
        .unwrap(),
    );
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".to_owned(),
            web_root_dir: None,
        },
    );
    let connection = rusqlite::Connection::open(&database).unwrap();
    (app, core, database, connection)
}

async fn atomic_settings_response(app: &Router, method: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri("/api/v1/app/settings")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(if method == "GET" {
                    Body::empty()
                } else {
                    Body::from(body.to_string())
                })
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn atomic_settings_rows(connection: &rusqlite::Connection) -> Vec<(String, String, String, i64)> {
    connection
        .prepare(
            "SELECT section, key, value_json, updated_at_ms FROM settings ORDER BY section, key",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

#[tokio::test]
async fn settings_http_middleware_rejects_invalid_core_before_any_setting_changes() {
    let (app, core, _, connection) = atomic_settings_router();
    let before = core.app_settings().await.unwrap();
    let rows = atomic_settings_rows(&connection);
    let (status, response) = atomic_settings_response(
        &app,
        "PATCH",
        json!({
            "nat": {"enabled": !before.nat.enabled}, "core": {"uploadLimitKiBps": 0},
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(core.app_settings().await.unwrap(), before);
    assert_eq!(core.core_settings().await, before.core);
    assert_eq!(atomic_settings_rows(&connection), rows);
}

#[tokio::test]
async fn valid_settings_http_patch_rolls_back_every_section_when_later_sql_write_fails() {
    let (app, core, database, connection) = atomic_settings_router();
    let (_, before) = atomic_settings_response(&app, "GET", Value::Null).await;
    let rows = atomic_settings_rows(&connection);
    let old_core = core.core_settings().await;
    let reload = !before["data"]["daemon"]["initialSharedDirectoryReload"]
        .as_bool()
        .unwrap();
    let nat = !before["data"]["nat"]["enabled"].as_bool().unwrap();
    let request = json!({
        "core": {"uploadLimitKiBps": 1024},
        "daemon": {"initialSharedDirectoryReload": reload}, "nat": {"enabled": nat},
    });
    // This request passes route validation. NAT is written after the earlier
    // core/daemon sections, so a real SQLite failure proves transaction rollback.
    connection.execute_batch(
        "CREATE TRIGGER synthetic_settings_failure BEFORE INSERT ON settings
         WHEN NEW.section = 'nat' BEGIN SELECT RAISE(ABORT, 'synthetic later settings failure'); END;",
    ).unwrap();
    let (status, response) = atomic_settings_response(&app, "PATCH", request.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("synthetic later settings failure")
    );
    assert_eq!(atomic_settings_rows(&connection), rows);
    assert_eq!(core.core_settings().await, old_core);
    let (_, after) = atomic_settings_response(&app, "GET", Value::Null).await;
    assert_eq!(after["data"], before["data"]);

    connection
        .execute_batch("DROP TRIGGER synthetic_settings_failure")
        .unwrap();
    let (status, committed) = atomic_settings_response(&app, "PATCH", request).await;
    assert_eq!(status, StatusCode::OK);
    let mut expected = before["data"].clone();
    expected["core"]["uploadLimitKiBps"] = json!(1024);
    expected["daemon"]["initialSharedDirectoryReload"] = json!(reload);
    expected["nat"]["enabled"] = json!(nat);
    assert_eq!(committed["data"], expected);
    assert_eq!(core.core_settings().await.upload_limit_ki_bps, 1024);
    drop(app);
    drop(core);
    drop(connection);
    let restored = EmulebbCore::new(
        "test",
        FileIndex::open(database).unwrap(),
        unique_test_dir("atomic-settings-restart"),
    )
    .unwrap()
    .app_settings()
    .await
    .unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), expected);
}

#[tokio::test]
async fn event_stream_closes_without_replay_when_shutdown_is_already_requested() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let (shutdown, _) = watch::channel(false);
    shutdown.send_replace(true);
    let app = router_with_shutdown(
        core,
        RestServerSettings {
            api_key: "secret".to_owned(),
            web_root_dir: None,
        },
        Some(shutdown),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header("X-API-Key", "secret")
                .header("Last-Event-ID", "0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        to_bytes(response.into_body(), 4096),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn shared_root_api_consolidates_children_for_ui_and_direct_calls() {
    let temp = unique_test_dir("recursive-roots");
    let parent = temp.join("Shared");
    let child = parent.join("Child");
    let sibling = temp.join("Shared-Other");
    std::fs::create_dir_all(&child).unwrap();
    std::fs::create_dir(&sibling).unwrap();
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let app = router(
        core.clone(),
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );
    for (path, count) in [(&child, 1), (&parent, 1), (&child, 1), (&sibling, 2)] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/shared-directories/roots")
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({"path":path}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["data"]["roots"].as_array().unwrap().len(), count);
    }
    let roots = core.shared_directories().await.roots;
    assert!(
        roots
            .iter()
            .any(|root| std::path::Path::new(&root.path).ends_with("Shared"))
    );
    assert!(
        !roots
            .iter()
            .any(|root| std::path::Path::new(&root.path).ends_with("Child"))
    );
    core.stop_shared_directory_monitor();
    std::fs::remove_dir_all(temp).ok();
}

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
async fn diagnostic_bundle_is_returned_inline_without_daemon_persistence() {
    let runtime_dir = unique_test_dir("diagnostic-bundle");
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
                .uri("/api/v1/diagnostics/bundles")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmCapture":false,"maxBytes":4194304}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let invalid_budget = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/diagnostics/bundles")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmCapture":true,"maxBytes":65535}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_budget.status(), StatusCode::BAD_REQUEST);

    let accepted = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/diagnostics/bundles")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmCapture":true,"maxBytes":4194304}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        accepted.headers().get("content-type").unwrap(),
        "application/json"
    );
    let content_length = accepted
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let body = to_bytes(accepted.into_body(), usize::MAX).await.unwrap();
    assert_eq!(content_length, body.len());
    assert!(body.len() <= 4_194_304);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value.get("fullMemory").is_none());
    assert!(value.get("fullMemoryIncluded").is_none());
    assert!(value.get("path").is_none());
    assert!(value.get("byteCount").is_none());
    assert_eq!(value["schema"], "emulebb.diagnostic-bundle.v6");
    assert_eq!(value["budget"]["maxBytes"], 4_194_304);
    assert_eq!(value["budget"]["encodedBytes"], body.len());
    assert_eq!(value["summary"]["artifactFileCount"], 0);
    assert_eq!(
        value["summary"]["missingArtifactFamilies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!runtime_dir.join("diagnostics").exists());

    let bundle = &value;
    assert_eq!(bundle["schema"], "emulebb.diagnostic-bundle.v6");
    assert!(bundle.get("memory").is_none());
    assert_eq!(bundle["settingsProvenance"]["apiKeyIncluded"], true);
    assert_eq!(bundle["settingsProvenance"]["sensitiveValues"], "exact");
    assert_eq!(bundle["settingsProvenance"]["apiKey"], "secret");
    assert!(bundle["status"].is_object());
    assert!(bundle.get("runtimeDiagnostics").is_none());
    assert_eq!(
        bundle["status"]["runtimeDiagnostics"]["diagnosticWriter"]["enabled"],
        false
    );
    assert!(
        bundle["diagnosticHealth"]["writerIssues"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(bundle["settings"].is_object());
    assert!(bundle["recentLogs"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["servers"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["sharedFiles"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["searches"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["transfers"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["uploads"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["uploadQueue"]["items"].is_array());
    assert!(bundle["diagnosticArtifacts"]["families"].is_array());
    assert_eq!(bundle["limits"]["artifactFamilies"], 1);
    assert_eq!(bundle["limits"]["serverSnapshots"], 512);
    assert_eq!(bundle["limits"]["sharedFileSnapshots"], 512);
    assert_eq!(bundle["limits"]["searchSnapshots"], 64);
    assert_eq!(bundle["limits"]["searchResultsPerSnapshot"], 128);
    assert_eq!(bundle["limits"]["transferSnapshots"], 512);
    assert_eq!(bundle["limits"]["uploadSnapshots"], 512);
    assert_eq!(bundle["limits"]["uploadQueueSnapshots"], 512);
    assert!(serde_json::to_string(&bundle).unwrap().contains("secret"));
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
    assert!(value["data"]["core"].get("reconnect").is_none());
    assert!(value["data"]["core"].get("safeServerConnect").is_none());
    assert!(value["data"]["core"].get("addServersFromServer").is_none());
    assert_eq!(value["data"]["daemon"]["p2pBindInterface"], Value::Null);
    assert_eq!(value["data"]["ed2k"]["nickname"], "eMule");
    assert_eq!(value["data"]["ed2k"]["obfuscationEnabled"], true);
    assert_eq!(value["data"]["ed2k"]["useServerPriorities"], true);
    assert_eq!(value["data"]["ed2k"]["autoConnectStaticOnly"], false);
    assert_eq!(value["data"]["ed2k"]["reconnectEnabled"], true);
    assert_eq!(value["data"]["ed2k"]["safeServerConnect"], false);
    assert_eq!(value["data"]["ed2k"]["addServersFromServer"], false);
    assert_eq!(value["data"]["ed2k"]["serverKeepaliveMinutes"], 0);
    assert_eq!(
        value["data"]["ed2k"]["minFreeConfigSpaceBytes"],
        1_073_741_824_u64
    );
    assert_eq!(
        value["data"]["ed2k"]["minFreeTransferSpaceBytes"],
        5_368_709_120_u64
    );
    assert_eq!(
        value["data"]["ed2k"]["minFreeIncomingSpaceBytes"],
        5_368_709_120_u64
    );
    assert_eq!(value["data"]["kad"]["bootstrapMinRoutingContacts"], 10);
    assert_eq!(value["data"]["core"]["autoConnect"], true);
    assert_eq!(value["data"]["nat"]["enabled"], true);
    assert_eq!(value["data"]["nat"]["requireInitialMapping"], false);
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
                    r#"{"core":{"uploadLimitKiBps":2048,"uploadClientDataRate":64,"baseUploadSlots":4,"queueSize":3000,"networkEd2k":false},"daemon":{"p2pBindInterface":"hide.me","ed2kUserHash":"00112233440e66778899aabbccdd6fff"},"ed2k":{"nickname":"Phase B Mule","reconnectEnabled":false,"safeServerConnect":true,"addServersFromServer":true,"serverKeepaliveMinutes":20,"useServerPriorities":false,"autoConnectStaticOnly":true,"minFreeConfigSpaceBytes":2147483648,"minFreeTransferSpaceBytes":6442450944,"minFreeIncomingSpaceBytes":7516192768},"vpnGuard":{"enabled":true,"mode":"block","allowedPublicIpCidrs":"8.8.8.0/24 1.1.1.1"},"nat":{"enabled":true,"requireInitialMapping":true,"backendOrder":["upnp_miniupnpc"],"discoveryTimeoutSecs":5,"leaseDurationSecs":3600,"renewMarginSecs":300}}"#,
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
    assert_eq!(value["data"]["core"]["baseUploadSlots"], 4);
    assert_eq!(value["data"]["core"]["queueSize"], 3000);
    assert_eq!(value["data"]["core"]["networkEd2k"], false);
    assert_eq!(value["data"]["daemon"]["p2pBindInterface"], "hide.me");
    assert_eq!(value["data"]["ed2k"]["nickname"], "Phase B Mule");
    assert_eq!(value["data"]["ed2k"]["reconnectEnabled"], false);
    assert_eq!(value["data"]["ed2k"]["safeServerConnect"], true);
    assert_eq!(value["data"]["ed2k"]["addServersFromServer"], true);
    assert_eq!(value["data"]["ed2k"]["serverKeepaliveMinutes"], 20);
    assert_eq!(value["data"]["ed2k"]["useServerPriorities"], false);
    assert_eq!(value["data"]["ed2k"]["autoConnectStaticOnly"], true);
    assert_eq!(
        value["data"]["ed2k"]["minFreeConfigSpaceBytes"],
        2_147_483_648_u64
    );
    assert_eq!(
        value["data"]["ed2k"]["minFreeTransferSpaceBytes"],
        6_442_450_944_u64
    );
    assert_eq!(
        value["data"]["ed2k"]["minFreeIncomingSpaceBytes"],
        7_516_192_768_u64
    );
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
                    r#"{"nat":{"backendOrder":["pcp_natpmp","upnp_miniupnpc"],"pcpServerIp":"192.0.2.1","leaseDurationSecs":7200,"externalIpOverride":"198.51.100.24"}}"#,
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
        json!(["pcp_natpmp", "upnp_miniupnpc"])
    );
    assert_eq!(value["data"]["nat"]["pcpServerIp"], "192.0.2.1");
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
    core.add_shared_directory_root(&runtime_dir.display().to_string())
        .await
        .unwrap();
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
