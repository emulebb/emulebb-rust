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
                .uri("/api/v1/settings")
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

fn saved_settings_row(connection: &rusqlite::Connection) -> (i64, String) {
    connection
        .query_row(
            "SELECT revision,document_json FROM app_settings WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

#[tokio::test]
async fn settings_get_captures_complete_saved_effective_and_application_state() {
    let (app, core, _, sql) = atomic_settings_router();
    let before = saved_settings_row(&sql);
    let (status, read) = atomic_settings_response(&app, "GET", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["meta"]["settingsRevision"], "1");
    assert_eq!(
        read["data"]["saved"]["network"]["nickname"],
        json!({"mode":"default","value":"eMule"})
    );
    assert_eq!(
        read["data"]["effective"],
        serde_json::to_value(core.effective_settings().await.unwrap()).unwrap()
    );
    assert_eq!(
        read["data"]["application"],
        json!({"pendingRestart":[],"failed":[]})
    );
    assert_eq!(read["data"].as_object().unwrap().len(), 3);
    assert_eq!(read["data"]["saved"].as_object().unwrap().len(), 5);
    assert_eq!(saved_settings_row(&sql), before);
}

#[tokio::test]
async fn settings_patch_saves_restart_values_and_applies_only_admitted_live_values() {
    let (app, core, database, _) = atomic_settings_router();
    let (status,updated)=atomic_settings_response(&app,"PATCH",json!({"expectedRevision":"1","set":{
        "network":{"nickname":"Sample Client","servers":{"usePriorities":false,"staticOnly":true}},
        "transfers":{"uploadLimitBytesPerSecond":2097152,"upload":{"baseSlots":4,"queueCapacity":3000}}
    }})).await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["meta"]["settingsRevision"], "2");
    assert_eq!(
        updated["data"]["saved"]["network"]["nickname"],
        json!({"mode":"custom","value":"Sample Client"})
    );
    assert_eq!(updated["data"]["effective"]["network"]["nickname"], "eMule");
    assert_eq!(
        updated["data"]["effective"]["transfers"]["uploadLimitBytesPerSecond"],
        2097152
    );
    assert_eq!(
        updated["data"]["application"]["pendingRestart"],
        json!([
            "network.nickname",
            "network.servers.usePriorities",
            "network.servers.staticOnly"
        ])
    );
    drop(app);
    core.drain_persistence().await.unwrap();
    drop(core);
    let restored = EmulebbCore::new(
        "test",
        FileIndex::open(database).unwrap(),
        unique_test_dir("settings-restart"),
    )
    .unwrap();
    let values = restored.effective_settings().await.unwrap();
    assert_eq!(values.network.nickname, "Sample Client");
    assert!(!values.network.servers.use_priorities);
    assert!(values.network.servers.static_only);
    assert_eq!(values.transfers.upload.base_slots, 4);
    assert_eq!(values.transfers.upload.queue_capacity, 3000);
}

#[tokio::test]
async fn stale_settings_revision_returns_conflict_without_mutation() {
    let (app, core, _, sql) = atomic_settings_router();
    let change = json!({"expectedRevision":"1","set":{"transfers":{"upload":{"baseSlots":4}}}});
    assert_eq!(
        atomic_settings_response(&app, "PATCH", change.clone())
            .await
            .0,
        StatusCode::OK
    );
    let before = saved_settings_row(&sql);
    let effective = core.effective_settings().await.unwrap();
    let (status, error) = atomic_settings_response(&app, "PATCH", change).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(error["error"]["code"], "SETTINGS_CONFLICT");
    assert_eq!(error["error"]["details"]["actualRevision"], "2");
    assert_eq!(saved_settings_row(&sql), before);
    assert_eq!(core.effective_settings().await.unwrap(), effective);
}

#[tokio::test]
async fn nullable_values_arrays_omission_and_explicit_resets_preserve_saved_modes() {
    let (app, _, _, _) = atomic_settings_router();
    let (status,first)=atomic_settings_response(&app,"PATCH",json!({"expectedRevision":"1","set":{
        "network":{"nat":{"pcpServerIp":"192.0.2.1","igdIp":"192.0.2.2","backendOrder":["upnp"]}}
    }})).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, second) = atomic_settings_response(
        &app,
        "PATCH",
        json!({"expectedRevision":"2","set":{
        "network":{"nat":{"pcpServerIp":null}}
    },"reset":["network.nat.backendOrder"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second}");
    let nat = &second["data"]["saved"]["network"]["nat"];
    assert_eq!(nat["pcpServerIp"], json!({"mode":"default","value":null}));
    assert_eq!(
        nat["igdIp"],
        first["data"]["saved"]["network"]["nat"]["igdIp"]
    );
    assert_eq!(
        nat["backendOrder"],
        json!({"mode":"default","value":["pcp-natpmp","upnp"]})
    );
    let (status, third) = atomic_settings_response(
        &app,
        "PATCH",
        json!({"expectedRevision":"3","set":{"network":{"nat":{"igdIp":"192.0.2.2"}}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{third}");
    assert_eq!(third["meta"]["settingsRevision"], "4");
    assert_eq!(third["data"], second["data"]);
}

#[tokio::test]
async fn settings_validation_reports_independent_issues_and_preserves_saved_and_effective_state() {
    let (app, core, _, sql) = atomic_settings_router();
    let before = saved_settings_row(&sql);
    let effective = core.effective_settings().await.unwrap();
    let (status,error)=atomic_settings_response(&app,"PATCH",json!({"expectedRevision":"1","set":{
        "network":{"nickname":"","nat":{"enabled":"private-input"}},"transfers":{"upload":{"baseSlots":0}}
    }})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"]["code"], "INVALID_ARGUMENT");
    let issues = error["error"]["details"]["issues"].as_array().unwrap();
    assert_eq!(
        issues
            .iter()
            .map(|v| v["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "network.nickname",
            "network.nat.enabled",
            "transfers.upload.baseSlots"
        ]
    );
    assert!(!error.to_string().contains("private-input"));
    assert_eq!(saved_settings_row(&sql), before);
    assert_eq!(core.effective_settings().await.unwrap(), effective);
}

#[tokio::test]
async fn settings_sql_failure_is_http_500_and_an_explicit_retry_can_commit() {
    let (app, core, _, sql) = atomic_settings_router();
    let before = saved_settings_row(&sql);
    let effective = core.effective_settings().await.unwrap();
    let request = json!({"expectedRevision":"1","set":{"network":{"nickname":"Sample Client"},"transfers":{"uploadLimitBytesPerSecond":1048576}}});
    sql.execute_batch("CREATE TRIGGER synthetic_settings_failure BEFORE UPDATE ON app_settings BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let (status, error) = atomic_settings_response(&app, "PATCH", request.clone()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{error}");
    assert_eq!(error["error"]["code"], "PERSISTENCE_FAILED");
    assert_eq!(saved_settings_row(&sql), before);
    assert_eq!(core.effective_settings().await.unwrap(), effective);
    sql.execute_batch("DROP TRIGGER synthetic_settings_failure;")
        .unwrap();
    let (status, success) = atomic_settings_response(&app, "PATCH", request).await;
    assert_eq!(status, StatusCode::OK, "{success}");
    assert_eq!(success["meta"]["settingsRevision"], "2");
}

#[tokio::test]
async fn uncertain_settings_commit_returns_http_503_and_blocks_further_coherent_reads() {
    let (app, _, _, sql) = atomic_settings_router();
    sql.execute_batch("CREATE TABLE synthetic_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE synthetic_child(id INTEGER REFERENCES synthetic_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER synthetic_commit_failure AFTER UPDATE ON app_settings BEGIN INSERT INTO synthetic_child VALUES(1); END;").unwrap();
    let (status, error) = atomic_settings_response(
        &app,
        "PATCH",
        json!({"expectedRevision":"1","set":{"network":{"nickname":"Sample Client"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{error}");
    assert_eq!(error["error"]["code"], "PERSISTENCE_UNAVAILABLE");
    assert_eq!(
        atomic_settings_response(&app, "GET", Value::Null).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn settings_revision_exhaustion_has_an_explicit_http_conflict_code() {
    let (app, _, _, sql) = atomic_settings_router();
    sql.execute("UPDATE app_settings SET revision=?1", [i64::MAX])
        .unwrap();
    let before = saved_settings_row(&sql);
    let (status,error)=atomic_settings_response(&app,"PATCH",json!({"expectedRevision":i64::MAX.to_string(),"set":{"network":{"nickname":"Sample Client"}}})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{error}");
    assert_eq!(error["error"]["code"], "SETTINGS_REVISION_EXHAUSTED");
    assert_eq!(saved_settings_row(&sql), before);
}

#[tokio::test]
async fn restart_directory_settings_save_without_probing_or_creating_target_paths() {
    let (app, _, _, _) = atomic_settings_router();
    let target = unique_test_dir("settings-path").join("not-created");
    assert!(!target.exists());
    let (status, updated) = atomic_settings_response(
        &app,
        "PATCH",
        json!({"expectedRevision":"1","set":{"storage":{"incomingDirectory":target}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["data"]["application"]["pendingRestart"],
        json!(["storage.incomingDirectory"])
    );
    assert_eq!(
        updated["data"]["effective"]["storage"]["incomingDirectory"],
        "incoming"
    );
    assert!(!target.exists());
}

#[tokio::test]
async fn oversized_saved_candidate_returns_http_413_before_any_sql_write() {
    let (app, core, _, sql) = atomic_settings_router();
    let before = saved_settings_row(&sql);
    let effective = core.effective_settings().await.unwrap();
    let body = json!({"expectedRevision":"1","set":{"storage":{
        "incomingDirectory":"a".repeat(70000),"tempDirectory":"b".repeat(70000)
    }}});
    assert!(body.to_string().len() < emulebb_settings::product::MAX_PATCH_BYTES);
    let (status, error) = atomic_settings_response(&app, "PATCH", body).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{error}");
    assert_eq!(error["error"]["code"], "PAYLOAD_TOO_LARGE");
    assert_eq!(saved_settings_row(&sql), before);
    assert_eq!(core.effective_settings().await.unwrap(), effective);
}

#[tokio::test]
async fn settings_after_persistence_shutdown_return_http_503() {
    let (app, core, _, _) = atomic_settings_router();
    assert_eq!(
        atomic_settings_response(&app, "GET", Value::Null).await.0,
        StatusCode::OK
    );
    core.drain_persistence().await.unwrap();
    for (method, body) in [
        ("GET", Value::Null),
        (
            "PATCH",
            json!({"expectedRevision":"1","set":{"network":{"nickname":"Sample Client"}}}),
        ),
    ] {
        let (status, error) = atomic_settings_response(&app, method, body).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{error}");
        assert_eq!(error["error"]["code"], "PERSISTENCE_CLOSING");
    }
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
async fn shared_root_mutations_report_closed_persistence() {
    let root = unique_test_dir("closed-root-owner");
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
    for (method, uri, body) in [
        (
            "PATCH",
            "/api/v1/library/roots/1".to_owned(),
            json!({"watchEnabled":true}).to_string(),
        ),
        (
            "POST",
            "/api/v1/library/roots".to_owned(),
            json!({"path":root}).to_string(),
        ),
        (
            "DELETE",
            "/api/v1/library/roots/1".to_owned(),
            String::new(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("X-API-Key", "secret")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING");
    }
    std::fs::remove_dir_all(root).ok();
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
    let capture_started_at = chrono::Utc::now().timestamp();
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
    assert_eq!(value["schema"], "emulebb.diagnostic-bundle.v7");
    let captured_at = value["capturedAt"].as_i64().unwrap();
    assert!((capture_started_at..=chrono::Utc::now().timestamp()).contains(&captured_at));
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
    assert_eq!(bundle["schema"], "emulebb.diagnostic-bundle.v7");
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
    assert!(bundle["operationalSnapshots"]["downloads"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["uploads"]["items"].is_array());
    assert!(bundle["operationalSnapshots"]["uploadQueue"]["items"].is_array());
    assert!(bundle["diagnosticArtifacts"]["families"].is_array());
    assert_eq!(bundle["limits"]["artifactFamilies"], 1);
    assert_eq!(bundle["limits"]["serverSnapshots"], 512);
    assert_eq!(bundle["limits"]["sharedFileSnapshots"], 512);
    assert_eq!(bundle["limits"]["searchSnapshots"], 64);
    assert_eq!(bundle["limits"]["searchResultsPerSnapshot"], 128);
    assert_eq!(bundle["limits"]["downloadSnapshots"], 200);
    assert_eq!(bundle["limits"]["uploadSnapshots"], 200);
    assert_eq!(bundle["limits"]["uploadQueueSnapshots"], 200);
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
async fn diagnostic_capture_slot_follows_response_frames_and_their_clones() {
    use http_body_util::BodyExt;
    let app = test_router();
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/diagnostics/bundles")
            .header("X-API-Key", "secret")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"confirmCapture":true,"maxBytes":4194304}"#))
            .unwrap()
    };
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(!frame.is_empty());
    let retained = frame.clone();
    drop(frame);
    drop(body);
    let blocked = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
    let rejected: Value =
        serde_json::from_slice(&to_bytes(blocked.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(rejected["error"]["code"], "SERVICE_BUSY");
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    drop(status);
    drop(retained);
    let next = app.oneshot(request()).await.unwrap();
    assert_eq!(next.status(), StatusCode::OK);
}

#[tokio::test]
async fn failed_diagnostic_capture_releases_its_slot() {
    let (app, core, _, _) = atomic_settings_router();
    core.drain_persistence().await.unwrap();
    for _ in 0..2 {
        let response = app
            .clone()
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
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["error"]["code"], "PERSISTENCE_CLOSING");
    }
}

#[tokio::test]
async fn snapshot_returns_bounded_emulebb_polling_shape() {
    let runtime_dir = unique_test_dir("snapshot");
    let transfer_root = runtime_dir.join("transfers");
    let library_dir = runtime_dir.join("library");
    std::fs::create_dir_all(&library_dir).unwrap();
    let first_file = library_dir.join("First.Snapshot.bin");
    let second_file = library_dir.join("Second.Snapshot.bin");
    std::fs::write(&first_file, b"first snapshot payload").unwrap();
    std::fs::write(&second_file, b"second snapshot payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    core.create_library_root(&library_dir.display().to_string(), false)
        .await
        .unwrap()
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
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let value: Value = serde_json::from_slice(&body).unwrap();
    let data = &value["data"];
    assert_eq!(data["app"]["name"], "eMuleBB");
    assert_eq!(data["status"]["lifecycle"]["state"], "running");
    assert_eq!(data["downloads"], json!({"unfinished":0,"completed":0}));
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
async fn upload_queue_cursors_are_scoped_and_departed_anchors_require_refresh() {
    let app = test_router();
    let id = "12345678-1234-4234-8234-123456789abc";
    for (uri, status) in [
        (
            "/api/v1/upload-queue?limit=0".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/v1/upload-queue?limit=201".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(
                "/api/v1/upload-queue?cursor={}",
                hex::encode(format!("other-collection|{id}"))
            ),
            StatusCode::BAD_REQUEST,
        ),
        (
            format!(
                "/api/v1/upload-queue?cursor={}",
                hex::encode(format!("upload-queue|{id}"))
            ),
            StatusCode::CONFLICT,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{uri}");
        if status == StatusCode::CONFLICT {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["error"]["code"], "CONFLICT");
            assert!(
                value["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("refresh")
            );
        }
    }
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
        assert_eq!(value["data"].as_array().unwrap().len(), 0);
        assert!(value["meta"].get("total").is_none());
        assert_eq!(value["meta"]["hasMore"], false);
        assert!(value["meta"]["nextCursor"].is_null());
    }

    for collection in ["uploads", "upload-queue"] {
        let cursor = hex::encode(format!("{collection}|12345678-1234-4234-8234-123456789abc"));
        let other = if collection == "uploads" {
            "upload-queue"
        } else {
            "uploads"
        };
        let foreign = hex::encode(format!("{other}|12345678-1234-4234-8234-123456789abc"));
        for (query, expected) in [
            ("limit=1&countTotal=true".to_owned(), StatusCode::OK),
            ("limit=0".to_owned(), StatusCode::BAD_REQUEST),
            ("limit=201".to_owned(), StatusCode::BAD_REQUEST),
            (format!("cursor={foreign}"), StatusCode::BAD_REQUEST),
            (format!("cursor={cursor}"), StatusCode::CONFLICT),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/{collection}?{query}"))
                        .header("X-API-Key", "secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_eq!(status, expected, "{}", String::from_utf8_lossy(&body));
            let value: Value = serde_json::from_slice(&body).unwrap();
            if expected == StatusCode::OK {
                assert_eq!(value["meta"]["total"], 0);
                assert_eq!(value["meta"]["hasMore"], false);
                assert!(value["meta"]["nextCursor"].is_null());
            }
        }
    }

    for (path, expected_message) in [
        (
            "/api/v1/uploads/12345678-1234-4234-8234-123456789abc",
            "active upload client not found",
        ),
        (
            "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc",
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
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/remove",
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/release-slot",
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/add-friend",
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/remove-friend",
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/ban",
        "/api/v1/uploads/12345678-1234-4234-8234-123456789abc/operations/unban",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/remove",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/release-slot",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/add-friend",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/remove-friend",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/ban",
        "/api/v1/upload-queue/12345678-1234-4234-8234-123456789abc/operations/unban",
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
