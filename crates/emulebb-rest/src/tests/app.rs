use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use emulebb_core::{EmulebbCore, LocalShareCreate};
use emulebb_index::FileIndex;
use futures_util::StreamExt;
use serde_json::Value;
use tower::ServiceExt;

use crate::rest_test_support::unique_test_dir;
use crate::{RestServerSettings, router};

fn test_router() -> axum::Router {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    )
}

fn assert_disabled_diagnostic_writer(writer: &Value) {
    assert_eq!(writer["schema"], "diag_event_v2");
    assert_eq!(writer["enabled"], false);
    assert_eq!(writer["configured"], false);
    assert_eq!(writer["initialized"], false);
    assert_eq!(writer["droppedEvents"], 0);
    assert_eq!(writer["retentionScanErrors"], 0);
    assert_eq!(writer["freeSpaceProbeErrors"], 0);
    assert_eq!(writer["storagePolicyDrops"], 0);
    assert_eq!(writer["storageFaultDrops"], 0);
    assert_eq!(writer["writerFaultDrops"], 0);
    assert_eq!(writer["storageAuthorityFaulted"], false);
    assert_eq!(writer["writerIoFaulted"], false);
    assert_eq!(writer["storageBlockReason"], Value::Null);
    assert_eq!(writer["storagePolicySatisfied"], Value::Null);
    assert_eq!(writer["availableBytes"], Value::Null);
    assert_eq!(writer["maximumGrowthBytes"], Value::Null);
    assert_eq!(writer["maxTotalBytes"], Value::Null);
    assert_eq!(writer["maxRetainedSeconds"], Value::Null);
    assert_eq!(writer["minimumFreeBytes"], Value::Null);
}

#[tokio::test]
async fn healthz_is_unauthenticated_and_tracks_readiness() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let router = router(
        core.clone(),
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let ready = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::NO_CONTENT);
    assert_eq!(ready.headers()["x-emulebb-instance"], core.instance_id());
    assert_eq!(core.clone().instance_id(), core.instance_id());
    let another = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
    assert_ne!(another.instance_id(), core.instance_id());
    assert_eq!(
        ready.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
    assert!(
        to_bytes(ready.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );

    core.begin_shutdown();
    let shutting_down = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shutting_down.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        shutting_down.headers()["x-emulebb-instance"],
        core.instance_id()
    );
}

#[tokio::test]
async fn app_returns_evelope_with_capabilities() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/app")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-contract-version").unwrap(),
        "2.0.0"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["meta"]["apiVersion"], "v1");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert_eq!(value["data"]["name"], "eMuleBB");
    assert_eq!(value["data"]["channel"], emulebb_core::BUILD_CHANNEL);
    assert_eq!(
        value["data"]["sourceRevision"],
        emulebb_core::BUILD_SOURCE_REVISION
    );
    assert_eq!(value["data"]["platform"], emulebb_core::BUILD_ARCHITECTURE);
    assert_eq!(value["data"]["build"], emulebb_core::BUILD_FLAVOR);
    assert_eq!(value["data"]["capabilities"]["downloads"], true);
    assert_eq!(value["data"]["capabilities"]["downloads.sse"], true);
    assert_eq!(value["data"]["capabilities"]["downloads.sse.status"], true);
    assert_eq!(value["data"]["capabilities"]["libraryRoots"], true);
    assert_eq!(value["data"]["capabilities"]["peerControls"], true);
    assert!(
        value["data"]["capabilities"]
            .get("rest.emulebb.v1")
            .is_none()
    );
}

#[tokio::test]
async fn capabilities_returns_contract_version_and_capability_list() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/capabilities")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["contractVersion"], "2.0.0");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "downloads")
    );
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "downloads.sse")
    );
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "downloads.sse.status")
    );
    assert!(
        !value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "rest.emulebb.v1")
    );
}

#[tokio::test]
async fn settings_surface_describes_settings_fields_and_section_resources() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/settings/surface")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let fields = value["data"]["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 59);
    assert_eq!(
        value["data"]["schemas"],
        emulebb_settings::product::settings_schemas()
    );
    let keys = fields
        .iter()
        .map(|field| field["key"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(keys.len(), 59);
    assert!(fields.iter().any(
        |field| field["key"] == "transfers.uploadLimitBytesPerSecond"
            && field["application"] == "live"
            && field["unit"] == "bytes per second"
    ));
    assert!(
        fields
            .iter()
            .any(|field| field["key"] == "network.p2p.bindIp"
                && field["nullable"] == true
                && field["defaultValue"].is_null())
    );
    let bootstrap = value["data"]["bootstrap"].as_array().unwrap();
    assert_eq!(bootstrap.len(), 3);
    assert!(
        bootstrap
            .iter()
            .all(|entry| entry["class"] == "bootstrapOnly"
                && entry["restartRequired"] == true
                && entry.get("value").is_none())
    );
    assert!(
        bootstrap
            .iter()
            .any(|entry| entry["path"] == "rest.api_key")
    );
    assert!(
        value["data"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "libraryRoots"
                && entry["route"] == "/api/v1/library/roots")
    );
}

#[tokio::test]
async fn settings_surface_section_resources_resolve_to_live_get_routes() {
    let router = test_router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/settings/surface")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let section_resources = value["data"]["resources"].as_array().unwrap();

    for resource in section_resources {
        let route = resource["route"].as_str().unwrap();
        assert!(
            route.starts_with("/api/v1/"),
            "section resource route must stay in REST v1: {route}"
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(route)
                    .header("X-API-Key", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "section resource route must be a live GET route: {route}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            value.get("data").is_some(),
            "section resource route must return a data envelope: {route}"
        );
    }
}

#[tokio::test]
async fn events_endpoint_requires_auth_and_serves_sse() {
    let unauthorized = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.headers().get("x-contract-version").unwrap(),
        "2.0.0"
    );

    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    assert_eq!(
        response.headers().get("x-contract-version").unwrap(),
        "2.0.0"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache, no-transform"
    );
    assert_eq!(response.headers().get("x-accel-buffering").unwrap(), "no");
}

#[tokio::test]
async fn events_endpoint_signals_rebaseline_for_last_event_id() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header("X-API-Key", "secret")
                .header("Last-Event-ID", "f2db31c4-4225-408f-9dda-4799869e7b2b:17")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body().into_data_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(1), body.next())
        .await
        .expect("resume reset event")
        .expect("SSE data frame")
        .expect("valid body chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    assert!(text.contains("event: sync.reset"), "{text}");
    let payload: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    let epoch = payload["epoch"].as_str().unwrap();
    assert!(text.contains(&format!("id: {epoch}:0")), "{text}");
    assert_eq!(payload["id"], 0);
    assert!(text.contains(r#""type":"sync.reset""#), "{text}");
    assert_eq!(payload["reason"], "reconnect");
}

#[tokio::test]
async fn event_status_returns_download_event_diagnostics() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let _events =
        core.subscribe_download_events(emulebb_core::DownloadEventResetReason::Initial, None);
    let router = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/events/status")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], true);
    assert_eq!(value["data"]["stream"], "sse");
    assert_eq!(value["data"]["channelCapacity"], 1024);
    assert_eq!(value["data"]["queuedEventCount"], 0);
    assert_eq!(value["data"]["subscriberCount"], 1);
    assert_eq!(value["data"]["latestEventId"], 0);
    assert_eq!(value["data"]["nextEventId"], 1);
    assert_eq!(value["data"]["resumeBehavior"], "reset");
}

#[tokio::test]
async fn snapshot_limit_rejects_out_of_range_values_like_master() {
    let zero_response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/snapshot?limit=0")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(zero_response.status(), StatusCode::BAD_REQUEST);

    let large_response = test_router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/snapshot?limit=5000")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(large_response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(large_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], "limit is out of range");
    assert_eq!(value["error"]["details"]["field"], "limit");
    assert_eq!(value["error"]["details"]["constraint"], "1..1000");
}

#[tokio::test]
async fn stats_distinguish_active_downloads_from_total_queue() {
    let router = test_router();

    let create = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/downloads")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"source":{"type":"ed2k-link","link":"ed2k://|file|Active.bin|1|00112233445566778899aabbccddeeff|/"},"intent":"started"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);

    let create_stopped = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/downloads")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"source":{"type":"ed2k-link","link":"ed2k://|file|Stopped.bin|2|ffeeddccbbaa99887766554433221100|/"},"intent":"stopped"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_stopped.status(), StatusCode::CREATED);

    let stats = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/stats")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stats.status(), StatusCode::OK);
    let body = to_bytes(stats.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["downloadResources"]["waiting"], 1);
    assert_eq!(value["data"]["downloadResources"]["active"], 0);
    assert_eq!(value["data"]["downloadResources"]["preparing"], 0);
    assert_eq!(
        value["data"]["downloadResources"]["concurrency"]["mode"],
        "automatic"
    );
    assert_eq!(
        value["data"]["downloadResources"]["concurrency"]["configuredLimit"],
        Value::Null
    );
    assert_eq!(
        value["data"]["downloadResources"]["residentMemory"]["limitBytes"],
        128 * 1024 * 1024
    );
    assert_eq!(value["data"]["downloadCount"], 2);
    assert_eq!(value["data"]["sharedHashingActive"], false);
    assert_eq!(value["data"]["sharedHashingCount"], 0);
    assert_eq!(value["data"]["sharedFilesReady"], true);

    let status = router
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
    let body = to_bytes(status.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["runtimeDiagnostics"]["downloadFileCount"], 2);
    assert_eq!(value["data"]["sharedStartupCache"]["hashingCount"], 0);
    assert_eq!(
        value["data"]["sharedStartupCache"]["reloadProgress"]["phase"],
        "idle"
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["sharedDirectoryReloadProgress"]["plannedHashCount"],
        0
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["ed2kPublish"]["phase"],
        "idle"
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["ed2kPublish"]["running"],
        false
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["kadPublish"]["phase"],
        "idle"
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["kadPublish"]["running"],
        false
    );
    assert_eq!(
        value["data"]["sharedStartupCache"]["deferredHashingActive"],
        false
    );
    assert_eq!(value["data"]["runtimeDiagnostics"]["sharedHashingCount"], 0);
}

#[tokio::test]
async fn status_reports_shared_catalog_count_without_catalog_listing() {
    let runtime_dir = unique_test_dir("status-shared-count");
    let payload_path = runtime_dir.join("Shared.Count.bin");
    std::fs::write(&payload_path, b"shared count payload").unwrap();
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.create_library_root(&runtime_dir.display().to_string(), false)
        .await
        .unwrap()
        .unwrap();
    core.share_local_file(LocalShareCreate {
        path: payload_path.display().to_string(),
        name: None,
    })
    .await
    .unwrap();
    let router = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let status = router
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
    let body = to_bytes(status.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["runtimeDiagnostics"]["knownFileCount"], 1);
    assert_eq!(value["data"]["runtimeDiagnostics"]["sharedFileCount"], 1);
}

#[tokio::test]
async fn diagnostic_writer_health_is_exposed_on_status_and_snapshot() {
    let router = test_router();
    for (path, pointer) in [
        (
            "/api/v1/status",
            "/data/runtimeDiagnostics/diagnosticWriter",
        ),
        (
            "/api/v1/snapshot",
            "/data/status/runtimeDiagnostics/diagnosticWriter",
        ),
    ] {
        let response = router
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
        assert_disabled_diagnostic_writer(value.pointer(pointer).unwrap());
    }
}

#[tokio::test]
async fn diagnostics_returns_runtime_diagnostics_directly() {
    let router = test_router();

    let create_active = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/downloads")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"source":{"type":"ed2k-link","link":"ed2k://|file|Diagnostic.Active.bin|1|00112233445566778899aabbccddeeff|/"},"intent":"started"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_active.status(), StatusCode::CREATED);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/diagnostics")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["downloadFileCount"], 1);
    assert_eq!(value["data"]["sharedHashingCount"], 0);
    assert_eq!(
        value["data"]["sharedDirectoryReloadProgress"]["phase"],
        "idle"
    );
    assert_eq!(value["data"]["ed2kPublish"]["phase"], "idle");
    assert_eq!(value["data"]["kadPublish"]["phase"], "idle");
    assert_disabled_diagnostic_writer(&value["data"]["diagnosticWriter"]);
    assert_eq!(
        value["data"]["diagnosticWriter"]["processId"],
        std::process::id()
    );
    assert_eq!(value["data"]["downloadEvents"]["enabled"], true);
    assert_eq!(value["data"]["downloadEvents"]["stream"], "sse");
    assert_eq!(value["data"]["downloadEvents"]["channelCapacity"], 1024);
    assert_eq!(value["data"]["downloadEvents"]["subscriberCount"], 0);
    let latest_event_id = value["data"]["downloadEvents"]["latestEventId"]
        .as_u64()
        .expect("latest event id should be numeric");
    assert!(latest_event_id >= 1);
    assert_eq!(
        value["data"]["downloadEvents"]["nextEventId"].as_u64(),
        Some(latest_event_id + 1)
    );
    assert_eq!(value["data"]["downloadEvents"]["resumeBehavior"], "reset");
    assert_eq!(value["data"]["geolocation"], Value::Null);
}

#[tokio::test]
async fn process_resources_are_exposed_on_every_runtime_diagnostics_surface() {
    let router = test_router();
    for (path, pointer) in [
        ("/api/v1/diagnostics", "/data/processResources"),
        (
            "/api/v1/status",
            "/data/runtimeDiagnostics/processResources",
        ),
        (
            "/api/v1/snapshot",
            "/data/status/runtimeDiagnostics/processResources",
        ),
    ] {
        let response = router
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
        let resources = value.pointer(pointer).unwrap();
        assert!(resources["sampledAt"].as_i64().unwrap() > 0);
        assert!(resources["residentMemoryBytes"].as_u64().unwrap() > 0);
        assert!(resources.get("cpuUsagePercent").is_some());
        assert!(resources.get("cpuSampleIntervalMs").is_some());
    }
}

#[tokio::test]
async fn diagnostics_reports_download_event_subscribers() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let _events =
        core.subscribe_download_events(emulebb_core::DownloadEventResetReason::Initial, None);
    let router = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/diagnostics")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["downloadEvents"]["subscriberCount"], 1);
}

#[tokio::test]
async fn vpn_guard_returns_runtime_status_directly() {
    let router = test_router();

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/vpn-guard")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);
    assert_eq!(value["data"]["mode"], "off");
    assert_eq!(value["data"]["startupBlocked"], false);
    assert_eq!(value["data"]["egressVerified"], false);
    assert_eq!(value["data"]["stunProbe"]["attempted"], false);
    assert_eq!(value["data"]["httpProbe"]["attempted"], false);
}

#[tokio::test]
async fn vpn_guard_probe_returns_refreshed_runtime_status() {
    let router = test_router();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/vpn-guard/operations/probe")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);
    assert_eq!(value["data"]["mode"], "off");
    assert_eq!(value["data"]["startupBlocked"], false);
    assert_eq!(value["data"]["egressVerified"], false);
    assert_eq!(value["data"]["stunProbe"]["attempted"], false);
    assert_eq!(value["data"]["httpProbe"]["attempted"], false);
}

#[tokio::test]
async fn network_returns_runtime_binding_status_directly() {
    let router = test_router();

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/network")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ports"]["tcp"], 0);
    assert_eq!(value["data"]["ports"]["udp"], 0);
    assert!(value["data"]["ports"]["serverUdp"].is_null());
    assert_eq!(value["data"]["binding"]["resolveResult"], "default");
    assert_eq!(value["data"]["vpnGuard"]["enabled"], false);
}

#[tokio::test]
async fn nat_returns_runtime_mapping_status_directly() {
    let router = test_router();

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/nat")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);
    assert_eq!(value["data"]["gatewayDiscovered"], false);
    assert_eq!(value["data"]["gateway"], Value::Null);
    assert_eq!(value["data"]["mappings"].as_array().unwrap().len(), 0);
    assert_eq!(
        value["data"]["observedExternalAddresses"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn nat_refresh_returns_runtime_mapping_status() {
    let router = test_router();

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/nat/operations/refresh")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["enabled"], false);
    assert_eq!(value["data"]["gatewayDiscovered"], false);
    assert_eq!(value["data"]["gateway"], Value::Null);
    assert_eq!(value["data"]["mappings"].as_array().unwrap().len(), 0);
    assert_eq!(
        value["data"]["observedExternalAddresses"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn ip_filter_reports_default_status_and_reload_shape() {
    let router = test_router();

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/ip-filter")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["configured"], false);
    assert_eq!(value["data"]["reloadable"], false);
    assert_eq!(value["data"]["level"], 127);
    assert_eq!(value["data"]["rangeCount"], 0);
    assert!(value["data"].get("path").is_none());
    assert!(value["data"].get("loadedSha256").is_none());

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ip-filter/operations/reload")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["configured"], false);
    assert_eq!(value["data"]["reloadable"], false);
    assert_eq!(value["data"]["rangeCount"], 0);
}
