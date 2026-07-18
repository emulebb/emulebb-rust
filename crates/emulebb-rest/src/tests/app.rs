use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use emulebb_core::{EmulebbCore, LocalShareCreate, TransferCreate};
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
        "1.2.0"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["meta"]["apiVersion"], "v1");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert_eq!(value["data"]["name"], "eMuleBB");
    assert_eq!(value["data"]["capabilities"]["transfers"], true);
    assert_eq!(value["data"]["capabilities"]["transfers.sse"], true);
    assert_eq!(value["data"]["capabilities"]["sharedDirectories"], true);
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
    assert_eq!(value["data"]["contractVersion"], "1.2.0");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "transfers")
    );
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "transfers.sse")
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
                .uri("/api/v1/app/settings/surface")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    let settings = value["data"]["settings"].as_array().unwrap();
    assert!(settings.iter().any(|entry| {
        entry["path"] == "core.uploadLimitKiBps"
            && entry["class"] == "normalControl"
            && entry["route"] == "/api/v1/app/settings"
    }));
    assert!(settings.iter().any(|entry| {
        entry["path"] == "daemon.ed2kUserHash" && entry["class"] == "notUserFacing"
    }));
    assert!(!settings.iter().any(|entry| entry["path"] == "rest.apiKey"));

    let section_resources = value["data"]["sectionResources"].as_array().unwrap();
    assert!(section_resources.iter().any(|entry| {
        entry["name"] == "diagnostics"
            && entry["class"] == "existingSectionResource"
            && entry["route"] == "/api/v1/diagnostics"
    }));
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
        "1.2.0"
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
        "1.2.0"
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
                .header("Last-Event-ID", "17")
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
    assert!(text.contains("id: 1"), "{text}");
    assert!(text.contains(r#""id":1"#), "{text}");
    assert!(text.contains(r#""type":"sync.reset""#), "{text}");
    assert!(text.contains(r#""reason":"last-event-id""#), "{text}");
    assert!(text.contains(r#""lastEventId":"17""#), "{text}");
}

#[tokio::test]
async fn events_endpoint_streams_transfer_add_events() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let router = router(
        core.clone(),
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );
    let response = router
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
    let mut body = response.into_body().into_data_stream();

    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Route.Event.bin|4096|00112233445566778899aabbccddeeff|/".to_string(),
            ),
            links: None,
            category_id: None,
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();

    let chunk = tokio::time::timeout(Duration::from_secs(1), body.next())
        .await
        .expect("transfer add event")
        .expect("SSE data frame")
        .expect("valid body chunk");
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    assert!(text.contains("event: transfer.added"), "{text}");
    assert!(text.contains("id: 1"), "{text}");
    assert!(text.contains(r#""type":"transfer.added""#), "{text}");
    assert!(
        text.contains(&format!(r#""hash":"{}""#, transfer.hash)),
        "{text}"
    );
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
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Active.bin|1|00112233445566778899aabbccddeeff|/"],"paused":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);

    let create_paused = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Paused.bin|2|ffeeddccbbaa99887766554433221100|/"],"paused":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_paused.status(), StatusCode::OK);

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
    assert_eq!(value["data"]["activeDownloads"], 1);
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
async fn diagnostics_returns_runtime_diagnostics_directly() {
    let router = test_router();

    let create_active = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|Diagnostic.Active.bin|1|00112233445566778899aabbccddeeff|/"],"paused":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_active.status(), StatusCode::OK);

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
    assert_eq!(value["data"]["transferEvents"]["enabled"], true);
    assert_eq!(value["data"]["transferEvents"]["stream"], "sse");
    assert_eq!(value["data"]["transferEvents"]["channelCapacity"], 1024);
    assert_eq!(value["data"]["transferEvents"]["subscriberCount"], 0);
    assert_eq!(value["data"]["transferEvents"]["latestEventId"], 2);
    assert_eq!(value["data"]["transferEvents"]["nextEventId"], 3);
    assert_eq!(value["data"]["transferEvents"]["resumeBehavior"], "reset");
    assert_eq!(value["data"]["geolocation"], Value::Null);
}

#[tokio::test]
async fn diagnostics_reports_transfer_event_subscribers() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let _events = core.subscribe_transfer_events();
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
    assert_eq!(value["data"]["transferEvents"]["subscriberCount"], 1);
}
