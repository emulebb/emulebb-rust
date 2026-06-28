use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::EmulebbCore;
use emulebb_index::FileIndex;
use serde_json::Value;
use tower::ServiceExt;

use crate::rest_test_support::unique_test_dir;
use crate::{RestConfig, router};

fn test_router() -> axum::Router {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
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
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["meta"]["apiVersion"], "v1");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert_eq!(value["data"]["name"], "eMuleBB");
    assert_eq!(value["data"]["capabilities"]["transfers"], true);
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
    assert_eq!(value["data"]["contractVersion"], "1.0.0");
    assert_eq!(value["data"]["apiVersion"], "v1");
    assert!(
        value["data"]["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|capability| capability == "transfers")
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
        value["data"]["sharedStartupCache"]["reload"]["phase"],
        "idle"
    );
    assert_eq!(
        value["data"]["runtimeDiagnostics"]["sharedReload"]["plannedHashCount"],
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
    let router = router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
        },
    );

    let create = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/shared-files")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"path":"{}"}}"#,
                    payload_path.display().to_string().replace('\\', "\\\\")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);

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
