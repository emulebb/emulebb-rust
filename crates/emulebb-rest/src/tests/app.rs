use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::EmulebbCore;
use emulebb_index::FileIndex;
use serde_json::Value;
use tower::ServiceExt;

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
async fn snapshot_limit_clamps_like_master() {
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
    assert_eq!(zero_response.status(), StatusCode::OK);

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
    assert_eq!(large_response.status(), StatusCode::OK);
    let body = to_bytes(large_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"]["transfers"].as_array().unwrap().len() <= 1000);
    assert!(value["data"]["sharedFiles"].as_array().unwrap().len() <= 1000);
    assert!(value["data"]["uploads"].as_array().unwrap().len() <= 1000);
    assert!(value["data"]["uploadQueue"].as_array().unwrap().len() <= 1000);
    assert!(value["data"]["logs"].as_array().unwrap().len() <= 1000);
}
