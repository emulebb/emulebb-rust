use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::EmulebbCore;
use emulebb_index::FileIndex;
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

use crate::{RestConfig, log_buffer, record_log, router};

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
async fn logs_limit_matches_master_query_semantics() {
    let _guard = log_buffer::test_log_guard().await;
    log_buffer::clear_logs();
    record_log("info", "oldest log", false);
    record_log("warning", "middle log", false);
    record_log("error", "newest log", true);
    let app = test_router();

    let limited = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/logs?limit=1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::OK);
    let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["items"][0]["message"], "newest log");
    assert_eq!(value["data"]["items"][0]["level"], "error");
    assert_eq!(value["data"]["items"][0]["debug"], true);

    let default_limit = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/logs")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(default_limit.status(), StatusCode::OK);
    let body = to_bytes(default_limit.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 3);

    let zero_is_clamped = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/logs?limit=0")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(zero_is_clamped.status(), StatusCode::OK);
    let body = to_bytes(zero_is_clamped.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    log_buffer::clear_logs();
}

#[tokio::test]
async fn snapshot_includes_bounded_recent_logs() {
    let _guard = log_buffer::test_log_guard().await;
    log_buffer::clear_logs();
    record_log("info", "older snapshot log", false);
    record_log("warning", "newer snapshot log", true);
    let app = test_router();

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
    assert_eq!(value["data"]["logs"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["logs"][0]["message"], "newer snapshot log");
    assert_eq!(value["data"]["logs"][0]["level"], "warning");
    assert_eq!(value["data"]["logs"][0]["debug"], true);
    log_buffer::clear_logs();
}

#[tokio::test]
async fn logs_clear_requires_canonical_confirmation() {
    let _guard = log_buffer::test_log_guard().await;
    let app = test_router();

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/logs/operations/clear")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmClearLogs":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let cleared = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/logs/operations/clear")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmClearLogs":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
}
