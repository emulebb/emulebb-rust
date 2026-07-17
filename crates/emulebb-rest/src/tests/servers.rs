use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::{EmulebbCore, ServerCreate};
use emulebb_index::FileIndex;
use serde_json::Value;
use tower::ServiceExt;

use crate::{RestServerSettings, router};

#[tokio::test]
async fn server_connect_reports_core_failures() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
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
                .method("POST")
                .uri("/api/v1/servers/operations/connect")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("ED2K network is not configured")
    );
}

#[tokio::test]
async fn snapshot_limit_does_not_truncate_servers() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    for index in 1..=2 {
        core.add_server(ServerCreate {
            address: format!("192.0.2.{index}"),
            port: 4661,
            name: Some(format!("snapshot-server-{index}")),
            priority: None,
            static_server: Some(true),
            connect: None,
        })
        .await
        .unwrap();
    }
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
    assert_eq!(value["data"]["servers"].as_array().unwrap().len(), 2);
    assert_eq!(value["data"]["servers"][0]["name"], "snapshot-server-1");
    assert_eq!(value["data"]["servers"][1]["name"], "snapshot-server-2");
}
