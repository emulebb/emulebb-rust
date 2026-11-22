use std::sync::Arc;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::EmulebbCore;
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
        let definition = emulebb_metadata::MetadataServerCreate {
            address: format!("192.0.2.{index}"),
            port: 4661,
            priority: "normal".into(),
            static_server: true,
            enabled: true,
        };
        core.create_server_resource(&definition).await.unwrap();
        core.import_server_resource(&emulebb_metadata::MetadataServerImport {
            address: definition.address,
            port: definition.port,
            name: Some(format!("snapshot-server-{index}")),
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

#[tokio::test]
async fn retained_snapshot_frames_share_capacity_and_release_after_final_drop() {
    use http_body_util::BodyExt;

    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    for index in 0..16 {
        core.import_server_resource(&emulebb_metadata::MetadataServerImport {
            address: format!("192.0.2.{}", index + 30),
            port: 4661,
            name: Some("x".repeat(65_535)),
        })
        .await
        .unwrap();
    }
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_owned(),
            web_root_dir: None,
        },
    );
    let request = || {
        Request::builder()
            .uri("/api/v1/snapshot?limit=1")
            .header("X-API-Key", "secret")
            .body(Body::empty())
            .unwrap()
    };
    let mut retained = Vec::new();
    let mut refused = false;
    for _ in 0..8 {
        let response = app.clone().oneshot(request()).await.unwrap();
        if response.status() == StatusCode::SERVICE_UNAVAILABLE {
            let error: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(error["error"]["code"], "PERSISTENCE_BUSY");
            refused = true;
            break;
        }
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(frame.len() > 1024 * 1024);
        let document: Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(document["meta"]["apiVersion"], "v1");
        assert_eq!(document["data"]["downloads"]["unfinished"], 0);
        retained.push(frame.clone());
        drop(frame);
        drop(body);
    }
    assert!(!retained.is_empty());
    assert!(
        refused,
        "retained snapshot backing must exhaust shared capacity"
    );
    drop(retained);
    let recovered = app.oneshot(request()).await.unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
}

#[path = "../../../emulebb-core/tests/support/discovery_fixture.rs"]
mod discovery_fixture;

#[tokio::test]
async fn discovery_import_http_waits_for_completion_and_rejects_zero_usable_records() {
    use crate::rest_test_support::request;
    use discovery_fixture::{Reply, server};
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    for (path, bytes) in [
        (
            "/api/v1/servers/operations/import-met-url",
            vec![0x0e, 0, 0, 0, 0],
        ),
        ("/api/v1/kad/operations/import-nodes-url", vec![0, 0, 0, 0]),
    ] {
        let source = server(vec![Reply::body(&bytes)]).await;
        let redirect = server(vec![Reply::redirect(&source.url)]).await;
        let (status, body) = request(
            &app,
            "POST",
            path,
            Some(serde_json::json!({"url": redirect.url})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "INVALID_ARGUMENT");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no usable records")
        );
        assert_eq!(source.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(redirect.hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    let mut bytes = vec![0x0e];
    bytes.extend_from_slice(&3u32.to_le_bytes());
    for ip in [[0; 4], [192, 0, 2, 9]] {
        bytes.extend_from_slice(&ip);
        bytes.extend_from_slice(&4661u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.push(192);
    let source = server(vec![Reply::body(&bytes)]).await;
    let (status, body) = request(
        &app,
        "POST",
        "/api/v1/servers/operations/import-met-url",
        Some(serde_json::json!({"url":source.url})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["imported"], true);
    let (_, page) = request(&app, "GET", "/api/v1/servers", None).await;
    assert_eq!(page["data"].as_array().unwrap().len(), 1);
    assert_eq!(page["data"][0]["address"], "192.0.2.9");
}
