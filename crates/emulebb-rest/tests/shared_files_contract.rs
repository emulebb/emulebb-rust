use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::EmulebbCore;
use emulebb_index::FileIndex;
use emulebb_rest::{RestConfig, router};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn shared_files_use_canonical_route_and_envelope() {
    let runtime_dir = unique_test_dir("shared-files-canonical");
    let transfer_root = runtime_dir.join("transfers");
    let payload_path = runtime_dir.join("Canonical.Shared.bin");
    std::fs::write(&payload_path, b"canonical shared payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    let app = router(
        core,
        RestConfig {
            api_key: "secret".to_string(),
        },
    );

    let create_response = app
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
    assert_eq!(create_response.status(), StatusCode::OK);
    let body = to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert_eq!(value["data"]["queued"], false);
    assert_eq!(value["data"]["file"]["name"], "Canonical.Shared.bin");
    assert_eq!(value["data"]["file"]["complete"], true);
    assert_eq!(value["data"]["file"]["partCount"], 1);
    let hash = value["data"]["file"]["hash"].as_str().unwrap().to_string();
    let ed2k_link = value["data"]["file"]["ed2kLink"]
        .as_str()
        .unwrap()
        .to_string();

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/shared-files")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let body = to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 1);
    assert_eq!(value["data"]["items"][0]["hash"], hash);

    let read_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/shared-files/{hash}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_response.status(), StatusCode::OK);
    let body = to_bytes(read_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["hash"], hash);
    assert_eq!(value["data"]["ed2kLink"], ed2k_link);

    let link_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/shared-files/{hash}/ed2k-link"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(link_response.status(), StatusCode::OK);
    let body = to_bytes(link_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["hash"], hash);
    assert_eq!(value["data"]["link"], ed2k_link);

    let retired_route = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/shares")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retired_route.status(), StatusCode::NOT_IMPLEMENTED);
}

fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "emulebb-rest-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create test dir");
    path
}
