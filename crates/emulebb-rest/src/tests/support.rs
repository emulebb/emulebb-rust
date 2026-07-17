pub(crate) use std::sync::Arc;

pub(crate) use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
pub(crate) use emulebb_core::{EmulebbCore, LocalShareCreate};
pub(crate) use emulebb_index::{FileIndex, IndexedFile};
pub(crate) use serde_json::{Value, json};
pub(crate) use tokio::sync::watch;
pub(crate) use tower::ServiceExt;

pub(crate) use crate::{RestServerSettings, router, router_with_shutdown};

pub(crate) fn test_router() -> Router {
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

pub(crate) fn test_router_with_webui(web_root_dir: std::path::PathBuf) -> Router {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: Some(web_root_dir),
        },
    )
}

pub(crate) async fn assert_invalid_json_response(
    app: Router,
    method: &str,
    uri: &str,
    body: impl Into<Body>,
    expected_message: &str,
) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(body.into())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], expected_message);
}

pub(crate) async fn assert_invalid_query_response(app: Router, method: &str, uri: &str) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "unknown query parameter: unsupportedQuery"
    );
}

pub(crate) fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = rust_test_tmp_root().join(format!(
        "emulebb-rest-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create test dir");
    path
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
