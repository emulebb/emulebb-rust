use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::{EmulebbCore, LocalShareCreate};
use emulebb_index::FileIndex;
use emulebb_rest::{RestServerSettings, router};
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
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let hash = share.hash.clone();
    let ed2k_link = share.ed2k_link.clone();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
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
                    r#"{{"path":"  {}  "}}"#,
                    payload_path.display().to_string().replace('\\', "\\\\")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::METHOD_NOT_ALLOWED);

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
    assert_eq!(value["data"]["offset"], 0);
    assert_eq!(value["data"]["limit"], 100);
    assert_eq!(value["data"]["items"][0]["hash"], hash);

    let paged_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/shared-files?offset=1&limit=1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged_response.status(), StatusCode::OK);
    let body = to_bytes(paged_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 1);
    assert_eq!(value["data"]["offset"], 1);
    assert_eq!(value["data"]["limit"], 1);
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

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

    let comments_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/shared-files/{hash}/comments"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(comments_response.status(), StatusCode::OK);
    let body = to_bytes(comments_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);

    let remove_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/shared-files/{hash}"))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(remove_response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let still_shared_response = app
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
    assert_eq!(still_shared_response.status(), StatusCode::OK);

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
    assert_eq!(retired_route.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn shared_directories_use_emulebb_contract_and_reload_files() {
    let runtime_dir = unique_test_dir("shared-directories-contract");
    let transfer_root = runtime_dir.join("transfers");
    let shared_root = runtime_dir.join("shared-root");
    let extra_root = runtime_dir.join("extra-root");
    let nested_root = shared_root.join("nested");
    let top_level_file = shared_root.join("Top.Level.bin");
    let nested_file = nested_root.join("Nested.bin");
    std::fs::create_dir_all(&nested_root).unwrap();
    std::fs::create_dir_all(&extra_root).unwrap();
    std::fs::write(&top_level_file, b"top level shared payload").unwrap();
    std::fs::write(&nested_file, b"nested shared payload").unwrap();
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

    let rejected_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/shared-directories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"roots":["{}"],"confirmReplaceRoots":false}}"#,
                    shared_root.display().to_string().replace('\\', "\\\\")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected_response.status(), StatusCode::BAD_REQUEST);

    let update_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/shared-directories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(format!(
                    r#"{{"roots":[{{"path":"{}"}}],"confirmReplaceRoots":true}}"#,
                    shared_root.display().to_string().replace('\\', "\\\\")
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);
    let body = to_bytes(update_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["roots"][0]["accessible"], true);
    assert_eq!(value["data"]["roots"][0]["monitorOwned"], false);
    // A PATCH now kicks a detached background scan + hash of the files already
    // present under the new roots, so `hashingCount` reflects that queued work
    // (it drains to 0 in the background; the two files are picked up below). It is
    // a non-negative count, not necessarily 0 the instant the PATCH returns.
    assert!(
        value["data"]["hashingCount"]
            .as_i64()
            .expect("hashingCount is an integer")
            >= 0
    );

    let add_body = format!(
        r#"{{"path":"{}"}}"#,
        extra_root.display().to_string().replace('\\', "\\\\")
    );
    let add_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/shared-directories/roots")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(add_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_response.status(), StatusCode::OK);
    let body = to_bytes(add_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["roots"].as_array().unwrap().len(), 2);

    let add_again_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/shared-directories/roots")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(add_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_again_response.status(), StatusCode::OK);
    let body = to_bytes(add_again_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["roots"].as_array().unwrap().len(), 2);

    let remove_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/shared-directories/roots?path={}",
                    encode_query_value(&extra_root.display().to_string())
                ))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let remove_status = remove_response.status();
    let body = to_bytes(remove_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(remove_status, StatusCode::OK, "{value}");
    assert_eq!(value["data"]["roots"].as_array().unwrap().len(), 1);

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/shared-directories")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);
    let body = to_bytes(get_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"]["reloadProgress"]["phase"].is_string());
    assert!(value["data"]["reloadProgress"]["plannedReadBytes"].is_u64());
    assert!(value["data"]["reloadProgress"]["active"].is_array());
    assert!(value["data"]["reloadProgress"]["disks"].is_array());

    let reload_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/shared-directories/operations/reload")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reload_response.status(), StatusCode::OK);
    let body = to_bytes(reload_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);
    assert!(value["data"].get("count").is_none());

    // The reload hashes the library on a detached background task (independent of
    // the request), so the shared-files list fills in asynchronously. Poll until
    // both files appear rather than expecting them synchronously after the POST.
    let mut names: Vec<String> = Vec::new();
    for _ in 0..200 {
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
        names = value["data"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        if names.iter().any(|name| name == "Top.Level.bin")
            && names.iter().any(|name| name == "Nested.bin")
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(names.iter().any(|name| name == "Top.Level.bin"));
    assert!(names.iter().any(|name| name == "Nested.bin"));
}

fn unique_test_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

fn encode_query_value(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![char::from(byte)]
            }
            _ => format!("%{byte:02X}").chars().collect::<Vec<_>>(),
        })
        .collect()
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
