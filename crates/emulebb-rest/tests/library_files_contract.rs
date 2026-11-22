use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use emulebb_core::{EmulebbCore, LocalShareCreate, long_path, normal_path_display};
use emulebb_index::FileIndex;
use emulebb_rest::{RestServerSettings, router};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn library_files_use_canonical_route_and_envelope() {
    let runtime_dir = unique_test_dir("library-files-canonical");
    let transfer_root = runtime_dir.join("transfers");
    let library_dir = runtime_dir.join("library");
    std::fs::create_dir_all(&library_dir).unwrap();
    let payload_path = library_dir.join("Canonical.Shared.bin");
    std::fs::write(&payload_path, b"canonical shared payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    core.create_library_root(&library_dir.display().to_string(), false)
        .await
        .unwrap()
        .unwrap();
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let hash = share.hash.clone();
    let ed2k_link = share.ed2k_link.clone();
    settle_setup_scan(&core).await;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let list = get_json(&app, "/api/v1/library/files?countTotal=true").await;
    assert_eq!(list["meta"]["total"], 1);
    assert_eq!(list["data"][0]["hash"], hash);
    assert_eq!(list["meta"]["hasMore"], false);
    let detail = get_json(&app, &format!("/api/v1/library/files/{hash}")).await;
    assert_eq!(detail["data"]["hash"], hash);
    assert_eq!(detail["data"]["ed2kLink"], ed2k_link);
    assert_eq!(detail["data"]["comment"], "");
    assert_eq!(detail["data"]["rating"], 0);
    let locations = get_json(&app, &format!("/api/v1/library/files/{hash}/locations")).await;
    assert_eq!(
        std::path::Path::new(locations["data"][0]["path"].as_str().unwrap())
            .canonicalize()
            .unwrap(),
        payload_path.canonicalize().unwrap()
    );
}

#[tokio::test]
async fn library_files_page_filename_search_and_publication_status() {
    let runtime_dir = unique_test_dir("library-files-query");
    let transfer_root = runtime_dir.join("transfers");
    let library_dir = runtime_dir.join("library");
    std::fs::create_dir_all(&library_dir).unwrap();
    let alpha_path = library_dir.join("Alpha Sample ÄBC.bin");
    let zeta_path = library_dir.join("Zeta Sample.bin");
    std::fs::write(&alpha_path, b"alpha shared payload").unwrap();
    std::fs::write(&zeta_path, b"zeta shared payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    core.create_library_root(&library_dir.display().to_string(), false)
        .await
        .unwrap()
        .unwrap();
    let alpha = core
        .share_local_file(LocalShareCreate {
            path: alpha_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let zeta = core
        .share_local_file(LocalShareCreate {
            path: zeta_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    settle_setup_scan(&core).await;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    );

    let first = get_json(&app, "/api/v1/library/files?limit=1&countTotal=true").await;
    assert_eq!(first["meta"]["total"], 2);
    assert_eq!(first["data"][0]["hash"], alpha.hash);
    let detail = get_json(&app, &format!("/api/v1/library/files/{}", alpha.hash)).await;
    assert_eq!(detail["data"]["publication"]["ed2k"]["state"], "waiting");
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let encoded_cursor = utf8_percent_encode(cursor, NON_ALPHANUMERIC).to_string();
    let second = get_json(
        &app,
        &format!("/api/v1/library/files?limit=1&countTotal=true&cursor={encoded_cursor}"),
    )
    .await;
    assert_eq!(second["data"][0]["hash"], zeta.hash);
    assert!(second["meta"]["nextCursor"].is_null());

    for query in ["q=ALPHA", "q=pha%20sam", "q=%C3%A4bc"] {
        let searched = get_json(
            &app,
            &format!("/api/v1/library/files?countTotal=true&{query}"),
        )
        .await;
        assert_eq!(searched["meta"]["total"], 1);
        assert_eq!(searched["data"][0]["hash"], alpha.hash);
    }
    for query in ["q=library".to_string(), format!("q={}", &alpha.hash[..12])] {
        let searched = get_json(
            &app,
            &format!("/api/v1/library/files?countTotal=true&{query}"),
        )
        .await;
        assert_eq!(searched["meta"]["total"], 0);
        assert!(searched["data"].as_array().unwrap().is_empty());
    }

    let filtered = get_json(
        &app,
        "/api/v1/library/files?sharingEnabled=true&countTotal=true",
    )
    .await;
    assert_eq!(filtered["meta"]["total"], 2);
    assert_eq!(
        detail["data"]["publication"]["kadSource"]["state"],
        "unavailable"
    );
}

#[tokio::test]
async fn library_location_pages_preserve_cached_paths_when_sharing_is_disabled() {
    let runtime_dir = unique_test_dir("library-location-pages");
    let library = runtime_dir.join("library");
    std::fs::create_dir_all(&library).unwrap();
    let core = Arc::new(
        EmulebbCore::new(
            "test",
            FileIndex::in_memory().unwrap(),
            runtime_dir.join("transfers"),
        )
        .unwrap(),
    );
    core.create_library_root(&library.display().to_string(), false)
        .await
        .unwrap()
        .unwrap();
    let mut hash = String::new();
    let mut paths = Vec::new();
    for n in 1..=3 {
        let path = library.join(format!("Copy-{n}.bin"));
        std::fs::write(&path, b"sample identical content").unwrap();
        let shared = core
            .share_local_file(LocalShareCreate {
                path: path.display().to_string(),
                name: None,
            })
            .await
            .unwrap();
        if hash.is_empty() {
            hash = shared.hash;
        } else {
            assert_eq!(hash, shared.hash);
        }
        paths.push(path);
    }
    let policy = core
        .set_library_sharing(&emulebb_core::LibrarySharingRequest {
            enabled: false,
            hashes: vec![hash.clone()],
        })
        .await
        .unwrap();
    assert!(matches!(
        &policy.value()[0].outcome,
        Ok(emulebb_core::LibraryFileChange::Changed)
    ));
    drop(policy);
    settle_setup_scan(&core).await;
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let base = format!("/api/v1/library/files/{hash}/locations?limit=1");
    let first = get_json(&app, &base).await;
    assert_eq!(first["data"].as_array().unwrap().len(), 1);
    assert!(
        first["data"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("Copy-1.bin")
    );
    assert_eq!(first["data"][0]["present"], true);
    assert_eq!(first["meta"]["hasMore"], true);
    let cursor = utf8_percent_encode(
        first["meta"]["nextCursor"].as_str().unwrap(),
        NON_ALPHANUMERIC,
    )
    .to_string();
    let second = get_json(&app, &format!("{base}&cursor={cursor}")).await;
    assert!(
        second["data"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("Copy-2.bin")
    );
    let cursor = utf8_percent_encode(
        second["meta"]["nextCursor"].as_str().unwrap(),
        NON_ALPHANUMERIC,
    )
    .to_string();
    let third = get_json(&app, &format!("{base}&cursor={cursor}")).await;
    assert!(
        third["data"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("Copy-3.bin")
    );
    assert_eq!(third["meta"]["hasMore"], false);
    assert!(third["meta"]["nextCursor"].is_null());
    for path in paths {
        std::fs::remove_file(path).unwrap();
    }
    let cached = get_json(&app, &base).await;
    assert_eq!(
        cached["data"], first["data"],
        "reading cached evidence must not inspect the deleted file"
    );
}

async fn settle_setup_scan(core: &EmulebbCore) {
    // Root creation schedules independent work. Exercise idle reads only after
    // setup releases its admission; capacity refusal is tested separately.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let scan = core.library_scan();
            if !scan.reload_progress.running
                && !scan.reload_progress.pending
                && scan.hashing_count == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("setup scan must settle before library reads");
}

async fn get_json(app: &axum::Router, uri: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn library_root_creation_and_scan_share_recursive_files() {
    let runtime_dir = unique_test_dir("library-roots-contract");
    let transfer_root = runtime_dir.join("transfers");
    let shared_root = runtime_dir.join("shared-root");
    let shared_root_input = long_path(&shared_root).display().to_string();
    let nested_root = shared_root.join("nested");
    let top_level_file = shared_root.join("Top.Level.bin");
    let nested_file = nested_root.join("Nested.bin");
    std::fs::create_dir_all(&nested_root).unwrap();
    let expected_shared_root = std::fs::canonicalize(long_path(&shared_root))
        .map(|path| normal_path_display(path.display().to_string()))
        .expect("shared root should canonicalize");
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

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/library/roots")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"path":shared_root_input}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let value: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
            .unwrap();
    assert_eq!(value["data"]["path"], expected_shared_root);
    assert_eq!(value["data"]["managed"], false);
    assert_eq!(value["data"]["watchEnabled"], false);
    assert!(
        value["data"]["id"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > 0
    );

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/library/scan")
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
    assert_eq!(value["data"].as_object().unwrap().len(), 2);

    let reload_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/library/scan")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reload_response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(reload_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["data"]["hashingCount"].is_i64());
    assert!(value["data"]["reloadProgress"].is_object());

    // The reload hashes the library on a detached background task (independent of
    // the request), so the library list fills in asynchronously. Poll until
    // both files appear rather than expecting them synchronously after the POST.
    let mut names: Vec<String> = Vec::new();
    for _ in 0..200 {
        let list_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/library/files")
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
        names = value["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["displayName"].as_str().unwrap().to_string())
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

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
