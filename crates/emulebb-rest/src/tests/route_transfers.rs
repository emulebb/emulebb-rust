use crate::rest_test_support::*;

#[tokio::test]
async fn stopped_transfer_resume_returns_bad_request() {
    let app = test_router();
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"link":"ed2k://|file|Stopped.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                ))
                .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);
    let body = to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"][0]["ok"], true);
    assert_eq!(
        value["data"]["items"][0]["hash"],
        "00112233445566778899aabbccddeeff"
    );

    let recheck_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/recheck")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recheck_response.status(), StatusCode::OK);
    let body = to_bytes(recheck_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);

    let stop_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/stop")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stop_response.status(), StatusCode::OK);

    let resume_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/operations/resume")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resume_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn transfer_patch_uses_canonical_update_families() {
    let app = test_router();
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"link":"ed2k://|file|Patch.Me.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);

    let created_category = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/categories")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":"Media"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_category.status(), StatusCode::OK);

    let priority_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"priority":"veryhigh"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(priority_response.status(), StatusCode::OK);
    let body = to_bytes(priority_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["priority"], "veryhigh");

    let category_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"categoryName":"media"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(category_response.status(), StatusCode::OK);
    let body = to_bytes(category_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["categoryId"], 1);
    assert_eq!(value["data"]["categoryName"], "Media");

    let rename_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"name":" Renamed.bin "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rename_response.status(), StatusCode::OK);
    let body = to_bytes(rename_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["name"], "Renamed.bin");
    assert_eq!(value["data"]["priority"], "veryhigh");
    assert_eq!(value["data"]["categoryId"], 1);

    let multi_family_response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"priority":"high","name":"Nope.bin"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(multi_family_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_transfers_accepts_canonical_links_array() {
    let app = test_router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"links":["ed2k://|file|One.bin|1|00112233445566778899aabbccddeeff|/","ed2k://|file|Two.bin|2|ffeeddccbbaa99887766554433221100|/"],"paused":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 2);
    assert_eq!(value["data"]["items"][0]["ok"], true);
    assert_eq!(value["data"]["items"][1]["ok"], true);
    assert_eq!(
        value["data"]["items"][0]["hash"],
        "00112233445566778899aabbccddeeff"
    );
    assert_eq!(
        value["data"]["items"][1]["hash"],
        "ffeeddccbbaa99887766554433221100"
    );

    let paged = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers?state=paused&offset=1&limit=1")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paged.status(), StatusCode::OK);
    let body = to_bytes(paged.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["total"], 2);
    assert_eq!(value["data"]["offset"], 1);
    assert_eq!(value["data"]["limit"], 1);
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["items"][0]["state"], "paused");
}

#[tokio::test]
async fn delete_transfer_files_requires_confirm_and_removes_transfer() {
    let app = test_router();
    let create_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"link":"ed2k://|file|Delete.Me.bin|4096|00112233445566778899aabbccddeeff|/"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_response.status(), StatusCode::OK);

    let missing_confirm = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/files")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_confirm.status(), StatusCode::BAD_REQUEST);

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff/files?confirm=true")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
    let body = to_bytes(delete_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"][0]["ok"], true);
    assert_eq!(
        value["data"]["items"][0]["hash"],
        "00112233445566778899aabbccddeeff"
    );

    let read_after_delete = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers/00112233445566778899aabbccddeeff")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_after_delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_completed_transfer_row_preserves_files() {
    let runtime_dir = unique_test_dir("delete-completed-transfer-row");
    let transfer_root = runtime_dir.join("transfers");
    let payload_path = runtime_dir.join("Completed.Rest.Row.bin");
    std::fs::write(&payload_path, b"completed rest row payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    let share = core
        .share_local_file(LocalShareCreate {
            path: payload_path.display().to_string(),
            name: Some("Completed.Rest.Row.bin".to_string()),
        })
        .await
        .unwrap();
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".to_string(),
        },
    );

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/transfers/{}", share.hash))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::OK);
    let body = to_bytes(delete_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"][0]["ok"], true);
    assert_eq!(value["data"]["items"][0]["hash"], share.hash);
    assert!(std::path::Path::new(&share.transfer_dir).is_dir());

    let read_after_delete = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/transfers/{}", share.hash))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_after_delete.status(), StatusCode::NOT_FOUND);
    assert!(
        core.shares()
            .await
            .iter()
            .any(|entry| entry.hash == share.hash)
    );
}

#[tokio::test]
async fn clear_completed_transfers_requires_confirmation_and_preserves_files() {
    let runtime_dir = unique_test_dir("clear-completed-transfers");
    let transfer_root = runtime_dir.join("transfers");
    let first_path = runtime_dir.join("Completed.Rest.Clear.One.bin");
    let second_path = runtime_dir.join("Completed.Rest.Clear.Two.bin");
    std::fs::write(&first_path, b"completed clear row one").unwrap();
    std::fs::write(&second_path, b"completed clear row two").unwrap();
    let core = Arc::new(
        EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &transfer_root).unwrap(),
    );
    let first = core
        .share_local_file(LocalShareCreate {
            path: first_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let second = core
        .share_local_file(LocalShareCreate {
            path: second_path.display().to_string(),
            name: None,
        })
        .await
        .unwrap();
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".to_string(),
        },
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers/operations/clear-completed")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmClearCompleted":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let cleared = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/transfers/operations/clear-completed")
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"confirmClearCompleted":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    let body = to_bytes(cleared.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["ok"], true);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/transfers")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let body = to_bytes(list.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["data"]["items"].as_array().unwrap().len(), 0);
    assert!(std::path::Path::new(&first.transfer_dir).is_dir());
    assert!(std::path::Path::new(&second.transfer_dir).is_dir());
    assert_eq!(core.shares().await.len(), 2);

    let delete_shared_file = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/shared-files/{}/file?confirm=true",
                    first.hash
                ))
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_shared_file.status(), StatusCode::OK);
    assert!(!std::path::Path::new(&first.transfer_dir).exists());
}
