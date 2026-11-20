use crate::rest_test_support::*;

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    body.map(|value| value.to_string()).unwrap_or_default(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, value)
}

#[tokio::test]
async fn root_resources_preserve_identity_ownership_and_independent_watch_policy() {
    let temp = unique_test_dir("library-root-resources");
    let incoming = temp.join("incoming");
    let parent = temp.join("library");
    let child = parent.join("rare");
    let sibling = temp.join("library-other");
    for path in [&incoming, &child, &sibling] {
        std::fs::create_dir_all(path).unwrap();
    }
    let payload = child.join("sample.bin");
    std::fs::write(&payload, b"preserved root payload").unwrap();
    let core = Arc::new(
        EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap())
            .unwrap()
            .with_incoming_dir(incoming),
    );
    let app = router(
        core.clone(),
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let (status, headers, created) = request(
        &app,
        "POST",
        "/api/v1/library/roots",
        Some(json!({"path":child})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let id = created["data"]["id"].as_str().unwrap().to_owned();
    assert_eq!(headers["location"], format!("/api/v1/library/roots/{id}"));
    assert_eq!(created["data"]["watchEnabled"], false);
    assert_eq!(created["data"]["scanRequired"], false);
    assert_eq!(created["data"]["managed"], false);
    for path in [&child, &parent] {
        let (status, _, value) = request(
            &app,
            "POST",
            "/api/v1/library/roots",
            Some(json!({"path":path,"watchEnabled":true})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"]["code"], "ROOT_CONFLICT");
    }
    let (status, _, second) = request(
        &app,
        "POST",
        "/api/v1/library/roots",
        Some(json!({"path":sibling,"watchEnabled":true})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(second["data"]["watchEnabled"], true);
    let uri = format!("/api/v1/library/roots/{id}");
    let (status, _, value) = request(&app, "PATCH", &uri, Some(json!({"watchEnabled":true}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["data"]["id"], id);
    assert_eq!(value["data"]["watchEnabled"], true);

    let mut cursor = None;
    let mut roots = Vec::new();
    for _ in 0..4 {
        let path = cursor.as_ref().map_or_else(
            || "/api/v1/library/roots?limit=1".to_owned(),
            |cursor| format!("/api/v1/library/roots?limit=1&cursor={cursor}"),
        );
        let (status, _, value) = request(&app, "GET", &path, None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = value["data"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        roots.push(rows[0].clone());
        cursor = value["meta"]["nextCursor"].as_str().map(str::to_owned);
        assert_eq!(value["meta"]["hasMore"], cursor.is_some());
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(roots.len(), 3);
    let managed_id = roots.iter().find(|root| root["managed"] == true).unwrap()["id"]
        .as_str()
        .unwrap();
    let managed_uri = format!("/api/v1/library/roots/{managed_id}");
    assert_eq!(
        request(
            &app,
            "PATCH",
            &managed_uri,
            Some(json!({"watchEnabled":true}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, _, value) = request(&app, "DELETE", &managed_uri, None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(value["error"]["code"], "ROOT_MANAGED");
    let (status, _, value) = request(&app, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(value.is_null());
    assert_eq!(std::fs::read(&payload).unwrap(), b"preserved root payload");
    assert_eq!(
        request(&app, "GET", &uri, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, _, replacement) = request(
        &app,
        "POST",
        "/api/v1/library/roots",
        Some(json!({"path":child})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(
        replacement["data"]["id"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > id.parse::<i64>().unwrap()
    );
    assert_eq!(
        request(&app, "PATCH", &uri, Some(json!({"watchEnabled":true})))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for path in [
        "/api/v1/library/roots/01",
        "/api/v1/library/roots?limit=101",
        "/api/v1/library/roots?cursor=invalid",
    ] {
        assert_eq!(
            request(&app, "GET", path, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, headers, scan) = request(&app, "POST", "/api/v1/library/scan", None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(headers["location"], "/api/v1/library/scan");
    assert!(scan["data"]["hashingCount"].is_number());
    assert!(scan["data"]["reloadProgress"].is_object());
    assert_eq!(
        request(&app, "GET", "/api/v1/library/scan", None).await.0,
        StatusCode::OK
    );
    core.drain_persistence().await.unwrap();
    std::fs::remove_dir_all(temp).unwrap();
}
