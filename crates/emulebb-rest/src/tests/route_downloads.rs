use crate::rest_test_support::*;
use futures_util::StreamExt;

#[tokio::test]
async fn stream_baseline_precedes_identity_only_create_and_remove_notifications() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut stream = response.into_body().into_data_stream();
    let baseline = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(baseline.to_vec()).unwrap();
    let baseline: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(baseline["type"], "sync.reset");
    assert_eq!(baseline["reason"], "initial");
    let epoch = baseline["epoch"].as_str().unwrap();
    create(&app, 0x71, None, "stopped").await;
    let changed = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(changed.to_vec()).unwrap();
    let changed: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        changed,
        json!({"type":"download.changed","id":1,"epoch":epoch,"downloadId":"1"})
    );
    assert!(text.contains(&format!("id: {epoch}:1")));
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/downloads/remove",
        Some(json!({"ids":["1"],"deleteData":false})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    let removed = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(removed.to_vec()).unwrap();
    let removed: Value = serde_json::from_str(
        text.lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        removed,
        json!({"type":"download.removed","id":2,"epoch":epoch,"downloadId":"1"})
    );
}

async fn create(app: &Router, hash: u8, size: Option<u64>, intent: &str) -> Value {
    let (status,value)=request(app,"POST","/api/v1/downloads",Some(json!({
        "source":{"type":"content","hash":format!("{hash:02x}").repeat(16),"name":"Sample.bin","sizeBytes":size},"intent":intent
    }))).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["data"].clone()
}

#[tokio::test]
async fn creation_uses_durable_ids_and_preserves_active_duplicate_fields() {
    let app = test_router();
    let first = create(&app, 0x31, None, "stopped").await;
    assert_eq!(first["id"], "1");
    assert_eq!(first["sizeBytes"], Value::Null);
    assert_eq!(first["progress"], Value::Null);
    assert_eq!(first["intent"], "stopped");
    assert!(first["createdAt"].as_i64().unwrap() < 10_000_000_000);
    let (status,duplicate)=request(&app,"POST","/api/v1/downloads",Some(json!({
        "source":{"type":"content","hash":"31".repeat(16),"name":"Other.bin","sizeBytes":32},"intent":"started"
    }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(duplicate["data"], first);
}

#[tokio::test]
async fn conflicting_size_returns_conflict_and_link_source_is_parsed_server_side() {
    let app = test_router();
    let first = create(&app, 0x32, Some(32), "stopped").await;
    let (status,value)=request(&app,"POST","/api/v1/downloads",Some(json!({"source":{"type":"content","hash":"32".repeat(16),"name":"Other.bin","sizeBytes":33}}))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{value}");
    assert_eq!(value["error"]["code"], "DOWNLOAD_CONFLICT");
    let (status, value) = request(&app, "GET", "/api/v1/downloads/1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["data"]["name"], first["name"]);
    let (status,value)=request(&app,"POST","/api/v1/downloads",Some(json!({"source":{"type":"ed2k-link","link":"ed2k://|file|Linked.bin|4096|33333333333333333333333333333333|/"},"intent":"stopped"}))).await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    assert_eq!(value["data"]["sizeBytes"], 4096);
    assert_eq!(value["data"]["name"], "Linked.bin");
}

#[tokio::test]
async fn newest_id_pages_have_scoped_opaque_continuation_and_independent_evidence() {
    let app = test_router();
    for hash in 1..=5 {
        create(&app, hash, None, "stopped").await;
    }
    let (status, first) = request(&app, "GET", "/api/v1/downloads?limit=2", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["data"][0]["id"], "5");
    assert_eq!(first["data"][1]["id"], "4");
    assert_eq!(first["meta"]["hasMore"], true);
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let (status, second) = request(
        &app,
        "GET",
        &format!("/api/v1/downloads?limit=3&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        second["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["3", "2", "1"]
    );
    assert_eq!(second["meta"]["hasMore"], false);
    assert!(second["meta"]["nextCursor"].is_null());
    for path in [
        format!("/api/v1/downloads?view=completed&cursor={cursor}"),
        format!("/api/v1/downloads/1/sources?cursor={cursor}"),
    ] {
        assert_eq!(
            request(&app, "GET", &path, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    for resource in ["sources", "comments", "parts"] {
        let (status, value) = request(
            &app,
            "GET",
            &format!("/api/v1/downloads/1/{resource}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{value}");
        assert_eq!(value["data"], json!([]));
        assert_eq!(value["meta"]["hasMore"], false);
    }
}

#[tokio::test]
async fn combined_patch_returns_no_content_and_contradiction_is_atomic() {
    let app = test_router();
    create(&app, 0x34, None, "stopped").await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/categories",
            Some(json!({"name":"Movies"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, value) = request(
        &app,
        "PATCH",
        "/api/v1/downloads/1",
        Some(json!({"name":"Updated.bin","category":"movies","sizeBytes":8192})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{value}");
    assert!(value.is_null());
    let (_, detail) = request(&app, "GET", "/api/v1/downloads/1", None).await;
    assert_eq!(detail["data"]["name"], "Updated.bin");
    assert_eq!(detail["data"]["category"], "Movies");
    assert_eq!(detail["data"]["sizeBytes"], 8192);
    assert!(detail["data"]["delivery"]["path"].is_null());
    let (status, _) = request(
        &app,
        "PATCH",
        "/api/v1/downloads/1",
        Some(json!({"name":"MustStayUnchanged.bin","sizeBytes":8193})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, detail) = request(&app, "GET", "/api/v1/downloads/1", None).await;
    assert_eq!(detail["data"]["name"], "Updated.bin");
    let (_, parts) = request(&app, "GET", "/api/v1/downloads/1/parts", None).await;
    assert_eq!(parts["data"][0]["start"], 0);
    assert_eq!(parts["data"][0]["end"], 8191);
    assert_eq!(parts["data"][0]["sizeBytes"], 8192);
    assert_eq!(parts["data"][0]["presentBytes"], 0);
    assert_eq!(parts["data"][0]["complete"], false);
}

#[tokio::test]
async fn admitted_actions_return_ordered_multistatus_and_failed_items_have_typed_errors() {
    let app = test_router();
    create(&app, 0x35, None, "started").await;
    create(&app, 0x36, None, "started").await;
    let (status, value) = request(
        &app,
        "POST",
        "/api/v1/downloads/stop",
        Some(json!({"ids":["1","999","2"]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(value["data"][0]["status"], "accepted");
    assert_eq!(value["data"][0]["httpStatus"], 202);
    assert!(value["data"][0].get("error").is_none());
    assert_eq!(value["data"][1]["status"], "failed");
    assert_eq!(value["data"][1]["httpStatus"], 404);
    assert_eq!(value["data"][1]["error"]["code"], "NOT_FOUND");
    assert!(value["data"][1]["error"]["details"].is_object());
    assert_eq!(value["data"][2]["id"], "2");
    let (_, value) = request(
        &app,
        "POST",
        "/api/v1/downloads/verify",
        Some(json!({"ids":["1","2"]})),
    )
    .await;
    assert!(
        value["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["status"] == "unchanged")
    );
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/downloads/remove",
        Some(json!({"ids":["1"],"deleteData":false})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(
        request(&app, "GET", "/api/v1/downloads/1", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn malformed_actions_and_ids_are_rejected_before_effects() {
    let app = test_router();
    create(&app, 0x37, None, "started").await;
    for body in [
        json!({"ids":[]}),
        json!({"ids":["1","1"]}),
        json!({"ids":[1]}),
        json!({"ids":["01"]}),
        json!({"ids":["1"],"unexpected":true}),
    ] {
        let (status, _) = request(&app, "POST", "/api/v1/downloads/stop", Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/downloads/remove",
            Some(json!({"ids":["1"]}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (_, detail) = request(&app, "GET", "/api/v1/downloads/1", None).await;
    assert_eq!(detail["data"]["intent"], "started");
    for id in ["0", "01", "-1", "9223372036854775808"] {
        assert_eq!(
            request(&app, "GET", &format!("/api/v1/downloads/{id}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(&app, "GET", "/api/v1/downloads/9223372036854775807", None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/downloads/start", None)
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}
