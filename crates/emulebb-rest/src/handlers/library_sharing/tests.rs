use super::*;
use crate::rest_test_support::*;
use emulebb_core::{LocalMutationError, PersistenceError};

const PATH: &str = "/api/v1/library/files/sharing";

#[tokio::test]
async fn sharing_action_has_ordered_idempotent_hash_outcomes_and_preserves_jobs_and_tags() {
    let app = test_router();
    let first = known_library_hash(&app, 1).await;
    let last = known_library_hash(&app, 2).await;
    let missing = "ff".repeat(16);
    request(
        &app,
        "POST",
        "/api/v1/library/tags",
        Some(json!({"name":"Rotate"})),
    )
    .await;
    request(
        &app,
        "POST",
        "/api/v1/library/files/tags/add",
        Some(json!({"tag":"Rotate","hashes":[first,last]})),
    )
    .await;
    for (attempt, expected) in [(0, "accepted"), (1, "unchanged")] {
        let (status, body) = request(
            &app,
            "POST",
            PATH,
            Some(json!({"enabled":false,"hashes":[first,missing,last]})),
        )
        .await;
        assert_eq!(status, StatusCode::MULTI_STATUS);
        assert_eq!(
            body["data"],
            json!([
                {"hash":first,"status":expected,"httpStatus":200},
                {"hash":missing,"status":"failed","httpStatus":404,"error":{"code":"NOT_FOUND","message":"library file not found","details":{}}},
                {"hash":last,"status":expected,"httpStatus":200}
            ]),
            "attempt {attempt}"
        );
    }
    let (status, enabled) = request(
        &app,
        "POST",
        PATH,
        Some(json!({"enabled":true,"hashes":[last,first]})),
    )
    .await;
    assert_eq!(status, StatusCode::MULTI_STATUS);
    assert_eq!(enabled["data"][0]["hash"], last);
    assert_eq!(enabled["data"][1]["hash"], first);
    assert!(
        enabled["data"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["status"] == "accepted")
    );
    for hash in [&first, &last] {
        let (_, tags) = request(
            &app,
            "GET",
            &format!("/api/v1/library/files/{hash}/tags"),
            None,
        )
        .await;
        assert_eq!(tags["data"], json!([{"name":"Rotate"}]));
    }
    for id in ["1", "2"] {
        let (_, job) = request(&app, "GET", &format!("/api/v1/downloads/{id}"), None).await;
        assert_eq!(job["data"]["intent"], "stopped");
    }
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/library/files/{missing}/tags"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn malformed_sharing_selection_is_refused_before_any_change() {
    let app = test_router();
    let hash = known_library_hash(&app, 0xab).await;
    for body in [
        json!({"enabled":false,"hashes":[]}),
        json!({"enabled":false,"hashes":[hash,hash]}),
        json!({"enabled":false,"hashes":(0..101).map(|n|format!("{n:032x}")).collect::<Vec<_>>()}),
        json!({"enabled":false,"hashes":[hash,"BAD"]}),
        json!({"enabled":false,"hashes":[hash,hash.to_uppercase()]}),
        json!({"enabled":false,"hashes":[hash],"unknown":true}),
        json!({"hashes":[hash]}),
        json!({"enabled":null,"hashes":[hash]}),
        json!({"enabled":"false","hashes":[hash]}),
        json!({"enabled":false}),
    ] {
        let (status, error) = request(&app, "POST", PATH, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(error["error"]["code"], "INVALID_ARGUMENT");
        // The first valid disable must still change the original enabled value.
        let (_, result) = request(
            &app,
            "POST",
            PATH,
            Some(json!({"enabled":false,"hashes":[hash]})),
        )
        .await;
        assert_eq!(result["data"][0]["status"], "accepted");
        request(
            &app,
            "POST",
            PATH,
            Some(json!({"enabled":true,"hashes":[hash]})),
        )
        .await;
    }
    assert_eq!(
        request(
            &app,
            "POST",
            &format!("{PATH}?enabled=false"),
            Some(json!({"enabled":false,"hashes":[hash]}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&app, "GET", PATH, None).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn sharing_action_reports_closed_profile_owner_before_items() {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    core.drain_persistence().await.unwrap();
    let app = router(
        core,
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    let (status, error) = request(
        &app,
        "POST",
        PATH,
        Some(json!({"enabled":false,"hashes":["01".repeat(16)]})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error["error"]["code"], "PERSISTENCE_CLOSING");
}

#[tokio::test]
async fn sharing_item_errors_use_the_same_status_and_commit_details_as_whole_requests() {
    for error in [
        LocalMutationError::Busy,
        LocalMutationError::Closing,
        LocalMutationError::TooLarge,
        LocalMutationError::Storage,
        LocalMutationError::Committed,
        LocalMutationError::Unknown,
    ] {
        let persistence = PersistenceError::from(&error);
        let item = serde_json::to_value(outcome(LibrarySharingOutcome {
            hash: "01".repeat(16),
            outcome: Err(persistence),
        }))
        .unwrap();
        let response = persistence_error(error.into());
        assert_eq!(item["httpStatus"], response.status().as_u16());
        let whole: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(item["error"], whole["error"]);
        assert_eq!(item["status"], "failed");
        if item["error"]["code"] == "PERSISTENCE_COMMITTED" {
            assert_eq!(item["error"]["details"], json!({"committed":true}));
        } else {
            assert_eq!(item["error"]["details"], json!({}));
        }
    }
}
