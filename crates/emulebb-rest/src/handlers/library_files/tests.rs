use super::*;
use crate::rest_test_support::*;
use serde_json::json;

#[tokio::test]
async fn copyless_library_pages_details_and_explicit_edits_share_one_hash() {
    let app = test_router();
    let hashes = [
        known_library_hash(&app, 0x41).await,
        known_library_hash(&app, 0x42).await,
        known_library_hash(&app, 0x43).await,
    ];
    let (status, present) = request(&app, "GET", "/api/v1/library/files", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(present["data"], json!([]));
    let (status, first) = request(
        &app,
        "GET",
        "/api/v1/library/files?view=allKnown&limit=2&countTotal=true",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["meta"]["total"], 3);
    assert_eq!(first["meta"]["hasMore"], true);
    assert_eq!(first["data"][0]["hash"], hashes[0]);
    assert_eq!(first["data"].as_array().unwrap().len(), 2);
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let (status, last) = request(
        &app,
        "GET",
        &format!("/api/v1/library/files?view=allKnown&limit=2&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(last["data"][0]["hash"], hashes[2]);
    assert_eq!(last["meta"]["hasMore"], false);
    assert!(last["meta"].get("total").is_none());
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/library/files?view=shared&cursor={cursor}"),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let decoded = String::from_utf8(hex::decode(cursor).unwrap()).unwrap();
    let (scope, _) = decoded.rsplit_once('|').unwrap();
    assert_eq!(
        request(
            &app,
            "GET",
            &format!(
                "/api/v1/library/files?view=allKnown&cursor={}",
                encode_cursor(scope, &"ff".repeat(16))
            ),
            None
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let path = format!("/api/v1/library/files/{}", hashes[0]);
    let (status, detail) = request(&app, "GET", &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["data"]["hash"], hashes[0]);
    assert!(detail["data"]["sizeBytes"].is_null());
    assert!(detail["data"]["ed2kLink"].is_null());
    assert_eq!(
        detail["data"]["publication"]["ed2k"]["state"],
        "unavailable"
    );
    let (status, body) = request(
        &app,
        "PATCH",
        &path,
        Some(json!({"uploadPriority":"high","comment":"Operator note","rating":4})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_null());
    let (_, detail) = request(&app, "GET", &path, None).await;
    assert_eq!(detail["data"]["uploadPriority"], "high");
    assert_eq!(detail["data"]["comment"], "Operator note");
    assert_eq!(detail["data"]["rating"], 4);
    assert_eq!(
        request(
            &app,
            "PATCH",
            &format!("/api/v1/library/files/{}", "ff".repeat(16)),
            Some(json!({"uploadPriority":"low"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn library_sort_filter_and_paging_inputs_use_the_fixed_contract() {
    let app = test_router();
    known_library_hash(&app, 0x44).await;
    for sort in [
        "displayName",
        "sizeBytes",
        "sessionUploadedBytes",
        "sessionUploadRequests",
        "sessionAcceptedUploads",
        "lifetimeUploadedBytes",
        "lifetimeUploadRequests",
        "lifetimeAcceptedUploads",
        "lastUploadRequestedAt",
        "lastUploadedAt",
    ] {
        let (status, body) = request(
            &app,
            "GET",
            &format!(
                "/api/v1/library/files?view=unavailable&sort={sort}&order=desc&countTotal=true"
            ),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{sort}: {body}");
        assert_eq!(body["meta"]["total"], 1);
    }
    for query in [
        "limit=0",
        "limit=201",
        "view=unknown",
        "sort=unknown",
        "order=unknown",
        "rootId=0",
        "rootId=01",
        "tag=two%20words",
        "sharingEnabled=no",
        "q=ab",
        "cursor=bad",
    ] {
        let (status, body) =
            request(&app, "GET", &format!("/api/v1/library/files?{query}"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
    let (_, filtered) = request(
        &app,
        "GET",
        "/api/v1/library/files?view=allKnown&q=sam&tag=Missing&countTotal=true",
        None,
    )
    .await;
    assert_eq!(filtered["data"], json!([]));
    assert_eq!(filtered["meta"]["total"], 0);
}
