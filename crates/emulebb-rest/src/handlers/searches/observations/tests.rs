use crate::rest_test_support::*;

#[test]
fn observation_projection_preserves_remote_note_and_claimed_publisher() {
    use emulebb_metadata::*;
    let observation = MetadataContentObservation {
        receipt: MetadataContentObservationReceipt {
            claim_id: 1,
            observation_id: 2,
            first_seen_at_s: 3,
            last_seen_at_s: 4,
            observation_count: 1,
        },
        event: MetadataContentObservationEvent {
            claim: MetadataContentClaim {
                hash: [0x41; 16],
                size_bytes: None,
            },
            origin: MetadataObservationOrigin::Kad,
            reporter_endpoint: None,
            observed_at_s: 4,
            metadata: MetadataContentMetadata {
                comment: Some("Remote note".into()),
                publisher_id: Some([0x53; 16]),
                rating: Some(4),
                ..Default::default()
            },
        },
    };
    let row = MetadataSearchResultObservation {
        observation,
        first_seen_at_s: 3,
        last_seen_at_s: 4,
        observation_count: 1,
    };
    let value = super::observation_response(&row);
    assert_eq!(value["comment"], "Remote note");
    assert_eq!(value["publisherId"], "53".repeat(16));
    assert_eq!(value["rating"], 4);
    assert!(value["reporterEndpoint"].is_null());
    assert!(value["sizeBytes"].is_null());
}

async fn fixture() -> (Arc<EmulebbCore>, Router, String, String) {
    let mut a = IndexedFile {
        ed2k_hash: "00112233445566778899aabbccddeeff".into(),
        name: "Alpha.bin".into(),
        size_bytes: 42,
        content_type: "pro".into(),
        availability_score: 2,
    };
    let mut files = vec![a.clone()];
    a.name = "Beta.bin".into();
    files.push(a);
    let core = test_search_core(&files);
    let headers = core.search_headers_page(None, 1).await.unwrap();
    let session = headers.value().items[0].id;
    drop(headers);
    let rows = core
        .search_result_headers_page(session, 0, 1)
        .await
        .unwrap();
    let claim = rows.value().as_ref().unwrap().items[0].claim_id;
    drop(rows);
    let app = router(
        Arc::clone(&core),
        RestServerSettings {
            api_key: "secret".into(),
            web_root_dir: None,
        },
    );
    (core, app, session.to_string(), claim.to_string())
}

#[tokio::test]
async fn provenance_pages_preserve_raw_values_and_session_local_occurrences() {
    let (_core, app, session, claim) = fixture().await;
    let path = format!("/api/v1/searches/{session}/results/{claim}/observations");
    let (status, first) = request(&app, "GET", &format!("{path}?limit=1"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["data"].as_array().unwrap().len(), 1);
    assert_eq!(first["data"][0]["rawName"], "Alpha.bin");
    assert_eq!(first["data"][0]["normalizedName"], "Alpha.bin");
    assert_eq!(first["data"][0]["sources"], 2);
    assert!(first["data"][0]["completeSources"].is_null());
    assert!(first["data"][0]["firstSeenAt"].is_number());
    assert_eq!(first["data"][0]["observationCount"], 1);
    assert_eq!(first["meta"]["hasMore"], true);
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let (status, second) = request(
        &app,
        "GET",
        &format!("{path}?limit=1&cursor={cursor}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["data"][0]["rawName"], "Beta.bin");
    assert_eq!(second["meta"]["hasMore"], false);
    assert!(second["meta"]["nextCursor"].is_null());
    assert_ne!(first["data"][0]["id"], second["data"][0]["id"]);
}

#[tokio::test]
async fn provenance_cursor_identity_query_bounds_and_membership_are_enforced() {
    let (_core, app, session, claim) = fixture().await;
    let path = format!("/api/v1/searches/{session}/results/{claim}/observations");
    for suffix in ["?limit=0", "?limit=201", "?cursor=invalid", "?surprise=1"] {
        assert_eq!(
            request(&app, "GET", &format!("{path}{suffix}"), None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, first) = request(&app, "GET", &format!("{path}?limit=1"), None).await;
    let cursor = first["meta"]["nextCursor"].as_str().unwrap();
    let wrong = format!("/api/v1/searches/{session}/results/999/observations?cursor={cursor}");
    assert_eq!(
        request(&app, "GET", &wrong, None).await.0,
        StatusCode::BAD_REQUEST
    );
    for wrong in [
        format!("/api/v1/searches/01/results/{claim}/observations"),
        format!("/api/v1/searches/{session}/results/9223372036854775808/observations"),
    ] {
        assert_eq!(
            request(&app, "GET", &wrong, None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/api/v1/searches/{session}/results/999/observations"),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn provenance_reports_closed_admission_through_the_common_persistence_mapping() {
    let (core, app, session, claim) = fixture().await;
    core.drain_persistence().await.unwrap();
    let (status, body) = request(
        &app,
        "GET",
        &format!("/api/v1/searches/{session}/results/{claim}/observations"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "PERSISTENCE_CLOSING");
}
