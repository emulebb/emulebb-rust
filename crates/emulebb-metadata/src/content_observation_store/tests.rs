use super::*;

fn event(size_bytes: Option<u64>) -> MetadataContentObservationEvent {
    MetadataContentObservationEvent {
        claim: MetadataContentClaim {
            hash: [0x42; 16],
            size_bytes,
        },
        origin: MetadataObservationOrigin::Kad,
        reporter_endpoint: Some("192.0.2.7:4672".parse().unwrap()),
        metadata: MetadataContentMetadata {
            name: Some("Sample File.bin".into()),
            source_count: Some(5),
            source_client_id: Some(u32::MAX),
            source_client_port: Some(4662),
            aich_root: Some([0x12; 20]),
            complete: Some(false),
            ..Default::default()
        },
        observed_at_s: 100,
    }
}

#[test]
fn unknown_zero_conflicting_and_full_unsigned_sizes_have_distinct_stable_claims() {
    let store = MetadataStore::in_memory().unwrap();
    let events: Vec<_> = [None, Some(0), Some(1024), Some(u64::MAX)]
        .into_iter()
        .map(event)
        .collect();
    let first = store.ingest_content_observations(&events).unwrap();
    let again = store.ingest_content_observations(&events).unwrap();
    for (index, receipt) in first.iter().enumerate() {
        assert_eq!(
            store.content_claim(receipt.claim_id).unwrap(),
            Some(events[index].claim)
        );
        assert_eq!(receipt.claim_id, again[index].claim_id);
        assert_eq!(receipt.observation_id, again[index].observation_id);
        assert_eq!(again[index].observation_count, 2);
        assert!(
            first[..index]
                .iter()
                .all(|old| old.claim_id != receipt.claim_id)
        );
    }
    // Evidence cannot create accepted client-owned content.
    assert_eq!(store.table_count("known_files").unwrap(), 0);
    assert_eq!(store.table_count("content_claims").unwrap(), 4);
}

#[test]
fn repetitions_aggregate_out_of_order_and_metadata_or_reporter_changes_remain_distinct() {
    let store = MetadataStore::in_memory().unwrap();
    let original = event(Some(1024));
    let mut earlier = original.clone();
    earlier.observed_at_s = 50;
    let mut later = original.clone();
    later.observed_at_s = 200;
    let mut renamed = original.clone();
    renamed.metadata.name = Some("Alternate File.bin".into());
    let mut different_reporter = original.clone();
    different_reporter.reporter_endpoint = Some("192.0.2.7:4673".parse().unwrap());
    let mut unknown_reporter = original.clone();
    unknown_reporter.reporter_endpoint = None;
    let mut changed_count = original.clone();
    changed_count.metadata.source_count = Some(6);
    let mut absent_count = original.clone();
    absent_count.metadata.source_count = None;
    let mut other_origin = original.clone();
    other_origin.origin = MetadataObservationOrigin::Server;
    let receipts = store
        .ingest_content_observations(&[
            original.clone(),
            earlier,
            later,
            renamed,
            different_reporter,
            unknown_reporter.clone(),
            unknown_reporter,
            changed_count,
            absent_count,
            other_origin,
        ])
        .unwrap();
    assert_eq!(receipts[0].observation_id, receipts[2].observation_id);
    assert_eq!(receipts[2].observation_count, 3);
    assert_eq!(
        (receipts[2].first_seen_at_s, receipts[2].last_seen_at_s),
        (50, 200)
    );
    assert_eq!(receipts[6].observation_count, 2);
    let page = store
        .content_observations_page(receipts[0].claim_id, 0, 100)
        .unwrap();
    assert_eq!(page.items.len(), 7);
    assert!(!page.has_more);
    assert_eq!(page.items[0].event.metadata, original.metadata);
    assert_eq!(
        page.items[0].event.reporter_endpoint,
        original.reporter_endpoint
    );
    assert_eq!(page.items[0].receipt, receipts[2]);
    assert!(page.items[4].event.metadata.source_count == Some(6));
}

#[test]
fn bounds_validate_the_entire_batch_and_sql_failure_rolls_back_prior_occurrences() {
    let store = MetadataStore::in_memory().unwrap();
    let valid = event(None);
    let mut invalid = valid.clone();
    invalid.observed_at_s = -1;
    assert!(
        store
            .ingest_content_observations(&[valid.clone(), invalid])
            .is_err()
    );
    assert_eq!(store.table_count("content_claims").unwrap(), 0);
    let mut oversized = valid.clone();
    oversized.metadata.name = Some("x".repeat(64 * 1024));
    assert!(store.ingest_content_observations(&[oversized]).is_err());
    assert!(
        store
            .ingest_content_observations(&vec![valid.clone(); 129])
            .is_err()
    );
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_observation BEFORE INSERT ON content_claim_observations
         WHEN NEW.name='fail' BEGIN SELECT RAISE(ABORT,'injected failure'); END;",
        )
        .unwrap();
    let mut failing = valid.clone();
    failing.metadata.name = Some("fail".into());
    assert!(
        store
            .ingest_content_observations(&[valid.clone(), failing])
            .is_err()
    );
    assert_eq!(store.table_count("content_claims").unwrap(), 0);
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 0);
    let receipts = store.ingest_content_observations(&[valid]).unwrap();
    assert_eq!(receipts[0].observation_count, 1);
}

#[test]
fn corpus_survives_search_clear_reopen_and_saturates_counts_without_real_overflow() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("metadata.sqlite");
    let store = MetadataStore::open(&path).unwrap();
    let original = event(Some(256));
    let receipt = store
        .ingest_content_observations(std::slice::from_ref(&original))
        .unwrap()[0];
    store.connection().unwrap().execute_batch(
        "INSERT INTO search_sessions(query,normalized_query,requested_method,status,created_at_s,updated_at_s)
         VALUES('sample','sample','kad','completed',0,0)"
    ).unwrap();
    store.clear_searches().unwrap();
    assert_eq!(store.table_count("search_sessions").unwrap(), 0);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE content_claim_observations SET observation_count=?1 WHERE id=?2",
            params![i64::MAX, receipt.observation_id],
        )
        .unwrap();
    drop(store);
    let store = MetadataStore::open(&path).unwrap();
    let repeated = store.ingest_content_observations(&[original]).unwrap()[0];
    assert_eq!(repeated.claim_id, receipt.claim_id);
    assert_eq!(repeated.observation_id, receipt.observation_id);
    assert_eq!(repeated.observation_count, i64::MAX);
    let page = store
        .content_observations_page(receipt.claim_id, 0, 1)
        .unwrap();
    assert_eq!(page.items[0].receipt, repeated);
}

#[test]
fn provenance_pages_are_keyset_and_byte_bounded_without_losing_items() {
    let store = MetadataStore::in_memory().unwrap();
    let mut receipts = Vec::new();
    for index in 0..12 {
        let mut next = event(None);
        next.metadata.name = Some(format!("{index}{}", "x".repeat(8000)));
        receipts.push(store.ingest_content_observations(&[next]).unwrap()[0]);
    }
    let claim_id = receipts[0].claim_id;
    let first = store.content_observations_page(claim_id, 0, 100).unwrap();
    assert!(first.has_more);
    assert_eq!(first.items.len(), 5);
    let mut seen = Vec::new();
    let mut after = 0;
    loop {
        let page = store.content_observations_page(claim_id, after, 3).unwrap();
        for item in &page.items {
            assert!(item.receipt.observation_id > after);
            after = item.receipt.observation_id;
            seen.push(item.receipt);
        }
        if !page.has_more {
            break;
        }
    }
    assert_eq!(seen, receipts);
    assert!(store.content_observations_page(claim_id, 0, 0).is_err());
    assert!(store.content_observations_page(claim_id, 0, 101).is_err());
    assert!(store.content_observations_page(claim_id, -1, 1).is_err());
    assert!(
        store
            .content_observations_page(i64::MAX, 0, 100)
            .unwrap()
            .items
            .is_empty()
    );
}
