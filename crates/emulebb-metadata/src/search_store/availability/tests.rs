use crate::search_store::tests::{event, fields, name_vote, sample_search};
use crate::{
    MetadataContentObservationEvent, MetadataObservationOrigin as Origin, MetadataSearchProjection,
    MetadataSearchPublication, MetadataStore,
};

fn report(
    origin: Origin,
    endpoint: Option<&str>,
    sources: Option<u32>,
    complete: Option<u32>,
) -> MetadataContentObservationEvent {
    let mut value = event(Some(12), "Sample.bin");
    value.origin = origin;
    value.reporter_endpoint = endpoint.map(|v| v.parse().unwrap());
    value.metadata.source_count = sources;
    value.metadata.complete_source_count = complete;
    value
}
fn ingest(
    store: &MetadataStore,
    session: i64,
    events: &[MetadataContentObservationEvent],
) -> MetadataSearchPublication {
    store
        .ingest_search_observations(
            events,
            &MetadataSearchProjection {
                session_id: session,
                fields: vec![fields()],
                name_votes: vec![name_vote("Sample.bin")],
            },
        )
        .unwrap()
        .unwrap()
}
fn counts(value: MetadataSearchPublication) -> (u32, u32) {
    (
        value.summary.source_count,
        value.summary.complete_source_count,
    )
}

#[test]
fn reporter_maxima_deduplicate_transports_and_unknown_reporters_per_origin() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let packets = [
        report(Origin::Server, Some("192.0.2.1:4661"), Some(10), Some(2)),
        report(Origin::Global, Some("192.0.2.1:4661"), Some(7), Some(4)),
        report(Origin::Server, Some("192.0.2.2:4661"), Some(3), None),
        report(Origin::Server, None, Some(5), Some(1)),
        report(Origin::Server, None, Some(4), Some(2)),
        report(Origin::Global, None, Some(6), Some(3)),
    ];
    assert_eq!(counts(ingest(&store, id, &packets)), (24, 9));
    assert_eq!(counts(ingest(&store, id, &packets)), (24, 9));
    let loaded = store.load_searches().unwrap();
    assert_eq!(
        (
            loaded[0].results[0].summary.source_count,
            loaded[0].results[0].summary.complete_source_count
        ),
        (24, 9)
    );
}

#[test]
fn ed2k_subtotals_survive_a_leading_kad_estimate_and_overtake_independently() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    assert_eq!(
        counts(ingest(
            &store,
            id,
            &[report(Origin::Kad, None, Some(100), Some(2))]
        )),
        (100, 2)
    );
    assert_eq!(
        counts(ingest(
            &store,
            id,
            &[report(
                Origin::Server,
                Some("192.0.2.1:4661"),
                Some(60),
                Some(4)
            )]
        )),
        (100, 4)
    );
    assert_eq!(
        counts(ingest(
            &store,
            id,
            &[report(
                Origin::Global,
                Some("192.0.2.2:4661"),
                Some(50),
                Some(3)
            )]
        )),
        (110, 7)
    );
    assert_eq!(
        counts(ingest(
            &store,
            id,
            &[report(Origin::Kad, None, Some(90), Some(9))]
        )),
        (110, 9)
    );
    let conn = store.connection().unwrap();
    let components:(u32,u32,u32,u32)=conn.query_row("SELECT ed2k_source_count,ed2k_complete_source_count,kad_source_count,kad_complete_source_count FROM search_results WHERE session_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(components, (110, 7, 100, 9));
}

#[test]
fn saturation_and_absence_preserve_raw_facts_without_decreasing_totals() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let packets = [
        report(Origin::Server, None, None, None),
        report(Origin::Server, None, Some(0), Some(0)),
        report(
            Origin::Server,
            Some("192.0.2.1:4661"),
            Some(u32::MAX),
            Some(u32::MAX - 1),
        ),
        report(Origin::Server, Some("192.0.2.2:4661"), Some(9), Some(9)),
    ];
    assert_eq!(counts(ingest(&store, id, &packets)), (u32::MAX, u32::MAX));
    assert_eq!(
        counts(ingest(
            &store,
            id,
            &[report(Origin::Server, None, Some(1), Some(1))]
        )),
        (u32::MAX, u32::MAX)
    );
    assert_eq!(
        store.load_searches().unwrap()[0].results[0]
            .observations
            .len(),
        5
    );
}

#[test]
fn failure_rolls_back_all_derived_and_raw_changes_then_explicit_retry_succeeds() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let first = report(Origin::Server, None, Some(3), Some(1));
    ingest(&store, id, &[first]);
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_availability BEFORE UPDATE OF ed2k_source_count ON search_results BEGIN SELECT RAISE(ABORT,'injected availability failure'); END;").unwrap();
    let packet = report(Origin::Global, None, Some(8), Some(4));
    let projection = MetadataSearchProjection {
        session_id: id,
        fields: vec![fields()],
        name_votes: vec![name_vote("Changed.bin")],
    };
    assert!(
        store
            .ingest_search_observations(&[packet.clone()], &projection)
            .is_err()
    );
    let loaded = store.load_searches().unwrap();
    assert_eq!(loaded[0].results[0].summary.source_count, 3);
    assert_eq!(loaded[0].results[0].observations.len(), 1);
    let conn = store.connection().unwrap();
    for table in [
        "content_claim_observations",
        "search_ed2k_reporter_maxima",
        "search_name_totals",
    ] {
        let count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "{table}");
    }
    conn.execute_batch("DROP TRIGGER fail_availability")
        .unwrap();
    drop(conn);
    assert_eq!(counts(ingest(&store, id, &[packet])), (11, 5));
}

#[test]
fn claims_sessions_terminal_state_and_deletion_keep_availability_scoped() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let other = store.create_search(&sample_search()).unwrap();
    let first = report(Origin::Server, None, Some(3), None);
    ingest(&store, id, &[first.clone()]);
    assert_eq!(
        counts(ingest(
            &store,
            other,
            &[report(Origin::Server, None, Some(7), None)]
        )),
        (7, 0)
    );
    let mut distinct = first.clone();
    distinct.claim.size_bytes = None;
    distinct.metadata.source_count = Some(9);
    assert_eq!(counts(ingest(&store, id, &[distinct])), (9, 0));
    let mut header = sample_search();
    header.status = "completed".into();
    header.completed_at_s = Some(101);
    store.transition_search(id, &header, &[]).unwrap();
    assert!(
        store
            .ingest_search_observations(
                &[first],
                &MetadataSearchProjection {
                    session_id: id,
                    fields: vec![fields()],
                    name_votes: vec![name_vote("Sample.bin")]
                }
            )
            .unwrap()
            .is_none()
    );
    store.delete_search(id).unwrap();
    let conn = store.connection().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM search_ed2k_reporter_maxima",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM content_claims", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn reporter_lookup_seeks_exact_key_with_one_hundred_thousand_reporters() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let claim = ingest(&store, id, &[report(Origin::Server, None, Some(0), None)]).claim_id;
    let conn = store.connection().unwrap();
    conn.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO search_ed2k_reporter_maxima(session_id,claim_id,reporter_endpoint,unknown_origin,source_count,complete_source_count)
        SELECT ?1,?2,printf('198.18.%d.%d:%d',(i/65536),((i/256)%256),4661+(i%256)),'',0,0 FROM n",rusqlite::params![id,claim]).unwrap();
    let mut statement = conn.prepare(super::REPORTER_SQL).unwrap();
    let pair: (u32, u32) = statement
        .query_row(rusqlite::params![id, claim, "198.18.1.134:4821", ""], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(pair, (0, 0));
    assert_eq!(
        statement.get_status(rusqlite::StatementStatus::FullscanStep),
        0
    );
    assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
    assert!(statement.get_status(rusqlite::StatementStatus::VmStep) < 100);
}
