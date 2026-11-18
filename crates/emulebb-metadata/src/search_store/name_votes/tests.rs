use super::*;
use crate::search_store::tests::{event, fields, name_vote, sample_search};
use crate::{
    MetadataObservationOrigin as Origin, MetadataSearchNameVote, MetadataSearchProjection,
    MetadataSearchPublication, MetadataStore,
};

fn vote(
    name: &str,
    reporter: Option<&str>,
    origin: Origin,
    sources: u32,
) -> MetadataSearchNameVote {
    let mut vote = name_vote(name);
    vote.reporter_endpoint = reporter.map(|v| v.parse().unwrap());
    vote.origin = origin;
    vote.quality.sources = sources;
    vote
}
fn cast(
    store: &MetadataStore,
    session: i64,
    size: Option<u64>,
    vote: MetadataSearchNameVote,
) -> MetadataSearchPublication {
    let mut packet = event(size, &vote.normalized_name);
    packet.origin = vote.origin;
    packet.reporter_endpoint = vote.reporter_endpoint;
    packet.metadata.source_count = Some(vote.quality.sources);
    packet.metadata.complete_source_count = Some(vote.quality.complete_sources);
    packet.metadata.rating = Some(vote.quality.rating);
    store
        .ingest_search_observations(
            &[packet],
            &MetadataSearchProjection {
                session_id: session,
                fields: vec![fields()],
                name_votes: vec![vote],
            },
        )
        .unwrap()
        .unwrap()
}
fn total(store: &MetadataStore, session: i64, name: &str) -> i64 {
    store
        .connection()
        .unwrap()
        .query_row(
            "SELECT vote_count FROM search_name_totals WHERE session_id=?1 AND normalized_name=?2",
            params![session, name],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn changing_metadata_and_transport_origin_never_multiply_a_reporters_name_vote() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    cast(
        &store,
        id,
        Some(12),
        vote("Alpha.bin", Some("192.0.2.1:4661"), Origin::Server, 3),
    );
    cast(
        &store,
        id,
        Some(12),
        vote("Beta.bin", Some("192.0.2.2:4661"), Origin::Server, 1),
    );
    let claim = cast(
        &store,
        id,
        Some(12),
        vote("Beta.bin", Some("192.0.2.3:4661"), Origin::Server, 1),
    )
    .claim_id;
    for sources in 100..120 {
        let published = cast(
            &store,
            id,
            Some(12),
            vote("Alpha.bin", Some("192.0.2.1:4661"), Origin::Server, sources),
        );
        assert_eq!(published.summary.name, "Beta.bin");
    }
    cast(
        &store,
        id,
        Some(12),
        vote(
            "Alpha.bin",
            Some("192.0.2.1:4661"),
            Origin::Global,
            u32::MAX,
        ),
    );
    assert_eq!(total(&store, id, "Alpha.bin"), 1);
    assert_eq!(total(&store, id, "Beta.bin"), 2);
    assert_eq!(
        store
            .search_result_header(id, claim)
            .unwrap()
            .unwrap()
            .summary
            .name,
        "Beta.bin"
    );
    let packets: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT SUM(observation_count) FROM content_claim_observations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(packets, 24);
}

#[test]
fn unknown_reporters_count_once_per_origin_and_ties_use_quality_then_binary_name() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    cast(&store, id, None, vote("Zed.bin", None, Origin::Server, 3));
    assert_eq!(
        cast(&store, id, None, vote("Alpha.bin", None, Origin::Server, 3))
            .summary
            .name,
        "Alpha.bin"
    );
    assert_eq!(
        cast(&store, id, None, vote("Zed.bin", None, Origin::Server, 4))
            .summary
            .name,
        "Zed.bin"
    );
    assert_eq!(total(&store, id, "Zed.bin"), 1);
    cast(&store, id, None, vote("Alpha.bin", None, Origin::Global, 0));
    assert_eq!(
        cast(
            &store,
            id,
            None,
            vote("Zed.bin", None, Origin::Kad, u32::MAX)
        )
        .summary
        .name,
        "Zed.bin"
    );
    assert_eq!(
        cast(&store, id, None, vote("Alpha.bin", None, Origin::Kad, 0))
            .summary
            .name,
        "Alpha.bin"
    );
    assert_eq!(total(&store, id, "Alpha.bin"), 3);
    assert_eq!(total(&store, id, "Zed.bin"), 2);
}

#[test]
fn quality_updates_preserve_the_winning_tuple_without_mixing_component_maxima() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    cast(
        &store,
        id,
        Some(1),
        vote("Alpha.bin", None, Origin::Kad, 10),
    );
    let mut lower = vote("Alpha.bin", None, Origin::Kad, 9);
    lower.quality.complete_sources = 8;
    lower.quality.rating = 5;
    cast(&store, id, Some(1), lower);
    let stored: (u32,u32,u8) = store.connection().unwrap().query_row("SELECT quality_sources,quality_complete_sources,quality_rating FROM search_name_totals WHERE session_id=?1",[id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!(stored, (10, 0, 0));
    let mut better = vote("Beta.bin", None, Origin::Kad, 10);
    better.quality.complete_sources = 1;
    assert_eq!(cast(&store, id, Some(1), better).summary.name, "Beta.bin");
}

#[test]
fn name_publication_failure_rolls_back_votes_occurrences_and_summary() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let claim = cast(
        &store,
        id,
        None,
        vote("Alpha.bin", Some("192.0.2.1:4661"), Origin::Server, 3),
    )
    .claim_id;
    cast(
        &store,
        id,
        None,
        vote("Beta.bin", Some("192.0.2.2:4661"), Origin::Server, 1),
    );
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_name BEFORE UPDATE OF name ON search_results WHEN new.name='Beta.bin' BEGIN SELECT RAISE(ABORT,'injected name publication failure'); END;").unwrap();
    let beta = vote("Beta.bin", Some("192.0.2.3:4661"), Origin::Server, 1);
    let mut packet = event(None, "Beta.bin");
    packet.origin = beta.origin;
    packet.reporter_endpoint = beta.reporter_endpoint;
    packet.metadata.source_count = Some(1);
    assert!(
        store
            .ingest_search_observations(
                &[packet],
                &MetadataSearchProjection {
                    session_id: id,
                    fields: vec![fields()],
                    name_votes: vec![beta.clone()]
                }
            )
            .is_err()
    );
    assert_eq!(total(&store, id, "Beta.bin"), 1);
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 2);
    assert_eq!(store.table_count("search_name_reporters").unwrap(), 2);
    assert_eq!(
        store
            .search_result_header(id, claim)
            .unwrap()
            .unwrap()
            .summary
            .name,
        "Alpha.bin"
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_name;")
        .unwrap();
    assert_eq!(cast(&store, id, None, beta).summary.name, "Beta.bin");
}

#[test]
fn votes_are_scoped_to_session_and_size_claim_and_terminal_membership_stays_frozen() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store.create_search(&sample_search()).unwrap();
    let second = store.create_search(&sample_search()).unwrap();
    let alpha = cast(&store, first, None, vote("Alpha.bin", None, Origin::Kad, 3));
    let beta = cast(&store, second, None, vote("Beta.bin", None, Origin::Kad, 3));
    assert_eq!(alpha.claim_id, beta.claim_id);
    let zero = cast(
        &store,
        first,
        Some(0),
        vote("Zero.bin", None, Origin::Kad, 3),
    );
    assert_ne!(zero.claim_id, alpha.claim_id);
    let mut terminal = sample_search();
    terminal.status = "completed".into();
    store.update_search(first, &terminal).unwrap();
    assert!(
        store
            .ingest_search_observations(
                &[event(None, "Late.bin")],
                &MetadataSearchProjection {
                    session_id: first,
                    fields: vec![fields()],
                    name_votes: vec![name_vote("Late.bin")]
                }
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(store.table_count("search_name_totals").unwrap(), 3);
    assert_eq!(
        store
            .search_result_header(first, alpha.claim_id)
            .unwrap()
            .unwrap()
            .summary
            .name,
        "Alpha.bin"
    );
    store.delete_search(first).unwrap();
    assert_eq!(store.table_count("search_name_totals").unwrap(), 1);
    assert_eq!(store.table_count("search_name_reporters").unwrap(), 1);
    assert_eq!(
        store
            .search_result_header(second, beta.claim_id)
            .unwrap()
            .unwrap()
            .summary
            .name,
        "Beta.bin"
    );
    assert_eq!(store.table_count("content_claim_observations").unwrap(), 4);
}

#[test]
fn winner_lookup_uses_its_index_with_one_hundred_thousand_names() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let claim = cast(
        &store,
        id,
        None,
        vote("Actual.bin", None, Origin::Server, 3),
    )
    .claim_id;
    {
        let conn = store.connection().unwrap();
        conn.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
            INSERT INTO search_name_reporters(session_id,claim_id,normalized_name,reporter_endpoint,unknown_origin,
                quality_useful,quality_sources,quality_complete_sources,quality_rating)
            SELECT ?1,?2,printf('name-%06d.bin',i),'','server',1,0,0,0 FROM n",params![id,claim]).unwrap();
        conn.execute("INSERT INTO search_name_totals(session_id,claim_id,normalized_name,vote_count,
                quality_useful,quality_sources,quality_complete_sources,quality_rating)
            SELECT session_id,claim_id,normalized_name,1,quality_useful,quality_sources,quality_complete_sources,quality_rating
            FROM search_name_reporters WHERE session_id=?1 AND normalized_name!='Actual.bin'",[id]).unwrap();
    }
    assert_eq!(
        cast(
            &store,
            id,
            None,
            vote("Winner.bin", None, Origin::Server, 4)
        )
        .summary
        .name,
        "Winner.bin"
    );
    let conn = store.connection().unwrap();
    let mut statement = conn.prepare(WINNER_SQL).unwrap();
    let name: String = statement
        .query_row(params![id, claim], |row| row.get(0))
        .unwrap();
    assert_eq!(name, "Winner.bin");
    assert_eq!(
        statement.get_status(rusqlite::StatementStatus::FullscanStep),
        0
    );
    assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
    assert!(statement.get_status(rusqlite::StatementStatus::VmStep) < 200);
}
