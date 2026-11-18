use crate::search_store::tests::{event, fields, name_vote, sample_search};
use crate::{
    MetadataSearchProjection, MetadataSearchResultFields, MetadataSearchResultSummary,
    MetadataStore,
};
fn cast(
    store: &MetadataStore,
    id: i64,
    fields: Vec<MetadataSearchResultFields>,
) -> MetadataSearchResultSummary {
    store
        .ingest_search_observations(
            &[event(Some(12), "Sample.bin")],
            &MetadataSearchProjection {
                session_id: id,
                fields,
                name_votes: vec![name_vote("Sample.bin")],
            },
        )
        .unwrap()
        .unwrap()
        .summary
}
fn candidate(sources: u32) -> MetadataSearchResultFields {
    let mut value = fields();
    value.quality.sources = sources;
    value.file_type.clear();
    value.aich_hash.clear();
    value
}
#[test]
fn fields_select_independent_winners_without_losing_absent_values() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let mut artist = candidate(3);
    artist.media_artist = "Sample Artist".into();
    artist.rating = 4;
    let mut codec = candidate(8);
    codec.media_codec = "flac".into();
    codec.complete = true;
    let mut numbers = candidate(2);
    numbers.media_length_seconds = 120;
    numbers.media_bitrate_kbps = 320;
    let result = cast(&store, id, vec![artist, codec, numbers]);
    assert_eq!(result.media_artist, "Sample Artist");
    assert_eq!(result.media_codec, "flac");
    assert_eq!(
        (result.media_length_seconds, result.media_bitrate_kbps),
        (120, 320)
    );
    assert_eq!(result.rating, 4);
    assert!(result.complete);
    assert_eq!(cast(&store, id, vec![candidate(100)]), result);
}
#[test]
fn whole_quality_tuples_and_equal_quality_ties_are_arrival_independent() {
    for reverse in [false, true] {
        let store = MetadataStore::in_memory().unwrap();
        let id = store.create_search(&sample_search()).unwrap();
        let mut alpha = candidate(7);
        alpha.media_title = "Alpha".into();
        alpha.quality.complete_sources = 1;
        let mut beta = candidate(6);
        beta.media_title = "Beta".into();
        beta.quality.complete_sources = 100;
        let mut zed = candidate(7);
        zed.media_title = "Zed".into();
        zed.quality.complete_sources = 1;
        let mut values = vec![alpha, beta, zed];
        if reverse {
            values.reverse();
        }
        let result = cast(&store, id, values);
        assert_eq!(result.media_title, "Alpha");
        let mut better = candidate(8);
        better.media_title = "Omega".into();
        assert_eq!(cast(&store, id, vec![better]).media_title, "Omega");
    }
}
#[test]
fn source_pairs_aich_and_numeric_values_remain_atomic_with_deterministic_ties() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let mut a = candidate(1);
    a.source_client_id = Some(20);
    a.source_client_port = Some(5000);
    a.aich_hash = data_encoding::BASE32_NOPAD.encode(&[2; 20]);
    a.media_bitrate_kbps = 320;
    let mut b = candidate(1);
    b.source_client_id = Some(20);
    b.source_client_port = Some(4000);
    b.aich_hash = data_encoding::BASE32_NOPAD.encode(&[1; 20]);
    b.media_bitrate_kbps = 128;
    let result = cast(&store, id, vec![a, b]);
    assert_eq!(
        (result.source_client_id, result.source_client_port),
        (Some(20), Some(4000))
    );
    assert_eq!(result.media_bitrate_kbps, 128);
    assert_eq!(
        result.aich_hash,
        data_encoding::BASE32_NOPAD.encode(&[1; 20])
    );
}
#[test]
fn field_failure_rolls_back_quality_value_membership_and_corpus() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let mut first = candidate(1);
    first.media_artist = "Alpha".into();
    cast(&store, id, vec![first]);
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_field BEFORE UPDATE OF media_artist ON search_results WHEN new.media_artist='Beta' BEGIN SELECT RAISE(ABORT,'injected field failure'); END;").unwrap();
    let mut changed = candidate(9);
    changed.media_artist = "Beta".into();
    let projection = MetadataSearchProjection {
        session_id: id,
        fields: vec![changed.clone()],
        name_votes: vec![name_vote("Changed.bin")],
    };
    let packet = event(Some(12), "Changed.bin");
    assert!(
        store
            .ingest_search_observations(&[packet], &projection)
            .is_err()
    );
    let conn = store.connection().unwrap();
    let quality: i64 = conn
        .query_row(
            "SELECT quality_sources FROM search_field_quality WHERE field='media_artist'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(quality, 1);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM content_claim_observations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    conn.execute_batch("DROP TRIGGER fail_field").unwrap();
    drop(conn);
    assert_eq!(cast(&store, id, vec![changed]).media_artist, "Beta");
    store.delete_search(id).unwrap();
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM search_field_quality", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn presentation_bounds_and_incomplete_source_pairs_fail_before_writing_raw_facts() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.create_search(&sample_search()).unwrap();
    let mut half = candidate(1);
    half.source_client_id = Some(1);
    let mut large = candidate(1);
    large.media_artist = "x".repeat(12_000);
    for values in [vec![candidate(1); 129], vec![half], vec![large]] {
        let projection = MetadataSearchProjection {
            session_id: id,
            fields: values,
            name_votes: vec![name_vote("Sample.bin")],
        };
        assert!(
            store
                .ingest_search_observations(&[event(Some(12), "Sample.bin")], &projection)
                .is_err()
        );
    }
    assert!(store.load_searches().unwrap()[0].results.is_empty());
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM content_claims", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
