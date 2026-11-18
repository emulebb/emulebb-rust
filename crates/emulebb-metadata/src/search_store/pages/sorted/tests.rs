use super::*;
use crate::search_store::tests::{event, fields, name_vote, sample_search};
const SORTS: [Sort; 12] = [
    Sort::Name,
    Sort::SizeBytes,
    Sort::Sources,
    Sort::CompleteSources,
    Sort::Rating,
    Sort::FileType,
    Sort::Artist,
    Sort::Album,
    Sort::Title,
    Sort::LengthSeconds,
    Sort::BitrateKbps,
    Sort::Codec,
];
fn query(session: i64, sort: Sort, order: Order) -> MetadataSearchResultsQuery {
    MetadataSearchResultsQuery {
        session_id: session,
        after_claim_id: None,
        sort,
        order,
        limit: 2,
    }
}
fn compare(
    a: &MetadataSearchResultHeader,
    b: &MetadataSearchResultHeader,
    sort: Sort,
) -> std::cmp::Ordering {
    let (x, y) = (&a.summary, &b.summary);
    match sort {
        Sort::Name => x.name.cmp(&y.name),
        Sort::SizeBytes => a.size_bytes.cmp(&b.size_bytes),
        Sort::Sources => x.source_count.cmp(&y.source_count),
        Sort::CompleteSources => x.complete_source_count.cmp(&y.complete_source_count),
        Sort::Rating => x.rating.cmp(&y.rating),
        Sort::FileType => x.file_type.cmp(&y.file_type),
        Sort::Artist => x.media_artist.cmp(&y.media_artist),
        Sort::Album => x.media_album.cmp(&y.media_album),
        Sort::Title => x.media_title.cmp(&y.media_title),
        Sort::LengthSeconds => x.media_length_seconds.cmp(&y.media_length_seconds),
        Sort::BitrateKbps => x.media_bitrate_kbps.cmp(&y.media_bitrate_kbps),
        Sort::Codec => x.media_codec.cmp(&y.media_codec),
    }
    .then_with(|| a.claim_id.cmp(&b.claim_id))
}
#[test]
fn every_sort_and_direction_matches_global_order_across_ties_unknown_zero_and_unsigned_sizes() {
    let store = crate::MetadataStore::in_memory().unwrap();
    let session = store.create_search(&sample_search()).unwrap();
    let sizes = [
        None,
        Some(0),
        Some(1),
        Some(1024),
        Some(u64::MAX),
        Some(1 << 63),
        Some(u32::MAX as u64),
    ];
    let names = [
        "Alpha.bin",
        "alpha.bin",
        "Beta.bin",
        "Älpha.bin",
        "Zulu.bin",
        "Same.bin",
        "Same.bin",
    ];
    let mut expected = Vec::new();
    for (index, size) in sizes.into_iter().enumerate() {
        let n = index as u32;
        let mut packet = event(size, names[index]);
        packet.metadata.source_count = Some(n % 3);
        packet.metadata.complete_source_count = Some(n % 2);
        let mut f = fields();
        f.rating = (n % 3) as u8;
        f.file_type = if n % 2 == 0 { "doc" } else { "audio" }.into();
        f.media_artist = format!("Artist {}", n % 3);
        f.media_album = format!("Album {}", n % 2);
        f.media_title = names[index].into();
        f.media_length_seconds = n % 3;
        f.media_bitrate_kbps = n % 2;
        f.media_codec = if n % 2 == 0 { "FLAC" } else { "opus" }.into();
        let published = store
            .ingest_search_observations(
                &[packet],
                &crate::MetadataSearchProjection {
                    session_id: session,
                    fields: vec![f],
                    name_votes: vec![name_vote(names[index])],
                },
            )
            .unwrap()
            .unwrap();
        expected.push(
            store
                .search_result_header(session, published.claim_id)
                .unwrap()
                .unwrap(),
        );
    }
    for sort in SORTS {
        for order in [Order::Asc, Order::Desc] {
            let mut expected = expected.clone();
            expected.sort_by(|a, b| {
                let cmp = compare(a, b, sort);
                if order == Order::Desc {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
            let mut q = query(session, sort, order);
            let mut actual = Vec::new();
            loop {
                let page = store.search_results_page(&q).unwrap().unwrap();
                assert!(page.items.len() <= q.limit);
                q.after_claim_id = page.items.last().map(|r| r.claim_id);
                actual.extend(page.items.into_iter().map(|r| r.claim_id));
                if !page.has_more {
                    break;
                }
            }
            assert_eq!(
                actual,
                expected.iter().map(|r| r.claim_id).collect::<Vec<_>>(),
                "{sort:?} {order:?}"
            );
        }
    }
}
#[test]
fn every_late_sort_seek_uses_its_index_without_scanning_or_sorting_one_hundred_thousand_ties() {
    let store = crate::MetadataStore::in_memory().unwrap();
    let session = store.create_search(&sample_search()).unwrap();
    let conn = store.connection().unwrap();
    conn.execute_batch(
        "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO content_claims(id,ed2k_hash,size_bytes,first_seen_at_s,last_seen_at_s)
        SELECT i,zeroblob(16),CAST(printf('%08d',i) AS BLOB),1,1 FROM n;",
    )
    .unwrap();
    conn.execute("INSERT INTO search_results(session_id,claim_id,size_sort_key,ed2k_hash,name,file_type,media_artist,media_album,media_title,
        media_length_seconds,media_bitrate_kbps,media_codec,rating,complete,directory)
        SELECT ?1,id,size_sort_key,ed2k_hash,'same','doc','same','same','same',1,1,'same',1,0,'' FROM content_claims",[session]).unwrap();
    // Membership must remain a point seek even with 100k conflicting sizes
    // for one hash, or when that entire hash is absent from another session.
    for (id, hash, expected) in [
        (session, [0u8; 16], true),
        (session + 1, [0u8; 16], false),
        (session, [0xff; 16], false),
    ] {
        let mut probe = conn
            .prepare(crate::search_store::SESSION_HASH_MEMBERSHIP_SQL)
            .unwrap();
        let present: bool = probe
            .query_row(params![id, hash.as_slice()], |row| row.get(0))
            .unwrap();
        assert_eq!(present, expected);
        assert_eq!(probe.get_status(rusqlite::StatementStatus::FullscanStep), 0);
        assert!(probe.get_status(rusqlite::StatementStatus::VmStep) < 100);
    }
    for sort in SORTS {
        for order in [Order::Asc, Order::Desc] {
            let mut q = query(session, sort, order);
            q.after_claim_id = Some(if order == Order::Asc { 99990 } else { 11 });
            let mut point = conn.prepare(&anchor_sql(&q)).unwrap();
            let _: rusqlite::types::Value = point
                .query_row(params![session, q.after_claim_id], |r| r.get(0))
                .unwrap();
            assert_eq!(point.get_status(rusqlite::StatementStatus::FullscanStep), 0);
            assert!(point.get_status(rusqlite::StatementStatus::VmStep) < 100);
            let mut statement = conn.prepare(&sql(&q)).unwrap();
            let ids = statement
                .query_map(
                    params![
                        session,
                        anchor(&conn, &q).unwrap().unwrap(),
                        q.after_claim_id,
                        3
                    ],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert_eq!(
                ids,
                if order == Order::Asc {
                    vec![99991, 99992, 99993]
                } else {
                    vec![10, 9, 8]
                },
                "{sort:?} {order:?}"
            );
            assert_eq!(
                statement.get_status(rusqlite::StatementStatus::FullscanStep),
                0,
                "{sort:?} {order:?}"
            );
            assert_eq!(
                statement.get_status(rusqlite::StatementStatus::Sort),
                0,
                "{sort:?} {order:?}"
            );
            assert!(
                statement.get_status(rusqlite::StatementStatus::VmStep) < 1000,
                "{sort:?} {order:?}: {} steps",
                statement.get_status(rusqlite::StatementStatus::VmStep)
            );
        }
    }
}
#[test]
fn size_sort_keys_cannot_contradict_the_claim_and_missing_boundaries_stay_bounded() {
    let store = crate::MetadataStore::in_memory().unwrap();
    let session = store.create_search(&sample_search()).unwrap();
    let claim = crate::search_store::tests::project(&store, session, None, "Sample.bin");
    let conn = store.connection().unwrap();
    assert!(
        conn.execute(
            "UPDATE search_results SET ed2k_hash=zeroblob(16) WHERE session_id=?1 AND claim_id=?2",
            params![session, claim]
        )
        .is_err()
    );
    assert!(conn.execute("UPDATE search_results SET size_sort_key=x'010000000000000000' WHERE session_id=?1 AND claim_id=?2",params![session,claim]).is_err());
    let key: Vec<u8> = conn
        .query_row(
            "SELECT size_sort_key FROM content_claims WHERE id=?1",
            [claim],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(key, vec![0]);
    drop(conn);
    let mut q = query(session, Sort::SizeBytes, Order::Asc);
    q.after_claim_id = Some(i64::MAX);
    assert!(
        store
            .search_results_page(&q)
            .unwrap()
            .unwrap()
            .items
            .is_empty()
    );
    q.session_id = session + 1;
    assert!(store.search_results_page(&q).unwrap().is_none());
    q.session_id = session;
    q.limit = 201;
    assert!(store.search_results_page(&q).is_err());
}

#[test]
fn long_name_keys_continue_by_identity_without_becoming_cursor_payload() {
    let store = crate::MetadataStore::in_memory().unwrap();
    let session = store.create_search(&sample_search()).unwrap();
    let mut expected = Vec::new();
    for index in 1..=3 {
        let name = format!("{}-{index}.bin", "x".repeat(5000));
        expected.push(crate::search_store::tests::project(
            &store,
            session,
            Some(index),
            &name,
        ));
    }
    let mut q = query(session, Sort::Name, Order::Asc);
    q.limit = 1;
    let mut actual = Vec::new();
    loop {
        let page = store.search_results_page(&q).unwrap().unwrap();
        q.after_claim_id = page.items.last().map(|row| row.claim_id);
        actual.extend(page.items.into_iter().map(|row| row.claim_id));
        if !page.has_more {
            break;
        }
    }
    assert_eq!(actual, expected);
}
