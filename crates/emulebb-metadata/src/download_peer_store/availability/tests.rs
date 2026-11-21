use super::*;
use crate::download_peer_store::tests::{job, source};

fn delta(last: u8) -> MetadataDownloadPeerDelta {
    let mut source = source(last, String::new());
    source.user_hash = Some("12".repeat(16));
    MetadataDownloadPeerDelta::Availability {
        source,
        session_id: [1; 16],
        file_size_bytes: 16,
        available_parts: vec![true],
        observed_at_s: 10,
    }
}
fn query(token: JobToken) -> MetadataDownloadAvailabilityQuery {
    MetadataDownloadAvailabilityQuery {
        token,
        session_id: [1; 16],
        observed_since_s: 0,
        observed_until_s: 20,
        after_source_id: 0,
        limit: 256,
    }
}

#[test]
fn live_callback_proof_needs_no_endpoint_and_supersedes_its_older_status() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    let q = MetadataDownloadScarcityQuery {
        token: job.token,
        session_id: [1; 16],
        observed_since_s: 0,
        observed_until_s: 20,
        user_hash: [0x12; 16],
    };
    assert!(
        store
            .download_job_live_source_has_rare_part(q, 16, &[true])
            .unwrap()
    );
    assert!(
        store
            .download_job_source_endpoints_after(job.token, 0, 256)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .download_job_live_source_has_rare_part(q, 17, &[true])
            .is_err()
    );
    assert!(
        store
            .download_job_live_source_has_rare_part(q, 16, &[true, true])
            .is_err()
    );
    store
        .apply_download_peer_delta(job.token, &delta(1))
        .unwrap();
    assert!(
        !store
            .download_job_live_source_has_rare_part(q, 16, &[false])
            .unwrap(),
        "an older same-identity endpoint must not restore a part absent from the live reply"
    );
    let mut other = delta(2);
    let MetadataDownloadPeerDelta::Availability { source, .. } = &mut other else {
        unreachable!()
    };
    source.user_hash = Some("34".repeat(16));
    store.apply_download_peer_delta(job.token, &other).unwrap();
    assert!(
        !store
            .download_job_live_source_has_rare_part(q, 16, &[true])
            .unwrap()
    );
    let stale = MetadataDownloadScarcityQuery {
        token: JobToken {
            generation: job.token.generation + 1,
            ..job.token
        },
        ..q
    };
    assert!(
        !store
            .download_job_live_source_has_rare_part(stale, 16, &[true])
            .unwrap()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='stopped' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        !store
            .download_job_live_source_has_rare_part(q, 16, &[true])
            .unwrap()
    );
}

#[test]
fn scarcity_counts_reporters_not_endpoints_and_excludes_verified_or_stale_parts() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    let q = MetadataDownloadScarcityQuery {
        token: job.token,
        session_id: [1; 16],
        observed_since_s: 0,
        observed_until_s: 20,
        user_hash: [0x12; 16],
    };
    assert!(!store.download_job_has_rare_source_part(q).unwrap());
    store
        .apply_download_peer_delta(job.token, &delta(1))
        .unwrap();
    store
        .apply_download_peer_delta(job.token, &delta(2))
        .unwrap();
    assert!(
        store.download_job_has_rare_source_part(q).unwrap(),
        "two endpoints are one reporter"
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_job_source_availability SET part_status=x'80' WHERE job_id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        !store.download_job_has_rare_source_part(q).unwrap(),
        "padding is not payload"
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_job_source_availability SET part_status=x'01' WHERE job_id=?1",
            [job.token.job_id],
        )
        .unwrap();
    let mut other = delta(3);
    let MetadataDownloadPeerDelta::Availability {
        source,
        available_parts,
        ..
    } = &mut other
    else {
        unreachable!()
    };
    source.user_hash = Some("34".repeat(16));
    available_parts[0] = false;
    store.apply_download_peer_delta(job.token, &other).unwrap();
    assert!(store.download_job_has_rare_source_part(q).unwrap());
    let MetadataDownloadPeerDelta::Availability {
        available_parts, ..
    } = &mut other
    else {
        unreachable!()
    };
    available_parts[0] = true;
    store.apply_download_peer_delta(job.token, &other).unwrap();
    assert!(!store.download_job_has_rare_source_part(q).unwrap());
    assert!(
        !store
            .download_job_has_rare_source_part(MetadataDownloadScarcityQuery {
                user_hash: [0x56; 16],
                ..q
            })
            .unwrap()
    );
    assert!(
        !store
            .download_job_has_rare_source_part(MetadataDownloadScarcityQuery {
                session_id: [2; 16],
                ..q
            })
            .unwrap()
    );
    assert!(
        !store
            .download_job_has_rare_source_part(MetadataDownloadScarcityQuery {
                observed_since_s: 11,
                ..q
            })
            .unwrap()
    );
    assert!(
        !store
            .download_job_has_rare_source_part(MetadataDownloadScarcityQuery {
                token: JobToken {
                    generation: job.token.generation + 1,
                    ..job.token
                },
                ..q
            })
            .unwrap()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM download_job_sources WHERE job_id=?1 AND ip='192.0.2.3'",
            [job.token.job_id],
        )
        .unwrap();
    assert!(store.download_job_has_rare_source_part(q).unwrap());
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO download_job_pieces
        (job_id,piece_index,state,prefix_bytes,present_bytes,ich_corrupted,updated_at_s)
        VALUES(?1,0,'Verified',16,16,0,0)",
            [job.token.job_id],
        )
        .unwrap();
    assert!(!store.download_job_has_rare_source_part(q).unwrap());
    store
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM download_job_pieces WHERE job_id=?1",
            [job.token.job_id],
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='stopped' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(!store.download_job_has_rare_source_part(q).unwrap());
}

#[test]
fn observations_fence_session_time_generation_intent_and_identity() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    store
        .apply_download_peer_delta(job.token, &delta(1))
        .unwrap();
    let page = store
        .download_job_source_availability(query(job.token))
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(page[0].has_part(0));
    assert!(!page[0].has_part(1));
    assert_eq!(page[0].user_hash, [0x12; 16]);
    assert_eq!(page[0].part_status, [1]);
    let mut q = query(job.token);
    q.session_id = [2; 16];
    assert!(
        store
            .download_job_source_availability(q)
            .unwrap()
            .is_empty()
    );
    q = query(job.token);
    q.observed_since_s = 11;
    assert!(
        store
            .download_job_source_availability(q)
            .unwrap()
            .is_empty()
    );
    q = query(job.token);
    q.observed_until_s = 9;
    assert!(
        store
            .download_job_source_availability(q)
            .unwrap()
            .is_empty()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='stopped' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_job_source_availability(query(job.token))
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .apply_download_peer_delta(job.token, &delta(1))
            .is_err()
    );
    store.connection().unwrap().execute("UPDATE download_jobs SET intent='started',execution_generation=execution_generation+1 WHERE id=?1", [job.token.job_id]).unwrap();
    let newer = JobToken {
        generation: job.token.generation + 1,
        ..job.token
    };
    assert!(
        store
            .apply_download_peer_delta(job.token, &delta(1))
            .is_err()
    );
    assert!(
        store
            .download_job_source_availability(query(newer))
            .unwrap()
            .is_empty()
    );
    store.apply_download_peer_delta(newer, &delta(1)).unwrap();
    let mut replacement = source(1, String::new());
    replacement.user_hash = Some("34".repeat(16));
    store
        .apply_download_peer_delta(
            newer,
            &MetadataDownloadPeerDelta::Source {
                source: replacement,
                description_only: false,
            },
        )
        .unwrap();
    assert!(
        store
            .download_job_source_availability(query(newer))
            .unwrap()
            .is_empty()
    );
    store
        .apply_download_peer_delta(
            newer,
            &MetadataDownloadPeerDelta::RemoveSource {
                endpoint: Some(("192.0.2.1".parse().unwrap(), 4662)),
                user_hash: None,
            },
        )
        .unwrap();
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM download_job_source_availability",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn invalid_geometry_and_failed_status_write_leave_no_partial_source() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    let mut input = delta(1);
    let MetadataDownloadPeerDelta::Availability {
        file_size_bytes, ..
    } = &mut input
    else {
        unreachable!()
    };
    *file_size_bytes = 17;
    assert!(store.apply_download_peer_delta(job.token, &input).is_err());
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_availability BEFORE INSERT ON download_job_source_availability BEGIN SELECT RAISE(ABORT,'synthetic status refusal'); END;").unwrap();
    assert!(
        store
            .apply_download_peer_delta(job.token, &delta(1))
            .is_err()
    );
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM download_job_sources", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn sparse_observations_seek_status_rows_among_one_hundred_thousand_hints() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    store
        .connection()
        .unwrap()
        .execute(
            "WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<100000)
        INSERT INTO download_job_sources(job_id,ip,tcp_port,first_seen_at_s,last_seen_at_s)
        SELECT ?1,'192.0.2.' || (1+(i-1)/65535),1+(i-1)%65535,0,0 FROM n",
            [job.token.job_id],
        )
        .unwrap();
    for (ip, port) in [(1, 2), (2, 34464)] {
        let mut input = delta(ip);
        let MetadataDownloadPeerDelta::Availability { source, .. } = &mut input else {
            unreachable!()
        };
        source.tcp_port = port;
        store.apply_download_peer_delta(job.token, &input).unwrap();
    }
    let page = store
        .download_job_source_availability(query(job.token))
        .unwrap();
    assert_eq!(
        page.iter().map(|v| v.source_id).collect::<Vec<_>>(),
        [2, 99999]
    );
    let mut q = query(job.token);
    q.limit = 1;
    let first = store.download_job_source_availability(q).unwrap();
    q.after_source_id = first[0].source_id;
    assert_eq!(
        store.download_job_source_availability(q).unwrap()[0].source_id,
        99999
    );
    let conn = store.connection().unwrap();
    let plan = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {PAGE_SQL}"))
        .unwrap()
        .query_map(
            params![
                job.token.job_id,
                0,
                job.token.generation as i64,
                [1u8; 16].as_slice(),
                0,
                20,
                256
            ],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n");
    assert!(plan.contains("SEARCH a USING PRIMARY KEY"), "{plan}");
    assert!(
        !plan.contains("SCAN s") && !plan.contains("TEMP B-TREE"),
        "{plan}"
    );
}

#[test]
fn byte_bounded_pages_preserve_all_large_bitmaps_across_cursor_pages() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: "67".repeat(16),
            display_name: "large-status.bin".into(),
            expected_size_bytes: Some(65534 * 16),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 16,
        })
        .unwrap()
        .job;
    for port in 1..=256 {
        let mut input = delta(1);
        let MetadataDownloadPeerDelta::Availability {
            source,
            available_parts,
            file_size_bytes,
            ..
        } = &mut input
        else {
            unreachable!()
        };
        source.tcp_port = port;
        *file_size_bytes = 65534 * 16;
        *available_parts = vec![true; 65534];
        store.apply_download_peer_delta(job.token, &input).unwrap();
    }
    let mut q = query(job.token);
    let mut total = 0;
    loop {
        let page = store.download_job_source_availability(q).unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() < 256);
        assert!(
            page.iter()
                .map(|row| row.part_status.capacity()
                    + 2 * std::mem::size_of::<MetadataDownloadSourceAvailability>())
                .sum::<usize>()
                <= PAGE_BYTES
        );
        assert!(
            page.iter()
                .all(|row| row.has_part(65533) && !row.has_part(65534))
        );
        total += page.len();
        q.after_source_id = page.last().unwrap().source_id;
    }
    assert_eq!(total, 256);
    let q = MetadataDownloadScarcityQuery {
        token: job.token,
        session_id: [1; 16],
        observed_since_s: 0,
        observed_until_s: 20,
        user_hash: [0x12; 16],
    };
    assert!(store.download_job_has_rare_source_part(q).unwrap());
    let mut last_reporter = delta(1);
    let MetadataDownloadPeerDelta::Availability {
        source,
        file_size_bytes,
        available_parts,
        ..
    } = &mut last_reporter
    else {
        unreachable!()
    };
    source.tcp_port = 256;
    source.user_hash = Some("34".repeat(16));
    *file_size_bytes = 65534 * 16;
    *available_parts = vec![true; 65534];
    store
        .apply_download_peer_delta(job.token, &last_reporter)
        .unwrap();
    assert!(
        !store.download_job_has_rare_source_part(q).unwrap(),
        "the competing reporter beyond one byte-bounded page still counts"
    );
}
