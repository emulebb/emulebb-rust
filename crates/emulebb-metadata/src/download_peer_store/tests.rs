use super::*;

#[test]
fn server_low_id_rows_are_scoped_by_server_and_keep_the_latest_port() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    let server_a = "203.0.113.8:4242".parse().unwrap();
    let server_b = "203.0.113.9:4242".parse().unwrap();
    let mut candidate = source(0, String::new());
    let direct = MetadataDownloadSourceRoute::DirectWithServer(server_a);
    let callback = |server| MetadataDownloadSourceRoute::ServerLowId {
        client_id: 0x0002_00C0,
        server,
    };
    for route in [direct, callback(server_a), callback(server_b)] {
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::RoutedSource {
                    source: candidate.clone(),
                    route,
                },
            )
            .unwrap();
    }
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::Source {
                source: candidate.clone(),
                description_only: false,
            },
        )
        .unwrap();
    candidate.tcp_port = 4663;
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::RoutedSource {
                source: candidate,
                route: callback(server_a),
            },
        )
        .unwrap();
    let endpoints = store
        .download_job_source_endpoints_after(current.token, 0, 10)
        .unwrap();
    assert_eq!(endpoints.len(), 3);
    assert_eq!(endpoints[0].route, Some(direct));
    assert_eq!(endpoints[0].tcp_port, 4662);
    let callbacks = store
        .download_job_server_callback_endpoints_after(current.token, 0, 10)
        .unwrap();
    assert_eq!(callbacks.len(), 2);
    assert_eq!(callbacks[0].route, Some(callback(server_a)));
    assert_eq!(callbacks[0].tcp_port, 4663);
    assert_eq!(callbacks[1].route, Some(callback(server_b)));
    assert_eq!(callbacks[1].tcp_port, 4662);
}

#[test]
fn sparse_comment_pages_seek_the_comment_index_and_fence_old_generations() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    {
        let mut conn = store.connection().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "WITH RECURSIVE source_ids(n) AS (
            VALUES(1) UNION ALL SELECT n+1 FROM source_ids WHERE n<100000)
            INSERT INTO download_job_sources(job_id,ip,tcp_port,first_seen_at_s,last_seen_at_s)
            SELECT ?1,'192.0.2.' || (1+(n-1)/65535),1+(n-1)%65535,0,0 FROM source_ids",
            params![current.token.job_id],
        )
        .unwrap();
        tx.execute(
            "UPDATE download_job_sources SET
            file_comment=CASE id WHEN 2 THEN 'first' WHEN 99999 THEN 'last' ELSE '' END,
            file_rating=CASE WHEN id=50000 THEN 4 ELSE 0 END
            WHERE job_id=?1 AND id IN (2,50000,99999)",
            params![current.token.job_id],
        )
        .unwrap();
        tx.commit().unwrap();
        let mut explain = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {COMMENTS_SQL}"))
            .unwrap();
        let plan = explain
            .query_map(
                params![current.token.job_id, 2, current.token.generation as i64, 2],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join("\n");
        assert!(plan.contains("download_job_sources_comments_idx"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    }
    let first = store
        .download_job_comments_after(current.token, 0, 1)
        .unwrap();
    assert_eq!(first.comments.len(), 1);
    assert_eq!(first.comments[0].id, 2);
    assert_eq!(first.comments[0].comment, "first");
    assert!(first.has_more);
    let second = store
        .download_job_comments_after(current.token, 2, 1)
        .unwrap();
    assert_eq!(second.comments.len(), 1);
    assert_eq!(second.comments[0].id, 50000);
    assert_eq!(second.comments[0].rating, 4);
    assert!(second.has_more);
    let last = store
        .download_job_comments_after(current.token, 50000, 2)
        .unwrap();
    assert_eq!(last.comments.len(), 1);
    assert_eq!(last.comments[0].id, 99999);
    assert!(!last.has_more);
    assert!(store.stop_download_job(current.token).unwrap());
    let stale = store
        .download_job_comments_after(current.token, 0, 2)
        .unwrap();
    assert!(stale.comments.is_empty() && !stale.has_more);
    let stopped = store.download_job(current.token.job_id).unwrap().unwrap();
    assert_eq!(
        store
            .download_job_comments_after(stopped.token, 0, 256)
            .unwrap()
            .comments
            .len(),
        3
    );
}

#[test]
fn comment_pages_continue_at_the_byte_boundary_without_losing_rows() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    for last in 1..=20 {
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Source {
                    source: source(last, "c".repeat(65_536)),
                    description_only: false,
                },
            )
            .unwrap();
    }
    let first = store
        .download_job_comments_after(current.token, 0, 256)
        .unwrap();
    assert!(!first.comments.is_empty() && first.comments.len() < 20);
    assert!(first.has_more);
    let frontier = first.comments.last().unwrap().id;
    let last = store
        .download_job_comments_after(current.token, frontier, 256)
        .unwrap();
    assert_eq!(first.comments.len() + last.comments.len(), 20);
    assert!(last.comments[0].id > frontier);
    assert!(!last.has_more);
}

pub(super) fn job(store: &MetadataStore) -> crate::DownloadJobRecord {
    store
        .admit_download_job(&crate::DownloadJobRequest {
            file_hash: "45".repeat(16),
            display_name: "chosen.bin".into(),
            expected_size_bytes: Some(16),
            category_id: None,
            intent: crate::DownloadIntent::Started,
            piece_size: 16,
        })
        .unwrap()
        .job
}
pub(super) fn source(last: u8, comment: String) -> MetadataTransferSource {
    MetadataTransferSource {
        ip: format!("192.0.2.{last}"),
        tcp_port: 4662,
        user_hash: None,
        connect_options: None,
        file_comment: comment,
        file_rating: 0,
    }
}
fn observation(name: String) -> MetadataTransferFileNameObservation {
    MetadataTransferFileNameObservation {
        source_ip: Some("192.0.2.1".into()),
        source_tcp_port: Some(4662),
        user_hash: None,
        client_software: String::new(),
        origin: "peer".into(),
        reporter_endpoint: None,
        normalized_name: name.clone(),
        raw_name: name,
        observed_at_s: 1,
    }
}

#[test]
fn peer_deltas_preserve_chosen_name_and_verified_checkpoint_cannot_replay_old_name() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    let stale = store
        .download_job_manifest(current.token.job_id)
        .unwrap()
        .unwrap();
    for _ in 0..4 {
        let mut observed = observation("peer-proposed.bin".into());
        observed.reporter_endpoint = Some("192.0.2.7:4672".into());
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::ObserveName {
                    observation: observed,
                    source: Some(source(1, String::new())),
                },
            )
            .unwrap();
    }
    assert_eq!(
        store
            .download_job(current.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        "chosen.bin"
    );
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::Rename("operator.bin".into()),
        )
        .unwrap();
    let stored = store
        .upsert_transfer_manifest_reconciled(&stale, Ok)
        .unwrap();
    assert_eq!(stored.display_name, "operator.bin");
    assert_eq!(
        store
            .download_job_names_after(current.token, 0, 256)
            .unwrap()
            .len(),
        4
    );
    let names = store
        .download_job_names_after(current.token, 0, 256)
        .unwrap();
    assert!(
        names
            .iter()
            .all(|entry| entry.observation.reporter_endpoint.as_deref() == Some("192.0.2.7:4672"))
    );
    assert!(store.stop_download_job(current.token).unwrap());
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Source {
                    source: source(2, String::new()),
                    description_only: false,
                }
            )
            .is_err()
    );
    let stopped = store.download_job(current.token.job_id).unwrap().unwrap();
    assert_eq!(
        store
            .download_job_sources_after(stopped.token, 0, 256)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn source_windows_are_latest_first_identity_scoped_and_explicit_about_omissions() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    let anonymous = source(1, String::new());
    let mut identified = source(2, String::new());
    identified.user_hash = Some("77".repeat(16));
    for input in [&anonymous, &identified] {
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Source {
                    source: input.clone(),
                    description_only: false,
                },
            )
            .unwrap();
    }
    for index in 0..20 {
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::ObserveName {
                    observation: observation(format!("Sample-{index}.bin")),
                    source: None,
                },
            )
            .unwrap();
    }
    let mut named = observation("Peer.bin".into());
    named.user_hash = identified.user_hash.clone();
    named.source_ip = Some("198.51.100.8".into());
    named.source_tcp_port = Some(4000);
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::ObserveName {
                observation: named,
                source: None,
            },
        )
        .unwrap();
    let page = store
        .download_job_sources_after(current.token, 0, 2)
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].reported_file_names.len(), 16);
    assert_eq!(page[0].reported_file_names[0].raw_name, "Sample-19.bin");
    assert_eq!(page[0].reported_file_names[15].raw_name, "Sample-4.bin");
    assert!(page[0].reported_file_names_has_more);
    assert_eq!(page[1].reported_file_names.len(), 1);
    assert_eq!(page[1].reported_file_names[0].raw_name, "Peer.bin");
    assert!(!page[1].reported_file_names_has_more);
    let exact = store
        .download_job_source(
            current.token,
            MetadataDownloadSourceSelector::Endpoint("192.0.2.1".parse().unwrap(), 4662),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        exact.reported_file_names[0].raw_name,
        page[0].reported_file_names[0].raw_name
    );
    assert_eq!(
        exact.reported_file_names_has_more,
        page[0].reported_file_names_has_more
    );
    let exact = store
        .download_job_source(
            current.token,
            MetadataDownloadSourceSelector::UserHash([0x77; 16]),
        )
        .unwrap()
        .unwrap();
    assert_eq!(exact.reported_file_names[0].raw_name, "Peer.bin");
    assert!(
        store
            .download_job_source(
                current.token,
                MetadataDownloadSourceSelector::UserHash([0x78; 16])
            )
            .unwrap()
            .is_none()
    );
    drop(page);
    // An oversized current observation is omitted, never truncated. The same
    // stable latest window still reports that something was omitted.
    store.connection().unwrap().execute(
        "UPDATE download_job_file_name_observations SET raw_name=?2 WHERE job_id=?1 AND user_hash IS NOT NULL",
        params![current.token.job_id, "x".repeat(65_537)],
    ).unwrap();
    let page = store
        .download_job_sources_after(current.token, 0, 2)
        .unwrap();
    assert!(page[1].reported_file_names.is_empty());
    assert!(page[1].reported_file_names_has_more);
    assert_eq!(
        store
            .download_job(current.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        "chosen.bin"
    );
    let conn = store.connection().unwrap();
    for (sql, parameters, index) in [
        (
            SOURCE_HASH_NAMES_SQL,
            vec![
                rusqlite::types::Value::Integer(current.token.job_id.get()),
                rusqlite::types::Value::Blob(vec![0x77; 16]),
            ],
            "download_job_names_hash_window_idx",
        ),
        (
            SOURCE_ENDPOINT_NAMES_SQL,
            vec![
                rusqlite::types::Value::Integer(current.token.job_id.get()),
                rusqlite::types::Value::Text("192.0.2.1".into()),
                rusqlite::types::Value::Integer(4662),
            ],
            "download_job_names_endpoint_window_idx",
        ),
    ] {
        let mut statement = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan = statement
            .query_map(rusqlite::params_from_iter(parameters), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(plan.iter().any(|step| step.contains(index)), "{plan:?}");
        assert!(
            !plan.iter().any(|step| step.contains("USE TEMP B-TREE")),
            "{plan:?}"
        );
    }
}

#[test]
fn nested_source_windows_share_the_page_budget_without_hiding_later_sources() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    for peer in 1..=3 {
        let input = source(peer, "c".repeat(65_536));
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Source {
                    source: input.clone(),
                    description_only: false,
                },
            )
            .unwrap();
        for _ in 0..16 {
            let mut name = observation("r".repeat(65_536));
            name.normalized_name = "Sample.bin".into();
            name.source_ip = Some(input.ip.clone());
            store
                .apply_download_peer_delta(
                    current.token,
                    &MetadataDownloadPeerDelta::ObserveName {
                        observation: name,
                        source: None,
                    },
                )
                .unwrap();
        }
    }
    let mut after = 0;
    let mut count = 0;
    loop {
        let page = store
            .download_job_sources_after(current.token, after, 3)
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page[0].id > after);
        for entry in &page {
            assert!(entry.reported_file_names.len() < 16);
            assert!(entry.reported_file_names_has_more);
            assert!(
                entry
                    .reported_file_names
                    .iter()
                    .all(|name| name.raw_name.len() == 65_536)
            );
        }
        let mut bytes = page.capacity() * std::mem::size_of::<MetadataDownloadSourceEntry>();
        for entry in &page {
            bytes += entry.source.ip.capacity()
                + entry.source.file_comment.capacity()
                + entry.source.user_hash.as_ref().map_or(0, String::capacity)
                + entry.reported_file_names.capacity()
                    * std::mem::size_of::<MetadataTransferFileNameObservation>();
            for name in &entry.reported_file_names {
                bytes += name.source_ip.as_ref().map_or(0, String::capacity)
                    + name.user_hash.as_ref().map_or(0, String::capacity)
                    + name.client_software.capacity()
                    + name.origin.capacity()
                    + name.reporter_endpoint.as_ref().map_or(0, String::capacity)
                    + name.raw_name.capacity()
                    + name.normalized_name.capacity();
            }
        }
        assert!(bytes <= PAGE_BYTES, "{bytes}");
        count += page.len();
        after = page.last().unwrap().id;
    }
    assert_eq!(count, 3);
}

#[test]
fn peer_pages_bound_actual_text_and_keep_stable_cursor_and_endpoint_counts() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    for last in 1..=20 {
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Source {
                    source: source(last, "x".repeat(65_536)),
                    description_only: false,
                },
            )
            .unwrap();
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::ObserveName {
                    observation: observation("n".repeat(65_536)),
                    source: None,
                },
            )
            .unwrap();
    }
    let first = store
        .download_job_sources_after(current.token, 0, 256)
        .unwrap();
    assert!(!first.is_empty() && first.len() < 20);
    let second = store
        .download_job_sources_after(current.token, first.last().unwrap().id, 256)
        .unwrap();
    assert_eq!(first.len() + second.len(), 20);
    assert!(second[0].id > first.last().unwrap().id);
    assert_eq!(
        store
            .download_job_source_endpoints_after(current.token, 0, 256)
            .unwrap()
            .len(),
        20
    );
    let mut count = 0;
    let mut after = 0;
    loop {
        let page = store
            .download_job_names_after(current.token, after, 256)
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page[0].id > after);
        after = page.last().unwrap().id;
        count += page.len();
    }
    assert_eq!(count, 20);
    // Geometry hydration does not materialize either diagnostic relation.
    let mut events = 0;
    assert!(
        store
            .stream_download_execution(current.token, |_| {
                events += 1;
                Ok(())
            })
            .unwrap()
    );
    assert_eq!(events, 1);
    store.connection().unwrap().execute("UPDATE download_job_sources SET file_comment=?2 WHERE job_id=?1 AND id=(SELECT min(id) FROM download_job_sources WHERE job_id=?1)",
        params![current.token.job_id,"x".repeat(65_537)]).unwrap();
    assert!(
        store
            .download_job_sources_after(current.token, 0, 256)
            .is_err()
    );
}

#[test]
fn source_rediscovery_preserves_description_and_first_seen() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    let mut input = source(1, "retained comment".into());
    input.user_hash = Some("77".repeat(16));
    input.connect_options = Some(0);
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::Source {
                source: input.clone(),
                description_only: false,
            },
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_job_sources SET first_seen_at_s=1 WHERE job_id=?1",
            [current.token.job_id],
        )
        .unwrap();
    store
        .apply_download_peer_delta(
            current.token,
            &MetadataDownloadPeerDelta::Source {
                source: source(1, String::new()),
                description_only: false,
            },
        )
        .unwrap();
    let page = store
        .download_job_sources_after(current.token, 0, 256)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].source, input);
    let first: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT first_seen_at_s FROM download_job_sources WHERE job_id=?1",
            [current.token.job_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(first, 1);
}

#[test]
fn payload_verification_does_not_freeze_name_but_attempt_and_terminal_completion_do() {
    let store = MetadataStore::in_memory().unwrap();
    let current = job(&store);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET completed=1,visible_state='completed' WHERE id=?1",
            [current.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Rename("operator-before-attempt.bin".into())
            )
            .unwrap()
            .changed
    );
    let root = std::env::temp_dir();
    let attempt = uuid::Uuid::new_v4();
    store
        .begin_transfer_delivery_attempt(
            current.token,
            attempt,
            &root.join("delivered.bin"),
            &root.join(format!(".emulebb-delivery-{attempt}.tmp")),
        )
        .unwrap();
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Rename("too-late.bin".into())
            )
            .is_err()
    );
    let snapshot = store
        .download_job_delivery_attempt(current.token.job_id)
        .unwrap()
        .unwrap();
    let target_id: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT target_path_id FROM download_delivery_attempts WHERE job_id=?1",
            [current.token.job_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        store
            .settle_recovered_delivery_attempt(current.token, &snapshot)
            .unwrap()
    );
    // Establish a terminal historical fact; payload verification alone above
    // deliberately did not do this. A completed output cannot be renamed.
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET delivery_state='delivered',delivery_ownership='unowned',
        delivered_path_id=?2 WHERE id=?1",
            params![current.token.job_id, target_id],
        )
        .unwrap();
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Rename("delivered.bin".into())
            )
            .is_err()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET terminal_completed_at_s=1 WHERE id=?1",
            [current.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::Rename("history.bin".into())
            )
            .is_err()
    );
    assert_eq!(
        store
            .download_job(current.token.job_id)
            .unwrap()
            .unwrap()
            .display_name,
        "operator-before-attempt.bin"
    );
}
