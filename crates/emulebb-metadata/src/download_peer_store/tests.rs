use super::*;

fn job(store: &MetadataStore) -> crate::DownloadJobRecord {
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
fn source(last: u8, comment: String) -> MetadataTransferSource {
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
        server_endpoint: None,
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
        store
            .apply_download_peer_delta(
                current.token,
                &MetadataDownloadPeerDelta::ObserveName {
                    observation: observation("peer-proposed.bin".into()),
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
    let stored = store.upsert_transfer_manifest_reconciled(&stale).unwrap();
    assert_eq!(stored.display_name, "operator.bin");
    assert_eq!(
        store
            .download_job_names_after(current.token, 0, 256)
            .unwrap()
            .len(),
        4
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
