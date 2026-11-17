use super::*;
use crate::{DownloadIntent, DownloadJobRequest, NativeFileIdentity, NativeFileTimestamp};

fn request() -> DownloadJobRequest {
    DownloadJobRequest {
        file_hash: "51".repeat(16),
        display_name: "sample.bin".into(),
        expected_size_bytes: Some(8),
        category_id: None,
        intent: DownloadIntent::Started,
        piece_size: 1024,
    }
}
fn root_and_file(store: &MetadataStore) -> (i64, i64) {
    let root = std::env::temp_dir().join("availability-fixture");
    let fingerprint = NativeFileFingerprint {
        identity: NativeFileIdentity::Unix {
            device_id: 1,
            inode_number: 2,
        },
        size_bytes: 8,
        modified: NativeFileTimestamp::new(1, 0).unwrap(),
        changed: None,
    };
    let mut conn = store.connection().unwrap();
    let tx = conn.transaction().unwrap();
    let parent = crate::store::upsert_local_path(&tx, &root).unwrap();
    let path = crate::store::upsert_local_path(&tx, &root.join("sample.bin")).unwrap();
    tx.execute(
        "INSERT INTO shared_directory_roots(path_id,accessible,created_at_ms) VALUES(?1,0,0)",
        [parent],
    )
    .unwrap();
    let root_id = tx.last_insert_rowid();
    tx.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_ms)
        SELECT ?1,id,8,?2,?3,0 FROM known_files WHERE ed2k_hash=?4",params![path,fingerprint.identity.storage_bytes(),fingerprint.storage_bytes(),vec![0x51u8;16]]).unwrap();
    tx.execute("INSERT INTO shared_file_memberships(root_id,path_id,known_file_id,relative_path,first_seen_at_ms,last_seen_at_ms)
        SELECT ?1,?2,id,'sample.bin',0,0 FROM known_files WHERE ed2k_hash=?3",params![root_id,path,vec![0x51u8;16]]).unwrap();
    tx.commit().unwrap();
    (root_id, path)
}

#[test]
fn offline_copy_is_included_and_lengths_are_checked_before_decoding() {
    let store = MetadataStore::in_memory().unwrap();
    store.admit_download_job(&request()).unwrap();
    let (_root, path) = root_and_file(&store);
    let cut = store.capture_download_availability().unwrap();
    let step = store
        .next_download_availability(
            &request().file_hash,
            AvailabilitySource::Library,
            0,
            &cut,
            2 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert_eq!(step.key, path);
    assert!(!step.candidate.unwrap().root_accessible);
    assert!(step.charged_bytes < 2 * 1024 * 1024);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE local_paths SET native_path=zeroblob(65538) WHERE id=?1",
            [path],
        )
        .unwrap();
    let cut = store.capture_download_availability().unwrap();
    let step = store
        .next_download_availability(
            &request().file_hash,
            AvailabilitySource::Library,
            0,
            &cut,
            2 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert_eq!(step.charged_bytes, usize::MAX);
    assert!(step.candidate.is_none());
}

#[test]
fn delivered_fact_survives_terminal_internal_retirement() {
    let store = MetadataStore::in_memory().unwrap();
    let job = store.admit_download_job(&request()).unwrap().job;
    let (_, path) = root_and_file(&store);
    store.connection().unwrap().execute("UPDATE download_jobs SET completed=1,visible_state='completed',delivery_state='delivered',
        delivery_ownership='unowned',delivered_path_id=?2,terminal_completed_at_s=1,internal_storage_retired=1 WHERE id=?1",params![job.token.job_id,path]).unwrap();
    let cut = store.capture_download_availability().unwrap();
    let step = store
        .next_download_availability(
            &request().file_hash,
            AvailabilitySource::Delivered,
            0,
            &cut,
            2 * 1024 * 1024,
        )
        .unwrap()
        .unwrap();
    assert_eq!(step.key, job.token.job_id.get());
    assert!(step.candidate.is_some());
    assert!(
        store
            .active_download_job(&request().file_hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn exact_cut_and_root_epoch_are_checked_inside_creating_transaction() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let store = MetadataStore::in_memory().unwrap();
    let epoch = AtomicU64::new(0);
    let cut = store.capture_download_availability().unwrap();
    store
        .connection()
        .unwrap()
        .execute("UPDATE download_job_counts SET unfinished=unfinished", [])
        .unwrap();
    let gate = DownloadAvailabilityAdmission {
        initial_peers: &Default::default(),
        cut: &cut,
        availability: LocalContentAvailability::ConfirmedAbsent,
        redownload: false,
        aich_root: None,
        root_epoch: (&epoch, 0),
    };
    assert!(
        store
            .admit_available_download_job(&request(), gate)
            .unwrap_err()
            .is::<MetadataAvailabilityChanged>()
    );
    let cut = store.capture_download_availability().unwrap();
    epoch.store(2, Ordering::Release);
    let gate = DownloadAvailabilityAdmission {
        initial_peers: &Default::default(),
        cut: &cut,
        availability: LocalContentAvailability::ConfirmedAbsent,
        redownload: false,
        aich_root: None,
        root_epoch: (&epoch, 0),
    };
    assert!(
        store
            .admit_available_download_job(&request(), gate)
            .unwrap_err()
            .is::<MetadataAvailabilityChanged>()
    );
    assert!(
        store
            .active_download_job(&request().file_hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn claims_and_active_duplicate_precede_local_choice() {
    use std::sync::atomic::AtomicU64;
    let store = MetadataStore::in_memory().unwrap();
    let epoch = AtomicU64::new(0);
    let cut = store.capture_download_availability().unwrap();
    let initial_peers = Default::default();
    let gate = || DownloadAvailabilityAdmission {
        initial_peers: &initial_peers,
        cut: &cut,
        availability: LocalContentAvailability::Unavailable,
        redownload: false,
        aich_root: None,
        root_epoch: (&epoch, 0),
    };
    assert!(
        store
            .admit_available_download_job(&request(), gate())
            .unwrap_err()
            .is::<MetadataLocalContentChoiceRequired>()
    );
    let old = store.admit_download_job(&request()).unwrap().job;
    // Even a stale availability observation cannot create another active job.
    let duplicate = store
        .admit_available_download_job(&request(), gate())
        .unwrap();
    assert!(!duplicate.created);
    assert_eq!(duplicate.job, old);
    let mut conflict = request();
    conflict.expected_size_bytes = Some(9);
    assert!(
        store
            .admit_available_download_job(&conflict, gate())
            .unwrap_err()
            .is::<crate::MetadataContentConflict>()
    );
}

#[test]
fn admission_refuses_a_held_metadata_connection_without_using_old_evidence() {
    let store = MetadataStore::in_memory().unwrap();
    let epoch = std::sync::atomic::AtomicU64::new(0);
    let cut = store.capture_download_availability().unwrap();
    let held = store.connection().unwrap();
    let result = store.admit_available_download_job(
        &request(),
        DownloadAvailabilityAdmission {
            initial_peers: &Default::default(),
            cut: &cut,
            availability: LocalContentAvailability::ConfirmedAbsent,
            redownload: false,
            aich_root: None,
            root_epoch: (&epoch, 0),
        },
    );
    assert!(result.unwrap_err().is::<MetadataAvailabilityChanged>());
    drop(held);
    assert!(
        store
            .active_download_job(&request().file_hash)
            .unwrap()
            .is_none()
    );
}

#[test]
fn admission_refuses_external_writer_and_restores_normal_busy_policy() {
    let root = std::env::temp_dir().join(format!("availability-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("availability.sqlite");
    let store = MetadataStore::open(&database).unwrap();
    let epoch = std::sync::atomic::AtomicU64::new(0);
    let cut = store.capture_download_availability().unwrap();
    let writer = Connection::open(&database).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = store.admit_available_download_job(
        &request(),
        DownloadAvailabilityAdmission {
            initial_peers: &Default::default(),
            cut: &cut,
            availability: LocalContentAvailability::ConfirmedAbsent,
            redownload: false,
            aich_root: None,
            root_epoch: (&epoch, 0),
        },
    );
    assert!(result.unwrap_err().is::<MetadataAvailabilityChanged>());
    let restored: i64 = store
        .connection()
        .unwrap()
        .pragma_query_value(None, "busy_timeout", |row| row.get(0))
        .unwrap();
    assert_eq!(restored, 5000);
    assert!(
        store
            .active_download_job(&request().file_hash)
            .unwrap()
            .is_none()
    );
    writer.execute_batch("ROLLBACK").unwrap();
    let cut = store.capture_download_availability().unwrap();
    let admitted = store
        .admit_available_download_job(
            &request(),
            DownloadAvailabilityAdmission {
                initial_peers: &Default::default(),
                cut: &cut,
                availability: LocalContentAvailability::ConfirmedAbsent,
                redownload: false,
                aich_root: None,
                root_epoch: (&epoch, 0),
            },
        )
        .unwrap();
    assert!(admitted.created);
    assert_eq!(
        store
            .connection()
            .unwrap()
            .pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))
            .unwrap(),
        5000
    );
    drop(writer);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn availability_queries_use_content_keysets_without_temp_sort_or_history_scan() {
    let store = MetadataStore::in_memory().unwrap();
    let conn = store.connection().unwrap();
    for sql in [LIBRARY_SQL, OUTPUT_SQL, PAYLOAD_SQL] {
        let details = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map(params![vec![0x51u8; 16], 700], |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            details
                .iter()
                .all(|line| !line.contains("SCAN ") && !line.contains("TEMP B-TREE")),
            "{details:?}"
        );
        assert!(
            details
                .iter()
                .any(|line| line.contains("local_file_instances_content_idx")
                    || line.contains("download_jobs_content_history_idx")),
            "{details:?}"
        );
    }
}

#[test]
fn initial_peers_are_atomic_for_stopped_jobs_and_duplicates_are_unchanged() {
    use crate::{
        DownloadIntent, MetadataDownloadInitialPeers, MetadataTransferFileNameObservation,
        MetadataTransferSource,
    };
    let store = MetadataStore::in_memory().unwrap();
    let epoch = std::sync::atomic::AtomicU64::new(0);
    let peers = MetadataDownloadInitialPeers {
        sources: vec![MetadataTransferSource {
            ip: "192.0.2.1".into(),
            tcp_port: 4662,
            user_hash: None,
            connect_options: None,
            file_comment: String::new(),
            file_rating: 0,
        }],
        observations: vec![MetadataTransferFileNameObservation {
            source_ip: Some("192.0.2.1".into()),
            source_tcp_port: Some(4662),
            user_hash: None,
            client_software: String::new(),
            origin: "ed2k".into(),
            server_endpoint: None,
            raw_name: "sample.bin".into(),
            normalized_name: "sample.bin".into(),
            observed_at_s: 1,
        }],
    };
    let mut input = request();
    input.intent = DownloadIntent::Stopped;
    // A failure in the final child write must roll back the entire admission.
    store.connection().unwrap().execute_batch("CREATE TRIGGER fail_initial_name BEFORE INSERT ON download_job_file_name_observations BEGIN SELECT RAISE(ABORT,'test child failure'); END;").unwrap();
    let admit = |cut: &crate::MetadataAvailabilityCut| {
        store.admit_available_download_job(
            &input,
            DownloadAvailabilityAdmission {
                cut,
                availability: LocalContentAvailability::ConfirmedAbsent,
                redownload: false,
                aich_root: None,
                initial_peers: &peers,
                root_epoch: (&epoch, 0),
            },
        )
    };
    assert!(admit(&store.capture_download_availability().unwrap()).is_err());
    for table in [
        "download_jobs",
        "download_job_sources",
        "download_job_file_name_observations",
        "known_files",
    ] {
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_initial_name")
        .unwrap();
    let job = admit(&store.capture_download_availability().unwrap())
        .unwrap()
        .job;
    assert_eq!(job.intent, DownloadIntent::Stopped);
    let rows = store.download_job_sources_after(job.token, 0, 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source.ip, "192.0.2.1");
    assert_eq!(rows[0].reported_file_names.len(), 1);
    let duplicate = admit(&store.capture_download_availability().unwrap()).unwrap();
    assert!(!duplicate.created);
    assert_eq!(duplicate.job, job);
    assert_eq!(
        store.download_job_sources_after(job.token, 0, 10).unwrap()[0]
            .reported_file_names
            .len(),
        1
    );
    // Initial admission authority must not authorize stopped network callbacks.
    assert!(
        store
            .apply_download_peer_delta(
                job.token,
                &crate::MetadataDownloadPeerDelta::Source {
                    source: peers.sources[0].clone(),
                    description_only: false,
                }
            )
            .is_err()
    );
}
