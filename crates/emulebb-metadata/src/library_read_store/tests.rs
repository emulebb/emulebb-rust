use super::*;
use crate::{MetadataIndexedFile, MetadataIndexedFileOrigin};

const HASH: &str = "11111111111111111111111111111111";

fn job_request(byte: u8) -> crate::DownloadJobRequest {
    crate::DownloadJobRequest {
        file_hash: hex::encode([byte; 16]),
        display_name: "Pending.bin".into(),
        expected_size_bytes: Some(32),
        category_id: None,
        intent: crate::DownloadIntent::Stopped,
        piece_size: 1024,
    }
}

#[test]
fn accepted_unfinished_identity_survives_its_final_job_without_authorizing_payloads() {
    let store = MetadataStore::in_memory().unwrap();
    let request = job_request(0x44);
    let job = store.admit_download_job(&request).unwrap().job;
    let hash = &request.file_hash;
    assert!(
        store
            .file_upload_snapshot(hash)
            .unwrap()
            .unwrap()
            .known_client
    );
    assert!(
        store
            .library_locations(hash, 0, 2, LIBRARY_READ_MAX_BYTES)
            .unwrap()
            .unwrap()
            .locations
            .is_empty()
    );
    assert_eq!(
        store.try_verified_share_batch(&[[0x44; 16]]).unwrap(),
        Some(vec![(false, None)])
    );
    store.create_library_tag("Group-1").unwrap();
    store.set_library_file_tag(hash, "Group-1", true).unwrap();
    assert_eq!(
        store.set_library_sharing_enabled(hash, false).unwrap(),
        Some(true)
    );
    store.remove_download_job(job.token.job_id).unwrap();
    let cleanup = store
        .removed_download_cleanup_snapshot(job.token.job_id)
        .unwrap()
        .unwrap();
    assert!(
        store
            .finalize_transfer_retirement(job.token.job_id)
            .unwrap()
    );
    assert!(store.finalize_removed_download_job(cleanup.token).unwrap());
    assert!(store.download_job(job.token.job_id).unwrap().is_none());
    assert!(
        store
            .file_upload_snapshot(hash)
            .unwrap()
            .unwrap()
            .known_client
    );
    assert_eq!(store.library_sharing_enabled(hash).unwrap(), Some(false));
    let tags = store
        .library_file_tags_page(hash, None, 2)
        .unwrap()
        .unwrap();
    assert_eq!(tags.tags[0].name, "Group-1");
    assert!(
        store
            .library_locations(hash, 0, 2, LIBRARY_READ_MAX_BYTES)
            .unwrap()
            .unwrap()
            .locations
            .is_empty()
    );
    assert_eq!(
        store.try_verified_share_batch(&[[0x44; 16]]).unwrap(),
        Some(vec![(false, None)])
    );
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT size_bytes FROM known_files WHERE ed2k_hash=?1",
                [[0x44u8; 16].as_slice()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .unwrap(),
        None,
        "a job's size claim does not establish accepted content identity"
    );
}

#[test]
fn passive_knowledge_requires_client_acceptance_before_library_policy_and_session_statistics() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = "55".repeat(16);
    let file = MetadataIndexedFile {
        ed2k_hash: hash.clone(),
        name: "Sample.bin".into(),
        size_bytes: 32,
        content_type: String::new(),
        availability_score: 0,
    };
    store
        .upsert_indexed_file(&file, MetadataIndexedFileOrigin::PassiveCache)
        .unwrap();
    store.create_library_tag("Group-1").unwrap();
    assert!(
        store
            .library_file_tags_page(&hash, None, 2)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.set_library_sharing_enabled(&hash, false).unwrap(),
        None
    );
    assert_eq!(
        store
            .set_library_file_tag(&hash, "Group-1", true)
            .unwrap_err()
            .downcast_ref::<crate::LibraryTagError>(),
        Some(&crate::LibraryTagError::UnknownFile)
    );
    assert!(store.connection().unwrap().execute(
        "INSERT INTO known_file_tags SELECT k.id,t.id FROM known_files k CROSS JOIN library_tags t", [],
    ).is_err(), "the database must enforce the same library domain");
    let demand = crate::MetadataFileUploadDelta {
        file_hash: hash.clone(),
        upload_requests: 1,
        last_requested_at_s: Some(0),
        ..Default::default()
    };
    store
        .apply_credit_deltas(&[], std::slice::from_ref(&demand))
        .unwrap();
    let passive = store.file_upload_statistics(&hash).unwrap().unwrap();
    assert_eq!(passive.lifetime.upload_requests, 1);
    assert_eq!(passive.session_upload_requests, 0);
    store
        .upsert_indexed_file(&file, MetadataIndexedFileOrigin::LocalShare)
        .unwrap();
    store.set_library_file_tag(&hash, "Group-1", true).unwrap();
    store.apply_credit_deltas(&[], &[demand]).unwrap();
    let client = store.file_upload_statistics(&hash).unwrap().unwrap();
    assert_eq!(client.lifetime.upload_requests, 2);
    assert_eq!(client.session_upload_requests, 1);
    store
        .connection()
        .unwrap()
        .execute("DELETE FROM known_file_origins", [])
        .unwrap();
    assert!(
        store
            .file_upload_snapshot(&hash)
            .unwrap()
            .unwrap()
            .known_client
    );
    assert_eq!(
        store
            .library_file_tags_page(&hash, None, 2)
            .unwrap()
            .unwrap()
            .tags
            .len(),
        1
    );
}

#[test]
fn failed_client_acceptance_cannot_leave_library_identity_or_a_job() {
    let store = MetadataStore::in_memory().unwrap();
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_client_acceptance BEFORE INSERT ON library_files
         BEGIN SELECT RAISE(ABORT,'injected client acceptance failure'); END;",
        )
        .unwrap();
    let request = job_request(0x66);
    assert!(store.admit_download_job(&request).is_err());
    assert!(
        store
            .file_upload_snapshot(&request.file_hash)
            .unwrap()
            .is_none()
    );
    let conn = store.connection().unwrap();
    for table in ["library_files", "download_jobs"] {
        assert_eq!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

// These cached observations intentionally name nonexistent paths: reads must
// return evidence without inspecting the filesystem or authorizing payloads.
fn fixture() -> (MetadataStore, Vec<i64>) {
    let store = MetadataStore::in_memory().unwrap();
    let mut conn = store.connection().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute_batch("INSERT INTO known_files(id,ed2k_hash,size_bytes,display_name,first_seen_at_ms,last_seen_at_ms,updated_at_ms)
        VALUES(1,x'11111111111111111111111111111111',32,'Sample.bin',0,0,0);
        INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
        VALUES(1,'Sample.bin',9728000,0);").unwrap();
    let root = std::env::temp_dir().join(format!("library-locations-{}", uuid::Uuid::new_v4()));
    let root_id = crate::store::upsert_local_path(&tx, &root).unwrap();
    tx.execute(
        "INSERT INTO shared_directory_roots(id,path_id,created_at_ms) VALUES(1,?1,0)",
        [root_id],
    )
    .unwrap();
    let mut paths = Vec::new();
    for n in 1..=3 {
        let id = crate::store::upsert_local_path(&tx, &root.join(format!("Copy-{n}.bin"))).unwrap();
        tx.execute("INSERT INTO local_file_instances(path_id,known_file_id,size_bytes,native_identity,verified_fingerprint,verified_at_ms)
            VALUES(?1,1,32,x'01',x'02',0)", [id]).unwrap();
        tx.execute(
            "INSERT INTO shared_file_memberships VALUES(1,?1,1,'Sample.bin',0,0,NULL)",
            [id],
        )
        .unwrap();
        paths.push(id);
    }
    tx.execute(
        "INSERT INTO temp.session_verified_local_paths VALUES(?1,x'02')",
        [paths[0]],
    )
    .unwrap();
    tx.commit().unwrap();
    drop(conn);
    (store, paths)
}

#[test]
fn location_pages_are_cached_keysets_and_survive_root_withdrawal() {
    let (store, paths) = fixture();
    let first = store
        .library_locations(HASH, 0, 2, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(
        first
            .locations
            .iter()
            .map(|p| p.path_id)
            .collect::<Vec<_>>(),
        paths[..2]
    );
    assert!(first.locations[0].verified_in_session);
    assert!(!first.locations[1].verified_in_session);
    assert!(
        first
            .locations
            .iter()
            .all(|p| p.root_configured && p.root_accessible && !p.identity_excluded)
    );
    let next = store
        .library_locations(HASH, first.next_after.unwrap(), 2, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(next.locations[0].path_id, paths[2]);
    assert!(next.next_after.is_none());
    store
        .connection()
        .unwrap()
        .execute("UPDATE shared_directory_roots SET accessible=0", [])
        .unwrap();
    let offline = store
        .library_locations(HASH, 0, 2, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert!(
        offline
            .locations
            .iter()
            .all(|p| p.root_configured && !p.root_accessible)
    );
    store
        .connection()
        .unwrap()
        .execute("UPDATE shared_directory_roots SET enabled=0", [])
        .unwrap();
    let withdrawn = store
        .library_locations(HASH, 0, 2, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(withdrawn.locations.len(), 2);
    assert!(
        withdrawn
            .locations
            .iter()
            .all(|p| !p.root_configured && !p.root_accessible)
    );
}

#[test]
fn unknown_and_passive_observations_differ_from_copyless_library_content() {
    let (mut store, _) = fixture();
    let passive = "22".repeat(16);
    store
        .upsert_indexed_file(
            &MetadataIndexedFile {
                ed2k_hash: passive.clone(),
                name: "Remote.bin".into(),
                size_bytes: 32,
                content_type: String::new(),
                availability_score: 0,
            },
            MetadataIndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    let passive_demand = store.file_upload_snapshot(&passive).unwrap().unwrap();
    assert!(!passive_demand.known_client);
    let client_demand = store.file_upload_snapshot(HASH).unwrap().unwrap();
    assert!(client_demand.known_client);
    assert_eq!(client_demand.totals.upload_requests, 0);
    assert_eq!(client_demand.totals.last_requested_at_s, None);
    assert!(
        store
            .file_upload_snapshot(&"33".repeat(16))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .library_locations(&passive, 0, 2, LIBRARY_READ_MAX_BYTES)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .library_locations(&"33".repeat(16), 0, 2, LIBRARY_READ_MAX_BYTES)
            .unwrap()
            .is_none()
    );
    store
        .connection()
        .unwrap()
        .execute("DELETE FROM local_file_instances", [])
        .unwrap();
    let retained = store
        .library_locations(HASH, 0, 2, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert!(retained.locations.is_empty());
    assert!(retained.next_after.is_none());
}

#[test]
fn byte_limited_pages_resume_without_skipping_the_next_location() {
    let (store, paths) = fixture();
    assert!(store.library_locations(HASH, 0, 2, 1).is_err());
    let budget = store
        .library_locations(HASH, 0, 1, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap()
        .resident_bytes;
    let first = store
        .library_locations(HASH, 0, 200, budget)
        .unwrap()
        .unwrap();
    assert_eq!(first.locations.len(), 1);
    assert!(first.resident_bytes <= budget);
    let next = store
        .library_locations(HASH, first.next_after.unwrap(), 200, budget)
        .unwrap()
        .unwrap();
    assert_eq!(next.locations[0].path_id, paths[1]);
    for (after, limit, bytes) in [
        (-1, 1, 4096),
        (0, 0, 4096),
        (0, 201, 4096),
        (0, 1, 0),
        (0, 1, LIBRARY_READ_MAX_BYTES + 1),
    ] {
        assert!(store.library_locations(HASH, after, limit, bytes).is_err());
    }
}

#[test]
fn oversized_native_paths_fail_before_decode_without_hiding_later_copies() {
    let (store, paths) = fixture();
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE local_paths SET native_path=zeroblob(65538) WHERE id=?1",
            [paths[1]],
        )
        .unwrap();
    let first = store
        .library_locations(HASH, 0, 1, LIBRARY_READ_MAX_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(first.next_after, Some(paths[0]));
    assert!(
        store
            .library_locations(HASH, paths[0], 1, LIBRARY_READ_MAX_BYTES)
            .is_err()
    );
}
