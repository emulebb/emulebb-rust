use super::*;
use crate::{MetadataIndexedFile, MetadataIndexedFileOrigin};

const HASH: &str = "11111111111111111111111111111111";

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
    let passive_demand = store
        .add_file_upload_request(&passive, 1_700_000_000)
        .unwrap()
        .unwrap();
    assert!(!passive_demand.known_client);
    let client_demand = store
        .add_file_upload_request(HASH, 1_700_000_001)
        .unwrap()
        .unwrap();
    assert!(client_demand.known_client);
    assert_eq!(client_demand.totals.upload_requests, 1);
    assert_eq!(
        client_demand.totals.last_requested_at_s,
        Some(1_700_000_001)
    );
    assert!(
        store
            .add_file_upload_request(&"33".repeat(16), 1_700_000_001)
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
