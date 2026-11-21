use super::*;
use crate::{DownloadIntent, DownloadJobRequest};
use rusqlite::params;

const HASH: [u8; 16] = [0x71; 16];

fn job(store: &MetadataStore) -> crate::DownloadJobRecord {
    store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hex::encode(HASH),
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(12),
            category_id: None,
            intent: DownloadIntent::Stopped,
            piece_size: 8,
        })
        .unwrap()
        .job
}

#[test]
fn scalar_parts_count_only_complete_verified_ranges_including_short_final_part() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    for (ranges, expected) in [
        (vec![], 0),
        (vec![(8, 12)], 1),
        (vec![(0, 12)], 2),
        (vec![(0, 4), (4, 8)], 0),
        (vec![(1, 11)], 0),
        (vec![(0, 8)], 1),
        (vec![(0, 7), (8, 12)], 1),
    ] {
        {
            let conn = store.connection().unwrap();
            conn.execute(
                "DELETE FROM download_job_verified_ranges WHERE job_id=?1",
                [job.token.job_id],
            )
            .unwrap();
            for (start, end) in ranges {
                conn.execute("INSERT INTO download_job_verified_ranges(job_id,start_offset,end_offset,created_at_s) VALUES(?1,?2,?3,0)", params![job.token.job_id,start,end]).unwrap();
            }
        }
        let summary = store.upload_file_summary(&HASH).unwrap().unwrap();
        assert_eq!(summary.parts_total, 2);
        assert_eq!(summary.parts_obtained, expected);
        assert_eq!(summary.file_size, 12);
    }
}

#[test]
fn cached_local_content_precedes_job_name_without_paths_or_hashset_hydration() {
    let store = MetadataStore::in_memory().unwrap();
    assert!(store.upload_file_summary(&HASH).unwrap().is_none());
    let job = job(&store);
    assert_eq!(
        store
            .upload_file_summary(&HASH)
            .unwrap()
            .unwrap()
            .display_name,
        "Sample.bin"
    );
    store.connection().unwrap().execute(
        "UPDATE known_files SET size_bytes=12 WHERE id=(SELECT known_file_id FROM download_jobs WHERE id=?1)",
        [job.token.job_id],
    ).unwrap();
    store.connection().unwrap().execute(
        "INSERT INTO verified_local_content(known_file_id,display_name,part_size_bytes,part_count)
        SELECT known_file_id,'Cached.bin',8,2 FROM download_jobs WHERE id=?1", [job.token.job_id]
    ).unwrap();
    let summary = store.upload_file_summary(&HASH).unwrap().unwrap();
    assert_eq!(summary.display_name, "Cached.bin");
    assert_eq!(summary.parts_obtained, 2);
    assert_eq!(summary.parts_total, 2);
    assert!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
    let conn = store.connection().unwrap();
    let count: i64 = conn.query_row("SELECT (SELECT count(*) FROM local_file_instances)+(SELECT count(*) FROM verified_local_md4_hashes)+(SELECT count(*) FROM aich_recovery_sets)", [], |row| row.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn name_allowance_counts_utf8_bytes_and_never_truncates() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store);
    let name = "é".repeat(MAX_NAME_BYTES / 2);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![job.token.job_id, name],
        )
        .unwrap();
    assert_eq!(
        store
            .upload_file_summary(&HASH)
            .unwrap()
            .unwrap()
            .display_name,
        name
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![job.token.job_id, format!("{name}é")],
        )
        .unwrap();
    assert!(store.upload_file_summary(&HASH).is_err());
}

#[test]
fn caption_queries_seek_content_and_ranges_without_collection_scan_or_sort() {
    let store = MetadataStore::in_memory().unwrap();
    job(&store);
    let conn = store.connection().unwrap();
    for query in [COMPLETE_SQL, DOWNLOAD_SQL] {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap();
        let plan = statement
            .query_map([HASH.as_slice()], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.starts_with("SEARCH k ")),
            "{plan:?}"
        );
        assert!(
            !plan
                .iter()
                .any(|step| step.starts_with("SCAN ") || step.contains("USE TEMP")),
            "{plan:?}"
        );
    }
}
