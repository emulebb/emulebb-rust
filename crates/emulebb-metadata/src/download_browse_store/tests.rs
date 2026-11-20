use super::*;
use crate::{DownloadIntent, DownloadJobRequest, store::upsert_local_path};

#[test]
fn preparation_status_uses_only_verified_checkpoints_and_data_parts() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 91, Some(48), 16);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='started' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO download_job_pieces
        (job_id,piece_index,state,prefix_bytes,present_bytes,ich_corrupted,updated_at_s) VALUES
        (?1,0,'Missing',16,16,0,0),(?1,1,'Verified',16,16,0,0)",
            [job.token.job_id],
        )
        .unwrap();
    let parts = store
        .download_job_verified_parts(job.token)
        .unwrap()
        .unwrap();
    assert_eq!(parts.file_size_bytes, 48);
    assert_eq!(parts.verified_parts, [false, true, false]);
    assert!(
        store
            .download_job(job.token.job_id)
            .unwrap()
            .unwrap()
            .storage
            .is_none()
    );
    let stale = crate::JobToken {
        generation: job.token.generation + 1,
        ..job.token
    };
    assert!(store.download_job_verified_parts(stale).unwrap().is_none());
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
            .download_job_verified_parts(job.token)
            .unwrap()
            .is_none()
    );
}

#[test]
fn preparation_status_bounds_geometry_before_allocation_and_checks_verified_extents() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 92, Some(65534 * 16), 16);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='started' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    let parts = store
        .download_job_verified_parts(job.token)
        .unwrap()
        .unwrap();
    assert_eq!(parts.verified_parts.len(), 65534);
    assert!(parts.verified_parts.iter().all(|verified| !verified));
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET expected_size_bytes=?2 WHERE id=?1",
            params![job.token.job_id, 65535 * 16],
        )
        .unwrap();
    assert!(store.download_job_verified_parts(job.token).is_err());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET expected_size_bytes=15 WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO download_job_pieces
        (job_id,piece_index,state,prefix_bytes,present_bytes,ich_corrupted,updated_at_s)
        VALUES(?1,0,'Verified',14,14,0,0)",
            [job.token.job_id],
        )
        .unwrap();
    assert!(store.download_job_verified_parts(job.token).is_err());
}

#[test]
fn preparation_status_requires_runnable_known_size_and_healthy_internal_storage() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 93, None, 16);
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET intent='started' WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_job_verified_parts(job.token)
            .unwrap()
            .is_none()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET expected_size_bytes=17 WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert_eq!(
        store
            .download_job_verified_parts(job.token)
            .unwrap()
            .unwrap()
            .verified_parts,
        [false, false]
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET internal_storage_retired=1,removed_at_s=4 WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_job_verified_parts(job.token)
            .unwrap()
            .is_none()
    );
}

fn job(store: &MetadataStore, byte: u8, size: Option<u64>, part_size: u64) -> DownloadJobRecord {
    store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hex::encode([byte; 16]),
            display_name: "Sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent: DownloadIntent::Stopped,
            piece_size: part_size,
        })
        .unwrap()
        .job
}

fn complete_unowned(store: &MetadataStore, id: JobId) -> PathBuf {
    let path = std::env::temp_dir().join("recorded-output-not-probed.bin");
    let mut conn = store.connection().unwrap();
    let tx = conn.transaction().unwrap();
    let path_id = upsert_local_path(&tx, &path).unwrap();
    tx.execute(
        "UPDATE download_jobs SET completed=1,visible_state='completed',
        delivery_state='delivered',delivery_ownership='unowned',delivered_path_id=?2,
        completed_at_s=3,terminal_completed_at_s=3,internal_storage_retired=1 WHERE id=?1",
        params![id, path_id],
    )
    .unwrap();
    tx.commit().unwrap();
    path
}

#[test]
fn detail_reads_recorded_output_without_granting_ownership_or_hydrating_parts() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 1, Some(38), 16);
    let initial = store
        .download_job_detail(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(initial.job.token, job.token);
    assert_eq!(initial.ownership, MetadataTransferDeliveryOwnership::None);
    assert!(initial.delivered_path.is_none() && initial.job.storage.is_none());
    let output = complete_unowned(&store, job.token.job_id);
    let completed = store
        .download_job_detail(job.token.job_id)
        .unwrap()
        .unwrap();
    assert_eq!(completed.delivered_path, Some(output));
    assert_eq!(
        completed.ownership,
        MetadataTransferDeliveryOwnership::Unowned
    );
    assert_eq!(completed.job.completed_at_s, Some(3));
    assert!(completed.job.storage.is_none());
    assert!(
        store
            .download_job_parts_after(job.token.job_id, None, 200)
            .unwrap()
            .unwrap()
            .parts
            .is_empty()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET removed_at_s=4 WHERE id=?1",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_job_detail(job.token.job_id)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .download_job_parts_after(job.token.job_id, None, 200)
            .unwrap()
            .is_none()
    );
}

#[test]
fn part_pages_distinguish_presence_and_verification_and_use_inclusive_offsets() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 2, Some(38), 16);
    store
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO download_job_pieces
        (job_id,piece_index,state,prefix_bytes,present_bytes,ich_corrupted,updated_at_s) VALUES
        (?1,0,'Missing',16,16,0,0),(?1,1,'Verified',16,16,0,0),(?1,2,'Missing',2,2,1,0)",
            [job.token.job_id],
        )
        .unwrap();
    let first = store
        .download_job_parts_after(job.token.job_id, None, 2)
        .unwrap()
        .unwrap();
    assert_eq!(first.parts.len(), 2);
    assert_eq!(
        (
            first.parts[0].start,
            first.parts[0].end,
            first.parts[0].present_bytes
        ),
        (0, 15, 16)
    );
    assert!(!first.parts[0].complete);
    assert!(first.parts[1].complete);
    assert!(first.has_more);
    assert_eq!(first.next_after, Some(1));
    let last = store
        .download_job_parts_after(job.token.job_id, first.next_after, 2)
        .unwrap()
        .unwrap();
    assert_eq!(last.parts.len(), 1);
    assert_eq!(
        (
            last.parts[0].start,
            last.parts[0].end,
            last.parts[0].size_bytes,
            last.parts[0].present_bytes
        ),
        (32, 37, 6, 2)
    );
    assert!(last.parts[0].corrupted && !last.parts[0].complete);
    assert!(!last.has_more && last.next_after.is_none());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_job_pieces SET state='Verified' WHERE job_id=?1 AND piece_index=2",
            [job.token.job_id],
        )
        .unwrap();
    assert!(
        store
            .download_job_parts_after(job.token.job_id, Some(1), 1)
            .is_err()
    );
}

#[test]
fn large_unallocated_geometry_seeks_only_the_requested_window() {
    let store = MetadataStore::in_memory().unwrap();
    let size: u64 = 0x4000000000;
    let part_size = 9_728_000;
    let job = job(&store, 3, Some(size), part_size);
    let count = size.div_ceil(part_size);
    let first = store
        .download_job_parts_after(job.token.job_id, None, 200)
        .unwrap()
        .unwrap();
    assert_eq!(first.parts.len(), 200);
    assert_eq!(first.next_after, Some(199));
    assert!(
        first
            .parts
            .iter()
            .all(|part| part.present_bytes == 0 && !part.complete)
    );
    let last = store
        .download_job_parts_after(job.token.job_id, Some((count - 2) as u32), 200)
        .unwrap()
        .unwrap();
    assert_eq!(last.parts.len(), 1);
    assert_eq!(last.parts[0].end, size - 1);
    assert!(!last.has_more);
    assert!(
        store
            .download_job_parts_after(job.token.job_id, Some(u32::MAX), 200)
            .unwrap()
            .unwrap()
            .parts
            .is_empty()
    );
    assert!(
        store
            .download_job_parts_after(job.token.job_id, None, 0)
            .is_err()
    );
    let conn = store.connection().unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM download_job_pieces", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {PARTS_SQL}"))
        .unwrap();
    let plan = stmt
        .query_map(
            params![
                job.token.job_id,
                i64::try_from(count - 1).unwrap(),
                i64::try_from(count).unwrap()
            ],
            |row| row.get::<_, String>(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
        .join("\n");
    assert!(
        plan.contains("PRIMARY KEY") && !plan.contains("TEMP B-TREE"),
        "{plan}"
    );
}

#[test]
fn unknown_geometry_and_missing_jobs_are_distinct_and_detail_bounds_apply() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 4, None, 16);
    let page = store
        .download_job_parts_after(job.token.job_id, None, 200)
        .unwrap()
        .unwrap();
    assert!(page.parts.is_empty() && !page.has_more && page.next_after.is_none());
    assert!(
        store
            .download_job_parts_after(JobId::new(999).unwrap(), None, 200)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .download_job_detail(JobId::new(999).unwrap())
            .unwrap()
            .is_none()
    );
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE download_jobs SET display_name=?2 WHERE id=?1",
            params![job.token.job_id, "n".repeat(65_537)],
        )
        .unwrap();
    assert!(store.download_job_detail(job.token.job_id).is_err());
}
