use crate::{
    DownloadIntent, DownloadJobRecord, DownloadJobRequest, JobToken, MetadataStore,
    MetadataTransferManifest, MetadataTransferPiece,
};
use rusqlite::params;

#[test]
fn sparse_presence_updates_the_scalar_total_without_double_counting_prefixes_or_rollback() {
    let store = MetadataStore::in_memory().unwrap();
    let size = 3 * 184_320 + 13;
    let job = job(&store, 0x48, Some(size), 9_728_000);
    let mut manifest = store
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    manifest.pieces = vec![piece(0, 0)];
    store.upsert_transfer_manifest(&manifest).unwrap();
    let mut sparse = piece(0, 0);
    sparse.block_bitmap = Some("02".into());
    sparse.present_bytes = 184_320;
    assert!(
        store
            .checkpoint_download_progress(job.token, &[sparse.clone()])
            .unwrap()
    );
    assert_eq!(record(&store, job.token).checkpointed_bytes, 184_320);
    sparse.block_bitmap = Some("04".into());
    assert!(
        store
            .checkpoint_download_progress(job.token, &[sparse.clone()])
            .unwrap()
    );
    assert_eq!(record(&store, job.token).checkpointed_bytes, 184_320);
    let mut invalid = sparse.clone();
    invalid.present_bytes = size + 1;
    assert!(
        store
            .checkpoint_download_progress(job.token, &[invalid])
            .is_err()
    );
    assert_eq!(record(&store, job.token).checkpointed_bytes, 184_320);
    assert_eq!(
        store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap()
            .pieces[0],
        sparse
    );
    assert!(
        store
            .checkpoint_download_progress(job.token, &[piece(0, 184_320)])
            .unwrap()
    );
    assert_eq!(record(&store, job.token).checkpointed_bytes, 184_320);
    let tail = MetadataTransferPiece {
        prefix_bytes: 0,
        present_bytes: 13,
        block_bitmap: Some("08".into()),
        ..piece(0, 0)
    };
    assert!(
        store
            .checkpoint_download_progress(job.token, &[tail])
            .unwrap()
    );
    assert_eq!(record(&store, job.token).checkpointed_bytes, 13);
}

fn job(store: &MetadataStore, hash: u8, size: Option<u64>, piece_size: u64) -> DownloadJobRecord {
    store
        .admit_download_job(&DownloadJobRequest {
            file_hash: hex::encode([hash; 16]),
            display_name: "checkpoint-sample.bin".into(),
            expected_size_bytes: size,
            category_id: None,
            intent: DownloadIntent::Started,
            piece_size,
        })
        .unwrap()
        .job
}
fn piece(index: u32, bytes: u64) -> MetadataTransferPiece {
    MetadataTransferPiece {
        piece_index: index,
        state: "Missing".into(),
        prefix_bytes: bytes,
        present_bytes: bytes,
        block_bitmap: None,
        ich_corrupted: false,
    }
}
fn record(store: &MetadataStore, token: JobToken) -> DownloadJobRecord {
    store.download_job(token.job_id).unwrap().unwrap()
}
fn seed(
    store: &MetadataStore,
    token: JobToken,
    pieces: Vec<MetadataTransferPiece>,
) -> MetadataTransferManifest {
    let mut manifest = store.download_job_manifest(token.job_id).unwrap().unwrap();
    manifest.pieces = pieces;
    store.upsert_transfer_manifest(&manifest).unwrap();
    manifest
}

#[test]
fn checkpoint_counter_is_atomic_for_batches_and_stale_generations() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 211, Some(48), 16);
    seed(&store, job.token, vec![piece(0, 0), piece(1, 0)]);
    assert!(
        store
            .checkpoint_download_progress(job.token, &[piece(0, 4), piece(1, 8)])
            .unwrap()
    );
    let before = record(&store, job.token);
    assert_eq!(before.checkpointed_bytes, 12);
    assert_eq!(before.progress(), Some(0.25));
    assert!(!before.payload_verified);
    // The first update runs before a missing final piece refuses the batch.
    assert!(
        !store
            .checkpoint_download_progress(job.token, &[piece(0, 9), piece(2, 0)])
            .unwrap()
    );
    assert_eq!(record(&store, job.token), before);
    // An invalid final extent also rolls the first update back.
    assert!(
        store
            .checkpoint_download_progress(job.token, &[piece(0, 9), piece(1, 17)])
            .is_err()
    );
    assert_eq!(record(&store, job.token), before);
    assert!(store.stop_download_job(job.token).unwrap());
    assert!(
        !store
            .checkpoint_download_progress(job.token, &[piece(0, 16)])
            .unwrap()
    );
    let stopped = record(&store, job.token);
    assert_eq!(stopped.checkpointed_bytes, 12);
    let mut stale = store
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    stale.token = job.token;
    stale.pieces[0].prefix_bytes = 16;
    stale.pieces[0].present_bytes = 16;
    assert!(store.upsert_transfer_manifest(&stale).is_err());
    assert_eq!(record(&store, job.token), stopped);
}

#[test]
fn snapshot_verification_corruption_salvage_and_repartition_maintain_counter() {
    let store = MetadataStore::in_memory().unwrap();
    let job = job(&store, 212, Some(32), 16);
    let mut manifest = seed(&store, job.token, vec![piece(0, 16), piece(1, 16)]);
    assert_eq!(record(&store, job.token).checkpointed_bytes, 32);
    manifest.pieces[0].state = "Verified".into();
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 32);
    // A corrupt part loses its byte claim; salvaged unverified bytes count again.
    manifest.pieces[0].state = "Missing".into();
    manifest.pieces[0].prefix_bytes = 0;
    manifest.pieces[0].present_bytes = 0;
    manifest.pieces[0].ich_corrupted = true;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 16);
    manifest.pieces[0].prefix_bytes = 4;
    manifest.pieces[0].present_bytes = 4;
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 20);
    // Changing full geometry must apply decreases/deletions before increases.
    manifest.piece_size = 32;
    manifest.pieces = vec![piece(0, 32)];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 32);
    manifest.piece_size = 16;
    manifest.pieces = vec![piece(0, 16), piece(1, 16)];
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 32);
    // A later child failure rolls back the entire snapshot and its counter.
    store.connection().unwrap().execute_batch("CREATE TEMP TRIGGER reject_hash BEFORE INSERT ON download_job_md4_part_hashes BEGIN SELECT RAISE(ABORT,'injected hash rejection'); END;").unwrap();
    let before = store
        .download_job_manifest(job.token.job_id)
        .unwrap()
        .unwrap();
    manifest.pieces = vec![piece(0, 3)];
    manifest.md4_hashset = vec!["11".repeat(16)];
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    assert_eq!(record(&store, job.token).checkpointed_bytes, 32);
    assert_eq!(
        store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap(),
        before
    );
    store
        .connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_hash;")
        .unwrap();
    manifest.md4_hashset.clear();
    manifest.pieces.clear();
    store.upsert_transfer_manifest(&manifest).unwrap();
    assert_eq!(record(&store, job.token).checkpointed_bytes, 0);
}

#[test]
fn counters_reopen_and_removed_piece_retirement_does_not_affect_new_attempt() {
    let root = std::env::temp_dir().join(format!("progress-counter-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let database = root.join("metadata.db");
    let store = MetadataStore::open(&database).unwrap();
    let first = job(&store, 213, Some(32), 16);
    seed(&store, first.token, vec![piece(0, 9), piece(1, 7)]);
    drop(store);
    let store = MetadataStore::open(&database).unwrap();
    assert_eq!(record(&store, first.token).checkpointed_bytes, 16);
    assert!(store.remove_download_job(first.token.job_id).unwrap());
    let next = job(&store, 213, Some(32), 16);
    seed(&store, next.token, vec![piece(0, 3)]);
    assert!(
        store
            .finalize_transfer_retirement(first.token.job_id)
            .unwrap()
    );
    assert_eq!(record(&store, first.token).checkpointed_bytes, 0);
    assert_eq!(record(&store, next.token).checkpointed_bytes, 3);
    assert!(store.delete_transfer_manifest(first.token.job_id).unwrap());
    assert_eq!(record(&store, next.token).checkpointed_bytes, 3);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn counter_arithmetic_rejects_negative_overflow_real_promotion_and_known_size_excess() {
    let store = MetadataStore::in_memory().unwrap();
    let unknown = job(&store, 214, None, 16);
    assert_eq!(unknown.progress(), None);
    assert_eq!(unknown.checkpointed_bytes, 0);
    let mut manifest = store
        .download_job_manifest(unknown.token.job_id)
        .unwrap()
        .unwrap();
    manifest.pieces = vec![piece(0, 1)];
    assert!(store.upsert_transfer_manifest(&manifest).is_err());
    let bounded = job(&store, 215, Some(16), 16);
    seed(&store, bounded.token, vec![piece(0, 16)]);
    {
        let conn = store.connection().unwrap();
        for bytes in [-1, 1] {
            assert!(conn.execute("INSERT INTO download_job_pieces(job_id,piece_index,state,prefix_bytes,present_bytes,updated_at_s) VALUES(?1,1,'Missing',?2,?2,0)", params![bounded.token.job_id,bytes]).is_err());
        }
        assert!(
            conn.execute(
                "UPDATE download_jobs SET expected_size_bytes=15 WHERE id=?1",
                [bounded.token.job_id]
            )
            .is_err()
        );
        // Raw current-schema numeric limits exercise the SQL arithmetic boundary
        // beyond the smaller executable ED2K geometry, without allocating payloads.
        conn.execute("INSERT INTO download_job_pieces(job_id,piece_index,state,prefix_bytes,present_bytes,updated_at_s) VALUES(?1,0,'Missing',9223372036854775807,9223372036854775807,0)", [unknown.token.job_id]).unwrap();
        assert!(conn.execute("INSERT INTO download_job_pieces(job_id,piece_index,state,prefix_bytes,present_bytes,updated_at_s) VALUES(?1,1,'Missing',1,1,0)", [unknown.token.job_id]).is_err());
        conn.execute("INSERT INTO download_job_pieces(job_id,piece_index,state,prefix_bytes,present_bytes,updated_at_s) VALUES(?1,1,'Missing',0,0,0)", [unknown.token.job_id]).unwrap();
        assert!(
            conn.execute(
                "UPDATE download_job_pieces SET prefix_bytes=1,present_bytes=1 WHERE job_id=?1 AND piece_index=1",
                [unknown.token.job_id]
            )
            .is_err()
        );
        let kind: String = conn
            .query_row(
                "SELECT typeof(checkpointed_bytes) FROM download_jobs WHERE id=?1",
                [unknown.token.job_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(kind, "integer");
    }
    let full = record(&store, unknown.token);
    assert_eq!(full.checkpointed_bytes, i64::MAX as u64);
    assert_eq!(full.progress(), None);
    assert_eq!(record(&store, bounded.token).checkpointed_bytes, 16);
    assert!(
        store
            .delete_transfer_manifest(unknown.token.job_id)
            .unwrap()
    );
    assert_eq!(record(&store, bounded.token).checkpointed_bytes, 16);
}

#[test]
fn maximum_geometry_compact_reads_do_not_load_children() {
    let store = MetadataStore::in_memory().unwrap();
    let size = 0x4000000000u64;
    let part_size = 9_728_000;
    let job = job(&store, 216, Some(size), part_size);
    let count = size.div_ceil(part_size);
    assert!(count <= 28_258);
    let pieces = (0..count)
        .map(|index| piece(index as u32, part_size.min(size - index * part_size)))
        .collect();
    seed(&store, job.token, pieces);
    // Any accidental child query fails, even a SUM that returns no geometry DTO.
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TEMP VIEW download_job_pieces AS SELECT * FROM forbidden_piece_read;",
        )
        .unwrap();
    assert!(store.download_job_manifest(job.token.job_id).is_err());
    let compact = record(&store, job.token);
    assert_eq!(compact.checkpointed_bytes, size);
    assert_eq!(compact.progress(), Some(1.0));
    assert!(
        !compact.payload_verified,
        "full byte presence is not verification"
    );
    assert_eq!(
        store.latest_download_job(&job.file_hash).unwrap(),
        Some(compact.clone())
    );
    assert_eq!(
        store.download_jobs_after(None, 256, false).unwrap(),
        vec![compact]
    );
}
