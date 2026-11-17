//! Selected-job geometry streaming. Source/name history has separate SQL readers.
use crate::{
    DownloadIntent, JobToken, MetadataStore, MetadataTransferDeliveryOwnership,
    MetadataTransferDeliveryState, MetadataTransferPiece, MetadataTransferRange,
    NativeFileFingerprint,
};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};

#[derive(Debug)]
pub struct MetadataDownloadExecutionHeader {
    pub token: JobToken,
    pub file_hash: String,
    pub display_name: String,
    pub file_size: u64,
    pub piece_size: u64,
    pub completed: bool,
    pub final_rehash_pending: bool,
    pub md4_hashset_acquired: bool,
    pub aich_hashset_acquired: bool,
    pub aich_root: Option<String>,
    pub aich_root_origin: Option<String>,
    pub aich_trust_generation: u64,
    pub upload_priority: String,
    pub auto_upload_priority: bool,
    pub comment: String,
    pub rating: u8,
    pub category_id: Option<i64>,
    pub intent: DownloadIntent,
    pub delivery_state: MetadataTransferDeliveryState,
    pub delivery_ownership: MetadataTransferDeliveryOwnership,
    pub delivered_path: Option<std::path::PathBuf>,
    pub source_fingerprint: Option<NativeFileFingerprint>,
    pub payload_fingerprint: Option<NativeFileFingerprint>,
}

/// Exact current-schema row counts; consumers reserve each vector once.
#[derive(Debug, Clone, Copy)]
pub struct MetadataDownloadGeometry {
    pub pieces: usize,
    pub md4_hashes: usize,
    pub aich_hashes: usize,
    pub ranges: usize,
}

#[derive(Debug)]
pub enum MetadataDownloadExecutionRow {
    Header(MetadataDownloadExecutionHeader, MetadataDownloadGeometry),
    Piece(MetadataTransferPiece),
    Md4([u8; 16]),
    Aich([u8; 20]),
    Range(MetadataTransferRange),
}

impl MetadataStore {
    /// Publish private execution backing only while its database observation
    /// still holds. The callback is synchronous and must not reenter the store
    /// or perform IO; callers acquire their cache/content guards beforehand.
    pub fn publish_observed_download_execution<T>(
        &self,
        token: JobToken,
        observed: &crate::MetadataAvailabilityCut,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let mut connection = self.connection()?;
        // WHY: an external writer must not commit between the observation
        // check and cache insertion. No payload IO occurs under this cut.
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        observed.check(self, &tx)?;
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2
             AND intent='started' AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL
             AND delete_requested_at_s IS NULL AND internal_storage_retired=0
             AND storage_failure_code IS NULL)",
            params![token.job_id, i64::try_from(token.generation)?],
            |row| row.get(0),
        )?;
        ensure!(active, crate::MetadataAvailabilityChanged);
        let result = publish()?;
        tx.commit()?;
        Ok(result)
    }

    /// Stream one selected execution under one coherent read transaction. The
    /// sink may only construct its owned result: no locks, I/O or store reentry.
    /// Each row is checked before emission; later validation can still fail.
    /// The sink must discard its private result unless the entire call succeeds.
    /// No source/filename history or second full geometry DTO is allocated.
    pub fn stream_download_execution(
        &self,
        token: JobToken,
        mut consume: impl FnMut(MetadataDownloadExecutionRow) -> Result<()>,
    ) -> Result<bool> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let bounded: Option<bool> = tx
            .query_row(
                "SELECT length(CAST(j.display_name AS BLOB))<=65536
                AND length(CAST(j.comment AS BLOB))<=65536
                AND length(CAST(j.upload_priority AS BLOB))<=65536
                AND coalesce(length(p.native_path),0)<=65536
                AND coalesce(length(j.source_fingerprint),0)<=1024
                AND coalesce(length(j.payload_fingerprint),0)<=1024
                AND coalesce(length(CAST(j.aich_root_origin AS BLOB)),0)<=64
             FROM download_jobs j LEFT JOIN local_paths p ON p.id=j.delivered_path_id
             WHERE j.id=?1 AND j.execution_generation=?2 AND j.removed_at_s IS NULL
               AND j.delete_requested_at_s IS NULL AND j.internal_storage_retired=0",
                params![token.job_id, i64::try_from(token.generation)?],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bounded) = bounded else {
            return Ok(false);
        };
        ensure!(bounded, "execution header exceeds representation allowance");
        let row = crate::transfer_store::read_transfer_row(&tx, token.job_id, false)?
            .ok_or_else(|| anyhow::anyhow!("execution vanished within snapshot"))?;
        let size = row
            .expected_size_bytes
            .ok_or_else(|| anyhow::anyhow!("unknown-size job has no executable geometry"))?;
        ensure!(
            size > 0 && size <= 0x4000000000 && row.piece_size > 0,
            "unsupported execution geometry"
        );
        let parts = size.div_ceil(row.piece_size);
        ensure!(
            parts <= 28_258,
            "execution part count exceeds supported geometry"
        );
        let counts: (usize, usize, usize, usize) = tx.query_row(
            "SELECT (SELECT count(*) FROM download_job_pieces WHERE job_id=?1),
                (SELECT count(*) FROM download_job_md4_part_hashes WHERE job_id=?1),
                (SELECT count(*) FROM download_job_aich_part_hashes WHERE job_id=?1),
                (SELECT count(*) FROM download_job_verified_ranges WHERE job_id=?1)",
            [token.job_id],
            |row| {
                Ok((
                    crate::sql_value::unsigned(row, 0)?,
                    crate::sql_value::unsigned(row, 1)?,
                    crate::sql_value::unsigned(row, 2)?,
                    crate::sql_value::unsigned(row, 3)?,
                ))
            },
        )?;
        ensure!(
            counts.0 <= parts as usize
                && counts.1 <= parts as usize + 1
                && counts.2 <= parts as usize
                && counts.3 <= parts as usize + 1,
            "execution child count exceeds geometry"
        );
        let part_size = row.piece_size;
        ensure!(
            !row.md4_hashset_acquired
                || u64::try_from(counts.1)?
                    == crate::download_hash_store::expected_md4_hashes(size, part_size),
            "acquired MD4 hashset differs from execution geometry"
        );
        ensure!(
            !row.aich_hashset_acquired
                || (row.aich_root.is_some()
                    && u64::try_from(counts.2)?
                        == crate::download_hash_store::expected_aich_hashes(size, part_size)),
            "acquired AICH hashset differs from execution geometry"
        );
        consume(MetadataDownloadExecutionRow::Header(
            MetadataDownloadExecutionHeader {
                token,
                file_hash: row.file_hash,
                display_name: row.display_name,
                file_size: size,
                piece_size: part_size,
                completed: row.completed,
                final_rehash_pending: row.final_rehash_pending,
                md4_hashset_acquired: row.md4_hashset_acquired,
                aich_hashset_acquired: row.aich_hashset_acquired,
                aich_root: row.aich_root,
                aich_root_origin: row.aich_root_origin,
                aich_trust_generation: row.aich_trust_generation,
                upload_priority: row.upload_priority,
                auto_upload_priority: row.auto_upload_priority,
                comment: row.comment,
                rating: row.rating,
                category_id: row.category_id,
                intent: DownloadIntent::parse(&row.intent)?,
                delivery_state: crate::transfer_store::delivery_state_from_sql(
                    &row.delivery_state,
                )?,
                delivery_ownership: crate::transfer_store::delivery_ownership_from_sql(
                    &row.delivery_ownership,
                )?,
                delivered_path: row.delivered_path,
                source_fingerprint: row.source_fingerprint,
                payload_fingerprint: row.payload_fingerprint,
            },
            MetadataDownloadGeometry {
                pieces: counts.0,
                md4_hashes: counts.1,
                aich_hashes: counts.2,
                ranges: counts.3,
            },
        ))?;
        let mut verified_pieces = 0usize;
        {
            let mut statement = tx.prepare_cached(
                "SELECT piece_index,state,bytes_written,block_bitmap,ich_corrupted
                FROM download_job_pieces WHERE job_id=?1 ORDER BY piece_index",
            )?;
            let mut rows = statement.query([token.job_id])?;
            while let Some(row) = rows.next()? {
                let index: u32 = row.get(0)?;
                ensure!(u64::from(index) < parts, "piece outside execution geometry");
                let state = row.get_ref(1)?.as_str()?;
                ensure!(
                    matches!(state, "Missing" | "Verified"),
                    "invalid execution piece state"
                );
                let bitmap = row.get_ref(3)?;
                if !matches!(bitmap, rusqlite::types::ValueRef::Null) {
                    let text = bitmap.as_str()?;
                    ensure!(
                        text.len() <= 14
                            && text.len().is_multiple_of(2)
                            && text.bytes().all(|byte| byte.is_ascii_hexdigit()),
                        "invalid execution bitmap"
                    );
                }
                let written: u64 = crate::sql_value::unsigned(row, 2)?;
                ensure!(
                    written <= part_size.min(size - u64::from(index) * part_size),
                    "piece exceeds payload extent"
                );
                if state == "Verified" {
                    ensure!(
                        written == part_size.min(size - u64::from(index) * part_size),
                        "verified piece is incomplete"
                    );
                    verified_pieces += 1;
                }
                consume(MetadataDownloadExecutionRow::Piece(MetadataTransferPiece {
                    piece_index: index,
                    state: state.to_owned(),
                    bytes_written: written,
                    block_bitmap: row.get(3)?,
                    ich_corrupted: row.get(4)?,
                }))?;
            }
        }
        for (sql, md4) in [
            (
                "SELECT part_index,md4_hash FROM download_job_md4_part_hashes WHERE job_id=?1 ORDER BY part_index",
                true,
            ),
            (
                "SELECT part_index,aich_hash FROM download_job_aich_part_hashes WHERE job_id=?1 ORDER BY part_index",
                false,
            ),
        ] {
            let mut statement = tx.prepare_cached(sql)?;
            let mut rows = statement.query([token.job_id])?;
            let mut expected_index = 0u64;
            while let Some(row) = rows.next()? {
                let index: u64 = crate::sql_value::unsigned(row, 0)?;
                ensure!(
                    index == expected_index,
                    "noncontiguous execution hash ordinal"
                );
                expected_index += 1;
                let bytes = row.get_ref(1)?.as_blob()?;
                consume(if md4 {
                    MetadataDownloadExecutionRow::Md4(bytes.try_into()?)
                } else {
                    MetadataDownloadExecutionRow::Aich(bytes.try_into()?)
                })?;
            }
        }
        {
            // Verified intervals are canonical whole-MD4-piece runs. AICH
            // block salvage is represented by each piece's bounded bitmap;
            // it does not grant partial-block upload authority.
            let mut statement = tx.prepare_cached("SELECT r.start_offset,r.end_offset,
                (SELECT count(*) FROM download_job_pieces p WHERE p.job_id=r.job_id
                 AND p.piece_index>=r.start_offset/?2 AND p.piece_index<(r.end_offset+?2-1)/?2
                 AND p.state='Verified')
                FROM download_job_verified_ranges r WHERE r.job_id=?1 ORDER BY r.start_offset,r.end_offset")?;
            let mut rows = statement.query(params![token.job_id, i64::try_from(part_size)?])?;
            let mut previous_end = None;
            let mut covered = 0usize;
            while let Some(row) = rows.next()? {
                let range = MetadataTransferRange {
                    start: crate::sql_value::unsigned(row, 0)?,
                    end: crate::sql_value::unsigned(row, 1)?,
                };
                ensure!(
                    range.start < range.end
                        && range.end <= size
                        && range.start.is_multiple_of(part_size)
                        && (range.end == size || range.end.is_multiple_of(part_size))
                        && previous_end.is_none_or(|end| end < range.start),
                    "noncanonical verified part range"
                );
                let expected =
                    usize::try_from(range.end.div_ceil(part_size) - range.start / part_size)?;
                let actual: usize = crate::sql_value::unsigned(row, 2)?;
                ensure!(
                    actual == expected,
                    "verified range contains an unverified or missing piece"
                );
                covered += actual;
                previous_end = Some(range.end);
                consume(MetadataDownloadExecutionRow::Range(range))?;
            }
            ensure!(
                covered == verified_pieces,
                "verified piece is missing its canonical range"
            );
        }
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn execution_with_hashes(
        size: u64,
        part_size: u64,
        md4: usize,
        aich: usize,
    ) -> (MetadataStore, JobToken) {
        let store = MetadataStore::in_memory().unwrap();
        let token = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "69".repeat(16),
                display_name: "hash-geometry.bin".into(),
                expected_size_bytes: Some(size),
                category_id: None,
                intent: DownloadIntent::Started,
                piece_size: part_size,
            })
            .unwrap()
            .job
            .token;
        {
            let connection = store.connection().unwrap();
            connection.execute("UPDATE download_jobs SET md4_hashset_acquired=1,aich_hashset_acquired=1,aich_root=?2,aich_root_origin='operator_link' WHERE id=?1",
                params![token.job_id, [1u8;20].as_slice()]).unwrap();
            for index in 0..md4 {
                connection.execute("INSERT INTO download_job_md4_part_hashes(job_id,part_index,md4_hash) VALUES(?1,?2,?3)",
                    params![token.job_id, i64::try_from(index).unwrap(), [2u8;16].as_slice()]).unwrap();
            }
            for index in 0..aich {
                connection.execute("INSERT INTO download_job_aich_part_hashes(job_id,part_index,aich_hash) VALUES(?1,?2,?3)",
                    params![token.job_id, i64::try_from(index).unwrap(), [3u8;20].as_slice()]).unwrap();
            }
        }
        (store, token)
    }

    // A consumer constructs privately and only returns/publishes after ALL
    // rows and the read transaction have succeeded, including late validation.
    fn build_private(
        store: &MetadataStore,
        token: JobToken,
        emitted: &mut usize,
    ) -> Result<Vec<MetadataDownloadExecutionRow>> {
        let mut result = Vec::new();
        ensure!(
            store.stream_download_execution(token, |row| {
                *emitted += 1;
                result.push(row);
                Ok(())
            })?,
            "execution missing"
        );
        Ok(result)
    }

    #[test]
    fn streaming_hash_geometry_handles_small_files_and_exact_part_multiples() {
        const PART: u64 = 9_728_000;
        for (size, md4, aich) in [
            (PART - 1, 0, 0),
            (PART, 2, 0),
            (PART + 1, 2, 2),
            (2 * PART, 3, 2),
            (2 * PART + 1, 3, 3),
        ] {
            let (store, token) = execution_with_hashes(size, PART, md4, aich);
            let rows = build_private(&store, token, &mut 0).unwrap();
            assert_eq!(
                rows.iter()
                    .filter(|row| matches!(row, MetadataDownloadExecutionRow::Md4(_)))
                    .count(),
                md4
            );
            assert_eq!(
                rows.iter()
                    .filter(|row| matches!(row, MetadataDownloadExecutionRow::Aich(_)))
                    .count(),
                aich
            );
        }
    }

    #[test]
    fn streaming_rejects_missing_acquired_hashes_before_emission() {
        for table in [
            "download_job_md4_part_hashes",
            "download_job_aich_part_hashes",
        ] {
            let (store, token) = execution_with_hashes(33, 16, 3, 3);
            store
                .connection()
                .unwrap()
                .execute(
                    &format!("DELETE FROM {table} WHERE job_id=?1 AND part_index=1"),
                    [token.job_id],
                )
                .unwrap();
            let mut emitted = 0;
            assert!(build_private(&store, token, &mut emitted).is_err());
            assert_eq!(emitted, 0, "count failure must precede builder allocation");
        }
    }

    #[test]
    fn streaming_rejects_gapped_hash_ordinals_and_discards_private_result() {
        for table in [
            "download_job_md4_part_hashes",
            "download_job_aich_part_hashes",
        ] {
            for acquired in [false, true] {
                let (store, token) = execution_with_hashes(33, 16, 3, 3);
                {
                    let connection = store.connection().unwrap();
                    connection
                        .execute(
                            &format!(
                                "UPDATE {table} SET part_index=3 WHERE job_id=?1 AND part_index=2"
                            ),
                            [token.job_id],
                        )
                        .unwrap();
                    connection.execute("UPDATE download_jobs SET md4_hashset_acquired=?2,aich_hashset_acquired=?2 WHERE id=?1", params![token.job_id, acquired]).unwrap();
                }
                let mut emitted = 0;
                let result = build_private(&store, token, &mut emitted);
                assert!(
                    emitted > 1,
                    "exercise a failure after private construction began"
                );
                assert!(result.is_err());
                assert!(
                    result.ok().is_none(),
                    "partial execution must never escape as a valid result"
                );
            }
        }
    }

    #[test]
    fn streaming_execution_rejects_block_ranges_and_requires_exact_verified_part_coverage() {
        let store = MetadataStore::in_memory().unwrap();
        let job = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "67".repeat(16),
                display_name: "canonical-parts.bin".into(),
                expected_size_bytes: Some(48),
                category_id: None,
                intent: DownloadIntent::Started,
                piece_size: 16,
            })
            .unwrap()
            .job;
        let mut manifest = store
            .download_job_manifest(job.token.job_id)
            .unwrap()
            .unwrap();
        manifest.pieces = (0..3)
            .map(|index| MetadataTransferPiece {
                piece_index: index,
                state: if index == 1 { "Missing" } else { "Verified" }.into(),
                bytes_written: if index == 1 { 0 } else { 16 },
                block_bitmap: None,
                ich_corrupted: false,
            })
            .collect();
        manifest.verified_ranges = vec![
            MetadataTransferRange { start: 0, end: 16 },
            MetadataTransferRange { start: 32, end: 48 },
        ];
        store.upsert_transfer_manifest(&manifest).unwrap();
        let mut ranges = 0;
        assert!(
            store
                .stream_download_execution(job.token, |row| {
                    if matches!(row, MetadataDownloadExecutionRow::Range(_)) {
                        ranges += 1
                    };
                    Ok(())
                })
                .unwrap()
        );
        assert_eq!(ranges, 2);
        store.connection().unwrap().execute("UPDATE download_job_verified_ranges SET end_offset=8 WHERE job_id=?1 AND start_offset=0",[job.token.job_id]).unwrap();
        assert!(
            store
                .stream_download_execution(job.token, |_| Ok(()))
                .is_err()
        );
        store
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM download_job_verified_ranges WHERE job_id=?1 AND start_offset=0",
                [job.token.job_id],
            )
            .unwrap();
        assert!(
            store
                .stream_download_execution(job.token, |_| Ok(()))
                .is_err()
        );
    }
    #[test]
    fn observed_execution_publication_rejects_changes_and_stopped_execution() {
        let (store, token) = execution_with_hashes(8, 9_728_000, 0, 0);
        let observed = store.capture_download_availability().unwrap();
        let mut published = false;
        store
            .publish_observed_download_execution(token, &observed, || {
                published = true;
                Ok(())
            })
            .unwrap();
        assert!(published);
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE download_jobs SET comment='changed' WHERE id=?1",
                [token.job_id],
            )
            .unwrap();
        published = false;
        assert!(
            store
                .publish_observed_download_execution(token, &observed, || {
                    published = true;
                    Ok(())
                })
                .unwrap_err()
                .is::<crate::MetadataAvailabilityChanged>()
        );
        assert!(!published);
        store.stop_download_job(token).unwrap();
        let stopped = store.download_job(token.job_id).unwrap().unwrap().token;
        let observed = store.capture_download_availability().unwrap();
        assert!(
            store
                .publish_observed_download_execution(stopped, &observed, || {
                    published = true;
                    Ok(())
                })
                .unwrap_err()
                .is::<crate::MetadataAvailabilityChanged>()
        );
        assert!(!published);
    }

    #[test]
    fn observed_execution_publication_fences_external_commits_through_callback() {
        let root =
            std::env::temp_dir().join(format!("execution-publication-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let database = root.join("metadata.sqlite");
        let store = MetadataStore::open(&database).unwrap();
        let token = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "73".repeat(16),
                display_name: "Sample.bin".into(),
                expected_size_bytes: Some(8),
                category_id: None,
                intent: DownloadIntent::Started,
                piece_size: 9_728_000,
            })
            .unwrap()
            .job
            .token;
        let writer = rusqlite::Connection::open(&database).unwrap();
        writer.busy_timeout(std::time::Duration::ZERO).unwrap();
        let observed = store.capture_download_availability().unwrap();
        store
            .publish_observed_download_execution(token, &observed, || {
                assert!(
                    writer
                        .execute(
                            "UPDATE download_jobs SET comment='external' WHERE id=?1",
                            [token.job_id]
                        )
                        .is_err()
                );
                Ok(())
            })
            .unwrap();
        writer
            .execute(
                "UPDATE download_jobs SET comment='external' WHERE id=?1",
                [token.job_id],
            )
            .unwrap();
        let mut published = false;
        assert!(
            store
                .publish_observed_download_execution(token, &observed, || {
                    published = true;
                    Ok(())
                })
                .unwrap_err()
                .is::<crate::MetadataAvailabilityChanged>()
        );
        assert!(!published);
        drop(writer);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
