//! Compact verified internal payload candidates, distinct from local root copies.
use crate::{
    DownloadJobStorage, JobId, JobToken, MetadataStore, MetadataTransferCatalogEntry,
    MetadataTransferMediaMetadata, NativeFileFingerprint, NativeFileIdentity,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};

// A sole visible unfinished attempt can own an independently verified payload.
// Terminal history and any accepted retirement never reopen internal serving.
pub(crate) const ELIGIBLE: &str = "j.completed=1 AND j.final_rehash_pending=0
    AND j.md4_hashset_acquired=1 AND j.payload_fingerprint IS NOT NULL
    AND j.storage_path_id IS NOT NULL AND j.storage_directory_identity IS NOT NULL
    AND j.expected_size_bytes>0 AND j.expected_size_bytes<=274877906944
    AND j.part_size_bytes>0 AND j.part_count>0
    AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL
    AND j.delete_requested_at_s IS NULL AND j.internal_storage_retired=0
    AND NOT EXISTS(SELECT 1 FROM download_retirements r WHERE r.job_id=j.id)";
const IDS: &str = "SELECT id FROM download_jobs INDEXED BY download_jobs_visible_page_idx
    WHERE removed_at_s IS NULL AND id>?1 ORDER BY id LIMIT ?2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDownloadPayload {
    pub token: JobToken,
    pub storage: DownloadJobStorage,
    pub fingerprint: NativeFileFingerprint,
    pub catalog: MetadataTransferCatalogEntry,
}
#[derive(Debug)]
pub struct MetadataDownloadPayloadPage {
    pub entries: Vec<MetadataDownloadPayload>,
    /// Last examined ID, including ineligible rows. An empty page may advance.
    pub cursor: Option<JobId>,
}

enum PayloadRead {
    Ineligible,
    Full,
    Value(Box<MetadataDownloadPayload>),
}
fn read(conn: &Connection, id: JobId, allowance: usize) -> Result<PayloadRead> {
    let sql = format!("SELECT j.execution_generation,lower(hex(k.ed2k_hash)),j.display_name,
        j.expected_size_bytes,j.part_size_bytes,j.part_count,lower(hex(j.aich_root)),
        j.upload_priority,j.auto_upload_priority,j.comment,j.rating,
        p.platform,p.native_path,j.storage_directory_marker_id,j.storage_directory_identity,j.payload_fingerprint,
        k.all_time_uploaded_bytes,k.all_time_upload_requests,k.all_time_upload_accepts,k.last_upload_requested_at_s,
        k.media_artist,k.media_album,k.media_title,k.media_length_seconds,k.media_bitrate_kbps,k.media_codec,k.media_extractor_version
        FROM download_jobs j JOIN known_files k ON k.id=j.known_file_id JOIN local_paths p ON p.id=j.storage_path_id
        WHERE j.id=?1 AND {ELIGIBLE}");
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query([id])?;
    let Some(row) = rows.next()? else {
        return Ok(PayloadRead::Ineligible);
    };
    for column in [2, 7, 9, 20, 21, 22, 25] {
        ensure!(
            row.get_ref(column)?.as_str()?.len() <= 65_536,
            "payload catalog text exceeds bound"
        );
    }
    ensure!(
        row.get_ref(12)?.as_blob()?.len() <= 65_536,
        "payload storage path exceeds bound"
    );
    let marker_id = crate::download_job_store::bounded_uuid_from_row(row, 13)?;
    ensure!(
        row.get_ref(14)?.as_blob()?.len() <= 64 && row.get_ref(15)?.as_blob()?.len() <= 1024,
        "payload identity exceeds bound"
    );
    // Include native decoding and the later joined/canonical payload path.
    let mut charge = 4096 + row.get_ref(12)?.as_blob()?.len() * 8;
    for column in [2, 7, 9, 20, 21, 22, 25] {
        charge += row.get_ref(column)?.as_str()?.len() * 2;
    }
    if charge > allowance {
        return Ok(PayloadRead::Full);
    }
    let size = crate::sql_value::unsigned::<u64>(row, 3)?;
    let part_size = crate::sql_value::unsigned::<u64>(row, 4)?;
    let parts = crate::sql_value::unsigned::<u32>(row, 5)?;
    ensure!(
        u64::from(parts) == size.div_ceil(part_size) && parts <= 28_258,
        "invalid verified payload geometry"
    );
    let fingerprint = NativeFileFingerprint::from_storage_bytes(row.get_ref(15)?.as_blob()?)
        .context("invalid payload fingerprint")?;
    ensure!(
        fingerprint.size_bytes == size,
        "payload fingerprint size differs from verified geometry"
    );
    let path = crate::native_path::path_from_row(row, 11, 12)?;
    let root: String = row.get(6)?;
    Ok(PayloadRead::Value(Box::new(MetadataDownloadPayload {
        token: JobToken {
            job_id: id,
            generation: crate::sql_value::unsigned(row, 0)?,
        },
        storage: DownloadJobStorage {
            path,
            marker_id,
            identity: Some(
                NativeFileIdentity::from_storage_bytes(row.get_ref(14)?.as_blob()?)
                    .context("invalid payload directory identity")?,
            ),
        },
        fingerprint,
        catalog: MetadataTransferCatalogEntry {
            file_hash: row.get(1)?,
            display_name: row.get(2)?,
            file_size: size,
            part_count: parts,
            aich_root: (!root.is_empty()).then_some(root),
            upload_priority: row.get(7)?,
            auto_upload_priority: row.get(8)?,
            comment: row.get(9)?,
            rating: row.get(10)?,
            all_time_uploaded_bytes: crate::sql_value::unsigned(row, 16)?,
            all_time_upload_requests: crate::sql_value::unsigned(row, 17)?,
            all_time_upload_accepts: crate::sql_value::unsigned(row, 18)?,
            last_upload_requested_at_s: row.get(19)?,
            media_path: None,
            media: MetadataTransferMediaMetadata {
                artist: row.get(20)?,
                album: row.get(21)?,
                title: row.get(22)?,
                length_seconds: row.get(23)?,
                bitrate_kbps: row.get(24)?,
                codec: row.get(25)?,
                extractor_version: row.get(26)?,
            },
        },
    })))
}
impl MetadataStore {
    /// At most `limit` indexed visible IDs are examined, even when all are
    /// history/ineligible. No full manifest, piece map or source list is read.
    pub fn download_payloads_after(
        &self,
        after: Option<JobId>,
        limit: usize,
    ) -> Result<MetadataDownloadPayloadPage> {
        ensure!((1..=256).contains(&limit), "invalid payload page size");
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let mut ids = tx.prepare_cached(IDS)?;
        let mut rows = ids.query(params![after.map_or(0, JobId::get), i64::try_from(limit)?])?;
        let mut entries = Vec::with_capacity(limit);
        let mut bytes = entries.capacity() * std::mem::size_of::<MetadataDownloadPayload>();
        let mut cursor = None;
        while let Some(row) = rows.next()? {
            let id = row.get::<_, JobId>(0)?;
            match read(&tx, id, crate::download_job_store::JOB_PAGE_BYTES - bytes)? {
                PayloadRead::Ineligible => {}
                PayloadRead::Full => {
                    ensure!(!entries.is_empty(), "payload row exceeds page allowance");
                    break;
                }
                PayloadRead::Value(value) => {
                    let c = &value.catalog;
                    bytes += 4096
                        + value.storage.path.as_os_str().len() * 4
                        + [
                            c.display_name.capacity(),
                            c.upload_priority.capacity(),
                            c.comment.capacity(),
                            c.media.artist.capacity(),
                            c.media.album.capacity(),
                            c.media.title.capacity(),
                            c.media.codec.capacity(),
                        ]
                        .into_iter()
                        .sum::<usize>()
                            * 2;
                    ensure!(
                        bytes <= crate::download_job_store::JOB_PAGE_BYTES,
                        "decoded payload row exceeds allowance"
                    );
                    entries.push(*value);
                }
            }
            cursor = Some(id);
        }
        drop(rows);
        drop(ids);
        tx.commit()?;
        Ok(MetadataDownloadPayloadPage { entries, cursor })
    }
    /// Recheck the captured token and snapshot after filesystem probing. This
    /// never resolves a hash to a different attempt or refreshes its generation.
    pub fn download_payload_is_current(&self, expected: &MetadataDownloadPayload) -> Result<bool> {
        let conn = self.connection()?;
        Ok(
            matches!(read(&conn,expected.token.job_id,crate::download_job_store::JOB_PAGE_BYTES)?, PayloadRead::Value(current) if *current==*expected),
        )
    }
    /// Resolve the sole unfinished job only at content-serving admission. The
    /// returned token must remain captured through all following I/O and checks.
    pub fn download_payload_candidate(
        &self,
        hash: &str,
    ) -> Result<Option<MetadataDownloadPayload>> {
        let raw = crate::store::decode_fixed_hex(hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let id = conn
            .query_row(
                "SELECT j.id FROM known_files k JOIN download_jobs j
            INDEXED BY download_jobs_unremoved_unfinished_content_idx ON j.known_file_id=k.id
            WHERE k.ed2k_hash=?1 AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL",
                [raw],
                |r| r.get::<_, JobId>(0),
            )
            .optional()?;
        match id
            .map(|id| read(&conn, id, crate::download_job_store::JOB_PAGE_BYTES))
            .transpose()?
        {
            Some(PayloadRead::Value(value)) => Ok(Some(*value)),
            Some(PayloadRead::Full) => anyhow::bail!("payload row exceeds allowance"),
            _ => Ok(None),
        }
    }
    /// Physical probing and canonicalizing the parent occur outside SQLite.
    /// This final cut rechecks captured authority and both actual native IDs;
    /// identity evidence is exclusion evidence, never destructive ownership.
    pub fn admit_download_payload(
        &self,
        expected: &MetadataDownloadPayload,
        normalized_payload: &std::path::Path,
        evidence: crate::NativeFileIdentityEvidence,
    ) -> Result<bool> {
        crate::download_job_store::validate_job_path(normalized_payload)?;
        evidence.validate_fingerprint(&expected.fingerprint)?;
        let native = crate::NativePath::from(normalized_payload);
        let mut conn = self.connection()?;
        let tx = conn.transaction()?;
        let current = matches!(read(&tx,expected.token.job_id,crate::download_job_store::JOB_PAGE_BYTES)?,
            PayloadRead::Value(current) if *current==*expected);
        let excluded: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions
            WHERE platform=?1 AND native_path=?2)",
            params![crate::NativePath::platform(), native.storage_bytes()],
            |r| r.get(0),
        )?;
        let allowed = current
            && !excluded
            && !crate::delivery_exclusion_store::evidence_is_excluded(&tx, evidence)?;
        tx.commit()?;
        Ok(allowed)
    }
}
#[cfg(test)]
mod tests;
