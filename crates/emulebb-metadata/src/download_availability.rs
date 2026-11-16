//! Bounded content-keyed availability reads, independent of execution manifests.
use crate::{MetadataStore, NativeFileFingerprint, download_job_store::bounded_row_bytes};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LocalContentAvailability {
    Present,
    ConfirmedAbsent,
    #[default]
    Unavailable,
}

#[derive(Debug)]
pub struct MetadataAvailabilityChanged;
impl std::fmt::Display for MetadataAvailabilityChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("availability observation changed before admission")
    }
}
impl std::error::Error for MetadataAvailabilityChanged {}

#[derive(Debug)]
pub struct MetadataLocalContentChoiceRequired(pub LocalContentAvailability);
impl std::fmt::Display for MetadataLocalContentChoiceRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("known local content requires an explicit redownload choice")
    }
}
impl std::error::Error for MetadataLocalContentChoiceRequired {}

/// Connection-local mutations and commits by other connections both invalidate
/// this conservative cut. Unrelated writes may refuse admission, never permit it.
#[derive(Debug)]
pub struct MetadataAvailabilityCut {
    connection: Weak<Mutex<Connection>>,
    changes: u64,
    data_version: i64,
}

/// Fresh native evidence must not park behind a SQLite writer. Restore the
/// normal connection timeout on every exit, including rollback and panic.
pub(crate) struct AvailabilityNoWait<'a> {
    connection: &'a Connection,
    timeout_ms: u64,
}
impl<'a> AvailabilityNoWait<'a> {
    pub(crate) fn new(connection: &'a Connection) -> Result<Self> {
        let timeout_ms: i64 =
            connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
        let timeout_ms = u64::try_from(timeout_ms)?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        Ok(Self {
            connection,
            timeout_ms,
        })
    }
}
impl Drop for AvailabilityNoWait<'_> {
    fn drop(&mut self) {
        // The connection remains borrowed and valid throughout this guard.
        let _ = self
            .connection
            .busy_timeout(std::time::Duration::from_millis(self.timeout_ms));
    }
}

/// Native owner supplies the observed availability, then SQL validates this
/// cut and current claims in the same transaction that allocates the job.
pub struct DownloadAvailabilityAdmission<'a> {
    pub cut: &'a MetadataAvailabilityCut,
    pub availability: LocalContentAvailability,
    pub redownload: bool,
    pub aich_root: Option<&'a str>,
    pub root_epoch: (&'a std::sync::atomic::AtomicU64, u64),
}
impl DownloadAvailabilityAdmission<'_> {
    pub(crate) fn check_root(&self) -> Result<()> {
        ensure!(
            self.root_epoch.1 % 2 == 0
                && self.root_epoch.0.load(std::sync::atomic::Ordering::Acquire)
                    == self.root_epoch.1,
            MetadataAvailabilityChanged
        );
        Ok(())
    }
}
impl MetadataAvailabilityCut {
    pub(crate) fn check(&self, store: &MetadataStore, conn: &Connection) -> Result<()> {
        let same = self
            .connection
            .upgrade()
            .is_some_and(|c| Arc::ptr_eq(&c, &store.conn));
        let version: i64 = conn.pragma_query_value(None, "data_version", |row| row.get(0))?;
        ensure!(
            same && self.changes == conn.total_changes() && self.data_version == version,
            MetadataAvailabilityChanged
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailabilitySource {
    Library,
    Delivered,
    Payload,
}

#[derive(Debug)]
pub struct MetadataAvailabilityCandidate {
    pub source: AvailabilitySource,
    pub path: PathBuf,
    pub root: Option<PathBuf>,
    pub root_accessible: bool,
    pub fingerprint: Option<NativeFileFingerprint>,
    pub size_bytes: u64,
}

/// One indexed row per call, including non-output history rows. The caller must
/// charge every step, not only candidates, against its operation work bound.
#[derive(Debug)]
pub struct MetadataAvailabilityStep {
    pub key: i64,
    pub charged_bytes: usize,
    pub candidate: Option<MetadataAvailabilityCandidate>,
}

const LIBRARY_SQL: &str = "SELECT i.path_id,length(p.native_path),length(i.verified_fingerprint),length(rp.native_path),
    p.platform,CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
    CASE WHEN length(i.verified_fingerprint)<=1024 THEN i.verified_fingerprint END,i.size_bytes,
    rp.platform,CASE WHEN length(rp.native_path)<=65536 THEN rp.native_path END,coalesce(r.accessible,1)
    FROM known_files k JOIN local_file_instances i ON i.known_file_id=k.id
    JOIN local_paths p ON p.id=i.path_id
    LEFT JOIN shared_directory_roots r ON r.id=(SELECT m.root_id FROM shared_file_memberships m
        WHERE m.path_id=i.path_id LIMIT 1)
    LEFT JOIN local_paths rp ON rp.id=r.path_id
    WHERE k.ed2k_hash=?1 AND i.path_id>?2 ORDER BY i.path_id LIMIT 1";

const OUTPUT_SQL: &str = "SELECT j.id,length(p.native_path),length(j.source_fingerprint),p.platform,
                CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
                CASE WHEN length(j.source_fingerprint)<=1024 THEN j.source_fingerprint END,
                j.expected_size_bytes FROM known_files k JOIN download_jobs j ON j.known_file_id=k.id
                LEFT JOIN local_paths p ON p.id=j.delivered_path_id
                WHERE k.ed2k_hash=?1 AND j.id>?2 ORDER BY j.id LIMIT 1";
const PAYLOAD_SQL: &str = "SELECT j.id,length(p.native_path),length(j.payload_fingerprint),p.platform,
                CASE WHEN length(p.native_path)<=65536 THEN p.native_path END,
                CASE WHEN length(j.payload_fingerprint)<=1024 THEN j.payload_fingerprint END,
                j.expected_size_bytes FROM known_files k JOIN download_jobs j ON j.known_file_id=k.id
                LEFT JOIN local_paths p ON p.id=j.storage_path_id AND j.internal_storage_retired=0 AND j.payload_fingerprint IS NOT NULL
                WHERE k.ed2k_hash=?1 AND j.id>?2 ORDER BY j.id LIMIT 1";

impl MetadataStore {
    pub fn validate_download_availability(&self, cut: &MetadataAvailabilityCut) -> Result<()> {
        cut.check(self, &*self.connection()?)
    }

    pub fn active_download_job(&self, hash: &str) -> Result<Option<crate::DownloadJobRecord>> {
        let hash = crate::store::decode_fixed_hex(hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        let id = conn
            .query_row(
                "SELECT j.id FROM known_files k JOIN download_jobs j ON j.known_file_id=k.id
            WHERE k.ed2k_hash=?1 AND j.removed_at_s IS NULL AND j.terminal_completed_at_s IS NULL",
                [hash],
                |row| row.get::<_, crate::JobId>(0),
            )
            .optional()?;
        id.map(|id| crate::download_job_store::read_job(&conn, id))
            .transpose()
            .map(Option::flatten)
    }
    pub fn capture_download_availability(&self) -> Result<MetadataAvailabilityCut> {
        let conn = self.connection()?;
        Ok(MetadataAvailabilityCut {
            connection: Arc::downgrade(&self.conn),
            changes: conn.total_changes(),
            data_version: conn.pragma_query_value(None, "data_version", |row| row.get(0))?,
        })
    }

    /// Includes offline/unshared library locations and all retained job rows.
    /// No file I/O, manifest hydration, latest-job selection or collection scan.
    pub fn next_download_availability(
        &self,
        hash: &str,
        source: AvailabilitySource,
        after: i64,
        cut: &MetadataAvailabilityCut,
        max_decoded_bytes: usize,
    ) -> Result<Option<MetadataAvailabilityStep>> {
        ensure!(
            after >= 0 && (1..=2 * 1024 * 1024).contains(&max_decoded_bytes),
            "invalid availability cursor or page budget"
        );
        let hash = crate::store::decode_fixed_hex(hash, 16, "ED2K hash")?;
        let conn = self.connection()?;
        cut.check(self, &conn)?;
        let step = if source == AvailabilitySource::Library {
            conn.query_row(LIBRARY_SQL, params![hash, after], |row| {
                let charged_bytes =
                    bounded_row_bytes(row, &[(1, 65536, 8), (2, 1024, 2), (3, 65536, 8)])
                        .unwrap_or(usize::MAX);
                if charged_bytes > max_decoded_bytes {
                    return Ok(MetadataAvailabilityStep {
                        key: row.get(0)?,
                        charged_bytes,
                        candidate: None,
                    });
                }
                Ok(MetadataAvailabilityStep {
                    key: row.get(0)?,
                    charged_bytes,
                    candidate: Some(MetadataAvailabilityCandidate {
                        source,
                        path: crate::native_path::path_from_row(row, 4, 5)?,
                        root: crate::native_path::optional_path_from_row(row, 8, 9)?,
                        root_accessible: row.get(10)?,
                        fingerprint: crate::transfer_store::optional_fingerprint_from_row(row, 6)?,
                        size_bytes: crate::sql_value::unsigned(row, 7)?,
                    }),
                })
            })
            .optional()?
        } else {
            // Select the next job BEFORE inspecting eligibility, so arbitrarily
            // long runs of retired/undelivered jobs still consume bounded work.
            let sql = if source == AvailabilitySource::Delivered {
                OUTPUT_SQL
            } else {
                PAYLOAD_SQL
            };
            conn.query_row(sql, params![hash, after], |row| {
                let charged_bytes =
                    bounded_row_bytes(row, &[(1, 65536, 8), (2, 1024, 2)]).unwrap_or(usize::MAX);
                if charged_bytes > max_decoded_bytes {
                    return Ok(MetadataAvailabilityStep {
                        key: row.get(0)?,
                        charged_bytes,
                        candidate: None,
                    });
                }
                let candidate = crate::native_path::optional_path_from_row(row, 3, 4)?
                    .map(|path| {
                        Ok::<_, rusqlite::Error>(MetadataAvailabilityCandidate {
                            source,
                            path,
                            root: None,
                            root_accessible: true,
                            fingerprint: crate::transfer_store::optional_fingerprint_from_row(
                                row, 5,
                            )?,
                            size_bytes: crate::sql_value::unsigned(row, 6)?,
                        })
                    })
                    .transpose()?;
                Ok(MetadataAvailabilityStep {
                    key: row.get(0)?,
                    charged_bytes,
                    candidate,
                })
            })
            .optional()?
        };
        cut.check(self, &conn)?;
        Ok(step)
    }
}

#[cfg(test)]
mod tests;
