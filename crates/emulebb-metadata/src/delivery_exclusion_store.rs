//! Durable sharing exclusions for incomplete direct delivery outputs.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::{
    JobId, JobToken, MetadataDeliveryOutputReservation, MetadataStore,
    MetadataTransferDeliveryAttempt, NativePath,
};

fn exclusion_path(path: &Path) -> Result<PathBuf> {
    crate::download_job_store::validate_job_path(path)?;
    let parent = path.parent().context("delivery path has no parent")?;
    let name = path.file_name().context("delivery path has no filename")?;
    let normalized = std::fs::canonicalize(parent)?.join(name);
    crate::download_job_store::validate_job_path(&normalized)?;
    Ok(normalized)
}

pub(crate) fn is_excluded(conn: &Connection, path: &Path) -> Result<bool> {
    let any: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions)")?
        .query_row([], |row| row.get(0))?;
    if !any {
        return Ok(false);
    }
    let normalized = match exclusion_path(path) {
        Ok(path) => path,
        // WHY: If the parent cannot be resolved, an alias of a reserved path
        // cannot be ruled out. Do not admit it to the shared catalog.
        Err(_) => return Ok(true),
    };
    let native = NativePath::from(normalized.as_path());
    Ok(conn
        .prepare_cached(
            "SELECT 1 FROM download_delivery_exclusions WHERE platform = ?1 AND native_path = ?2",
        )?
        .query_row(
            params![NativePath::platform(), native.storage_bytes()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

impl MetadataStore {
    /// Reserve an exact live attempt's final name before exclusive creation.
    /// Exclusions outlive jobs. Alias withdrawal below still scans the library
    /// and resolves parent paths under this transaction; it is not byte-bounded
    /// and must move to tracked incremental work in the runtime reservation cut.
    pub fn reserve_delivery_output(&self, token: JobToken, path: &Path, id: Uuid) -> Result<bool> {
        let job_id = token.job_id;
        let normalized = exclusion_path(path)?;
        let native = NativePath::from(normalized.as_path());
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let requested = NativePath::from(path);
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_jobs j
             JOIN download_delivery_attempts a ON a.job_id=j.id
             JOIN local_paths p ON p.id=a.target_path_id
             WHERE j.id=?1 AND j.execution_generation=?2 AND j.intent='started'
               AND j.removed_at_s IS NULL AND j.delete_requested_at_s IS NULL
               AND j.terminal_completed_at_s IS NULL AND j.completed=1 AND j.final_rehash_pending=0
               AND j.delivery_state='pending' AND j.delivered_path_id IS NULL
               AND a.attempt_id=?3 AND a.phase IN ('prepared','staged')
               AND p.platform=?4 AND p.native_path=?5)",
            params![
                job_id,
                i64::try_from(token.generation)?,
                id.to_string(),
                NativePath::platform(),
                requested.storage_bytes()
            ],
            |row| row.get(0),
        )?;
        if !current {
            return Ok(false);
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO download_delivery_exclusions(platform, native_path, reservation_id,originating_job_id) VALUES (?1, ?2, ?3, ?4)",
            params![NativePath::platform(), native.storage_bytes(), id.to_string(),job_id],
        )? == 1;
        if inserted {
            // WHY: an old session may still advertise a removed file under an
            // alias of this name. Withdraw it before a new partial can exist.
            let paths = {
                let mut stmt = tx.prepare("SELECT local_paths.id, local_paths.platform, local_paths.native_path
                    FROM local_file_instances JOIN local_paths ON local_paths.id = local_file_instances.path_id
                    WHERE EXISTS (SELECT 1 FROM shared_file_memberships m
                                  WHERE m.path_id = local_paths.id AND m.removed_at_s IS NULL)
                       OR EXISTS (SELECT 1 FROM temp.session_verified_local_paths v WHERE v.path_id = local_paths.id)")?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        crate::native_path::path_from_row(row, 1, 2)?,
                    ))
                })?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut parents: HashMap<PathBuf, Option<PathBuf>> = HashMap::new();
            for (path_id, known_path) in paths {
                let Some((parent, name)) = known_path.parent().zip(known_path.file_name()) else {
                    continue;
                };
                let resolved = parents
                    .entry(parent.to_path_buf())
                    .or_insert_with(|| std::fs::canonicalize(parent).ok());
                if resolved
                    .as_ref()
                    .is_some_and(|parent| parent.join(name) == normalized)
                {
                    tx.execute("UPDATE shared_file_memberships SET removed_at_s = ?2 WHERE path_id = ?1 AND removed_at_s IS NULL", params![path_id, crate::store::unix_s()])?;
                    tx.execute(
                        "DELETE FROM temp.session_verified_local_paths WHERE path_id = ?1",
                        [path_id],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Bind the identity obtained from the exclusively created output handle,
    /// before writing bytes. This is a sharing barrier, never deletion authority.
    pub fn bind_delivery_output_identity(
        &self,
        token: JobToken,
        reservation: &MetadataDeliveryOutputReservation,
        attempt: &MetadataTransferDeliveryAttempt,
        fingerprint: &crate::NativeFileFingerprint,
        evidence: crate::NativeFileIdentityEvidence,
    ) -> Result<bool> {
        evidence.validate_fingerprint(fingerprint)?;
        if !matches!(
            attempt.phase,
            crate::MetadataTransferDeliveryAttemptPhase::Prepared
                | crate::MetadataTransferDeliveryAttemptPhase::Staged
        ) || reservation.originating_job_id != token.job_id
            || attempt.job_id != token.job_id
            || attempt.attempt_id != reservation.reservation_id
        {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2
            AND intent='started' AND removed_at_s IS NULL AND terminal_completed_at_s IS NULL AND delete_requested_at_s IS NULL)",
            params![token.job_id,i64::try_from(token.generation)?],|row|row.get(0))?;
        if !current
            || crate::transfer_store::delivery_attempt_by_job(&tx, token.job_id)?.as_ref()
                != Some(attempt)
            || reservation_by_id(&tx, token.job_id, reservation.reservation_id)?.as_ref()
                != Some(reservation)
        {
            return Ok(false);
        }
        let changed=tx.execute("UPDATE download_delivery_exclusions SET output_identity=?3,secondary_identity=?4
            WHERE originating_job_id=?1 AND reservation_id=?2 AND (output_identity IS NULL OR (output_identity=?3 AND secondary_identity IS ?4))",
            params![token.job_id,reservation.reservation_id.to_string(),evidence.primary().storage_bytes(),evidence.secondary().map(|identity|identity.storage_bytes())])?;
        tx.commit()?;
        Ok(changed != 0)
    }

    /// Capture exact immutable reservation authority before cleanup I/O.
    pub fn delivery_output_reservation(
        &self,
        job_id: JobId,
        id: Uuid,
    ) -> Result<Option<MetadataDeliveryOutputReservation>> {
        let conn = self.connection()?;
        reservation_by_id(&conn, job_id, id)
    }

    /// A live callback must retain both snapshots and the executing token.
    pub fn release_delivery_output(
        &self,
        token: JobToken,
        reservation: &MetadataDeliveryOutputReservation,
        attempt: &MetadataTransferDeliveryAttempt,
    ) -> Result<bool> {
        self.release_existing_job_output(token, reservation, Some(attempt), true)
    }

    /// Recovery captures the current token and both snapshots under exclusive
    /// lifecycle ownership before I/O; it must never refresh them after I/O.
    /// An absent attempt snapshot is permitted only while no attempt exists,
    /// so an independently retained exclusion can settle without erasing a
    /// reservation underneath an unmatched active attempt.
    pub fn release_recovered_delivery_output(
        &self,
        token: JobToken,
        reservation: &MetadataDeliveryOutputReservation,
        attempt: Option<&MetadataTransferDeliveryAttempt>,
    ) -> Result<bool> {
        self.release_existing_job_output(token, reservation, attempt, false)
    }

    fn release_existing_job_output(
        &self,
        token: JobToken,
        reservation: &MetadataDeliveryOutputReservation,
        attempt: Option<&MetadataTransferDeliveryAttempt>,
        live: bool,
    ) -> Result<bool> {
        crate::download_job_store::validate_job_path(&reservation.path)?;
        if reservation.originating_job_id != token.job_id
            || attempt.is_some_and(|attempt| {
                attempt.job_id != token.job_id || attempt.attempt_id != reservation.reservation_id
            })
        {
            return Ok(false);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1 AND execution_generation=?2
            AND (?3=0 OR (intent='started' AND removed_at_s IS NULL AND delete_requested_at_s IS NULL AND terminal_completed_at_s IS NULL)))",
            params![token.job_id,i64::try_from(token.generation)?,live],|row|row.get(0))?;
        if !current
            || crate::transfer_store::delivery_attempt_by_job(&tx, token.job_id)?.as_ref()
                != attempt
            || reservation_by_id(&tx, token.job_id, reservation.reservation_id)?.as_ref()
                != Some(reservation)
        {
            return Ok(false);
        }
        let changed=tx.execute("DELETE FROM download_delivery_exclusions WHERE originating_job_id=?1 AND reservation_id=?2",
            params![token.job_id,reservation.reservation_id.to_string()])?;
        tx.commit()?;
        Ok(changed != 0)
    }

    /// Orphan cleanup cannot impersonate recovery for a job which still exists.
    /// Its exact persisted path and UUID authority must have been captured before I/O.
    pub fn release_orphaned_delivery_output(
        &self,
        reservation: &MetadataDeliveryOutputReservation,
    ) -> Result<bool> {
        crate::download_job_store::validate_job_path(&reservation.path)?;
        let path = NativePath::from(reservation.path.as_path());
        Ok(self.connection()?.execute(
            "DELETE FROM download_delivery_exclusions
            WHERE originating_job_id=?1 AND reservation_id=?2 AND platform=?3 AND native_path=?4
            AND output_identity IS ?5 AND secondary_identity IS ?6 AND NOT EXISTS(SELECT 1 FROM download_jobs WHERE id=?1)",
            params![
                reservation.originating_job_id,
                reservation.reservation_id.to_string(),
                NativePath::platform(),
                path.storage_bytes(),
                reservation
                    .output_identity
                    .map(|identity| identity.storage_bytes()),reservation.secondary_identity.map(|identity|identity.storage_bytes())
            ],
        )? != 0)
    }

    /// Return whether a path is barred from local sharing.
    pub fn delivery_output_is_excluded(&self, path: &Path) -> Result<bool> {
        let conn = self.connection()?;
        is_excluded(&conn, path)
    }

    /// A retained reservation indicates an interrupted direct-copy attempt.
    pub fn has_delivery_reservation(&self, job_id: JobId, id: Uuid) -> Result<bool> {
        Ok(self.connection()?.query_row(
            "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE reservation_id = ?1 AND originating_job_id=?2)",
            params![id.to_string(),job_id],
            |row| row.get(0),
        )?)
    }
}

fn reservation_by_id(
    conn: &Connection,
    job_id: JobId,
    id: Uuid,
) -> Result<Option<MetadataDeliveryOutputReservation>> {
    Ok(conn.query_row("SELECT platform,CASE WHEN length(native_path)<=65536 THEN native_path END,length(native_path),output_identity,secondary_identity
        FROM download_delivery_exclusions WHERE originating_job_id=?1 AND reservation_id=?2",
        params![job_id,id.to_string()],|row| {
            crate::download_job_store::bounded_row_bytes(row,&[(2,65536,4)])?;
            Ok(MetadataDeliveryOutputReservation {originating_job_id:job_id,reservation_id:id,
                path:crate::native_path::path_from_row(row,0,1)?,
                output_identity:crate::native_file::optional_identity_from_row(row,3)?,
                secondary_identity:crate::native_file::optional_identity_from_row(row,4)?})
        }).optional()?)
}

pub(crate) fn identity_is_excluded(
    conn: &Connection,
    identity: crate::NativeFileIdentity,
) -> Result<bool> {
    Ok(conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE output_identity=?1 OR secondary_identity=?1)")?.query_row(
        [identity.storage_bytes()],
        |row| row.get(0),
    )?)
}

pub(crate) fn evidence_is_excluded(
    conn: &Connection,
    evidence: crate::NativeFileIdentityEvidence,
) -> Result<bool> {
    Ok(conn.prepare_cached("SELECT EXISTS(SELECT 1 FROM download_delivery_exclusions WHERE output_identity IN (?1,?2) OR secondary_identity IN (?1,?2))")?.query_row(
        params![evidence.primary().storage_bytes(),evidence.secondary().map(|identity|identity.storage_bytes())],|row|row.get(0))?)
}

pub(crate) fn ensure_evidence_not_excluded(
    conn: &Connection,
    evidence: crate::NativeFileIdentityEvidence,
) -> Result<()> {
    ensure!(
        !evidence_is_excluded(conn, evidence)?,
        "local file is an incomplete delivery output"
    );
    Ok(())
}

pub(crate) fn ensure_not_excluded(conn: &Connection, path: &Path) -> Result<()> {
    ensure!(
        !is_excluded(conn, path)?,
        "local file is an incomplete delivery output"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prepared_job(store: &MetadataStore, target: &Path, attempt: Uuid) -> JobToken {
        let token = store
            .admit_download_job(&crate::DownloadJobRequest {
                file_hash: "11".repeat(16),
                display_name: "reserved.bin".into(),
                expected_size_bytes: Some(1),
                category_id: None,
                intent: crate::DownloadIntent::Started,
                piece_size: 1,
            })
            .unwrap()
            .job
            .token;
        let mut manifest = store.download_job_manifest(token.job_id).unwrap().unwrap();
        manifest.completed = true;
        store.upsert_transfer_manifest(&manifest).unwrap();
        store
            .begin_transfer_delivery_attempt(
                token,
                attempt,
                target,
                &target
                    .parent()
                    .unwrap()
                    .join(format!(".emulebb-delivery-{attempt}.tmp")),
            )
            .unwrap();
        token
    }

    #[test]
    fn paired_actual_windows_ids_block_overlap_but_preserve_unrelated_volume() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-paired-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut store = MetadataStore::in_memory().unwrap();
        let target = root.join("output.bin");
        let attempt = Uuid::new_v4();
        let token = prepared_job(&store, &target, attempt);
        let low = crate::NativeFileIdentity::WindowsLowResolution {
            volume_serial_number: 7,
            file_index: 17,
        };
        let high = crate::NativeFileIdentity::WindowsHighResolution {
            volume_serial_number: 7,
            file_id: 19,
        };
        let mut proof = crate::NativeFileFingerprint {
            identity: high,
            size_bytes: 1,
            modified: crate::NativeFileTimestamp::new(1, 0).unwrap(),
            changed: None,
        };
        let alias = root.join("alias.bin");
        let mut content = crate::MetadataVerifiedLocalContent {
            secondary_identity: Some(low),
            file_hash: "22".repeat(16),
            display_name: "alias.bin".into(),
            file_size: 1,
            part_size: 1,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            path: alias.clone(),
            fingerprint: proof.clone(),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        };
        store
            .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
                path: root.to_string_lossy().into_owned(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
        store.upsert_verified_local_content(&content).unwrap();
        assert!(
            store
                .admit_local_path_to_root(&root, &alias, Path::new("alias.bin"), &proof)
                .unwrap()
        );
        let query = crate::MetadataSharedFileQuery {
            limit: 10,
            count_total: true,
            ..Default::default()
        };
        // Warm the disposable projection before the reservation changes. Binding
        // must invalidate it even while the alias membership remains untouched.
        assert_eq!(
            store
                .query_active_local_share_entries(&query)
                .unwrap()
                .total,
            1
        );
        assert!(
            store
                .reserve_delivery_output(token, &target, attempt)
                .unwrap()
        );
        assert_eq!(
            store
                .query_active_local_share_entries(&query)
                .unwrap()
                .total,
            1
        );
        let reservation = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        let journal = store
            .download_job_delivery_attempt(token.job_id)
            .unwrap()
            .unwrap();
        proof.identity = low;
        let low_evidence = crate::NativeFileIdentityEvidence::new(low, None).unwrap();
        assert!(
            store
                .bind_delivery_output_identity(token, &reservation, &journal, &proof, low_evidence)
                .unwrap()
        );
        assert!(
            !store
                .try_verified_share_batch(&[[0x22; 16]])
                .unwrap()
                .unwrap()[0]
                .0
        );
        let retained = store
            .library_locations(&content.file_hash, 0, 2, crate::LIBRARY_READ_MAX_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(retained.locations.len(), 1);
        assert_eq!(retained.locations[0].path, alias);
        assert!(retained.locations[0].identity_excluded);
        let page = store.query_active_local_share_entries(&query).unwrap();
        assert_eq!(page.total, 0);
        assert!(page.entries.is_empty());
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
        assert!(store.upsert_verified_local_content(&content).is_err());
        content.secondary_identity = None;
        assert!(store.upsert_verified_local_content(&content).is_err());
        let other_low = crate::NativeFileIdentity::WindowsLowResolution {
            volume_serial_number: 71,
            file_index: 17,
        };
        content.secondary_identity = Some(other_low);
        content.fingerprint.identity = crate::NativeFileIdentity::WindowsHighResolution {
            volume_serial_number: 71,
            file_id: 19,
        };
        content.file_hash = "33".repeat(16);
        content.path = root.join("unrelated.bin");
        store.upsert_verified_local_content(&content).unwrap();
        assert!(
            store
                .admit_local_path_to_root(
                    &root,
                    &content.path,
                    Path::new("unrelated.bin"),
                    &content.fingerprint
                )
                .unwrap()
        );
        assert!(
            store
                .try_verified_share_batch(&[[0x33; 16]])
                .unwrap()
                .unwrap()[0]
                .0
        );
        assert!(
            !evidence_is_excluded(
                &store.connection().unwrap(),
                crate::NativeFileIdentityEvidence::new(
                    content.fingerprint.identity,
                    Some(other_low)
                )
                .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            store
                .query_active_local_share_entries(&query)
                .unwrap()
                .total,
            1
        );
        let bound = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        assert!(
            store
                .release_delivery_output(token, &bound, &journal)
                .unwrap()
        );
        let page = store.query_active_local_share_entries(&query).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.entries.len(), 2);
        assert_eq!(store.active_shared_content_count().unwrap(), 2);
        drop(store);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn bound_output_identity_excludes_aliases_and_invalidates_old_release_snapshots() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-identity-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let mut store = MetadataStore::in_memory().unwrap();
        let target = root.join("output.bin");
        let attempt = Uuid::new_v4();
        let token = prepared_job(&store, &target, attempt);
        assert!(
            store
                .reserve_delivery_output(token, &target, attempt)
                .unwrap()
        );
        let reserved = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        let journal = store
            .download_job_delivery_attempt(token.job_id)
            .unwrap()
            .unwrap();
        let proof = crate::NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 19,
                inode_number: 23,
            },
            size_bytes: 1,
            modified: crate::NativeFileTimestamp::new(1, 0).unwrap(),
            changed: None,
        };
        let evidence = crate::NativeFileIdentityEvidence::new(proof.identity, None).unwrap();
        let alias = root.join("different-leaf.bin");
        let content = crate::MetadataVerifiedLocalContent {
            secondary_identity: None,
            file_hash: "22".repeat(16),
            display_name: "different-leaf.bin".into(),
            file_size: 1,
            part_size: 1,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            path: alias.clone(),
            fingerprint: proof.clone(),
            upload_priority: "normal".into(),
            auto_upload_priority: false,
            comment: String::new(),
            rating: 0,
        };
        store
            .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
                path: root.to_string_lossy().into_owned(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
        // A candidate admitted before identity binding cannot remain eligible afterwards.
        store.upsert_verified_local_content(&content).unwrap();
        assert!(
            store
                .admit_local_path_to_root(&root, &alias, Path::new("different-leaf.bin"), &proof)
                .unwrap()
        );
        assert!(
            store
                .try_verified_share_batch(&[[0x22; 16]])
                .unwrap()
                .unwrap()[0]
                .0
        );
        assert_eq!(store.active_shared_content_count().unwrap(), 1);
        assert!(
            store
                .bind_delivery_output_identity(token, &reserved, &journal, &proof, evidence)
                .unwrap()
        );
        let bound = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        assert_eq!(bound.output_identity, Some(proof.identity));
        assert_eq!(store.active_shared_content_count().unwrap(), 0);
        assert!(
            !store
                .try_verified_share_batch(&[[0x22; 16]])
                .unwrap()
                .unwrap()[0]
                .0
        );
        assert!(store.upsert_verified_local_content(&content).is_err());
        store
            .replace_root_memberships(
                &root,
                &store.shared_root_scan_watermark(&root).unwrap(),
                &[(
                    alias.clone(),
                    PathBuf::from("different-leaf.bin"),
                    proof.clone(),
                )],
            )
            .unwrap();
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM shared_file_memberships WHERE removed_at_s IS NULL",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert!(
            !store
                .try_verified_share_batch(&[[0x22; 16]])
                .unwrap()
                .unwrap()[0]
                .0
        );
        assert!(
            !store
                .mark_session_verified_local_path(&alias, &proof)
                .unwrap()
        );
        assert!(
            !store
                .admit_local_path_to_root(&root, &alias, Path::new("different-leaf.bin"), &proof)
                .unwrap()
        );
        assert!(
            !store
                .release_delivery_output(token, &reserved, &journal)
                .unwrap()
        );
        let mut replaced = proof.clone();
        replaced.identity = crate::NativeFileIdentity::Unix {
            device_id: 19,
            inode_number: 24,
        };
        let replaced_evidence =
            crate::NativeFileIdentityEvidence::new(replaced.identity, None).unwrap();
        assert!(
            !store
                .bind_delivery_output_identity(
                    token,
                    &bound,
                    &journal,
                    &replaced,
                    replaced_evidence
                )
                .unwrap()
        );
        assert!(
            store
                .bind_delivery_output_identity(token, &bound, &journal, &proof, replaced_evidence)
                .is_err()
        );
        assert!(store.stop_download_job(token).unwrap());
        assert!(
            !store
                .bind_delivery_output_identity(token, &bound, &journal, &proof, evidence)
                .unwrap()
        );
        let recovery = store.download_job(token.job_id).unwrap().unwrap().token;
        assert!(
            store
                .release_recovered_delivery_output(recovery, &bound, Some(&journal))
                .unwrap()
        );
        assert!(!identity_is_excluded(&store.connection().unwrap(), proof.identity).unwrap());
        drop(store);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn reservation_requires_current_started_token_and_exact_attempt_target() {
        let root = std::env::temp_dir().join(format!("emulebb-exclusion-fence-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target.bin");
        let mut store = MetadataStore::in_memory().unwrap();
        let attempt = Uuid::new_v4();
        let token = prepared_job(&store, &target, attempt);
        let proof = crate::NativeFileFingerprint {
            identity: crate::NativeFileIdentity::Unix {
                device_id: 1,
                inode_number: 2,
            },
            size_bytes: 1,
            modified: crate::NativeFileTimestamp::new(1, 0).unwrap(),
            changed: None,
        };
        store
            .replace_shared_directory_roots(&[crate::MetadataSharedDirectoryRoot {
                path: root.to_string_lossy().into_owned(),
                watch_enabled: false,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();
        store
            .upsert_verified_local_content(&crate::MetadataVerifiedLocalContent {
                secondary_identity: None,
                file_hash: "22".repeat(16),
                display_name: "target.bin".into(),
                file_size: 1,
                part_size: 1,
                md4_hashset: Vec::new(),
                aich_root: None,
                aich_hashset: Vec::new(),
                path: target.clone(),
                fingerprint: proof.clone(),
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
            })
            .unwrap();
        assert!(
            store
                .admit_local_path_to_root(&root, &target, Path::new("target.bin"), &proof)
                .unwrap()
        );
        let live_members = || {
            store
                .connection()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM shared_file_memberships WHERE removed_at_s IS NULL",
                    [],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
        };
        assert_eq!(live_members(), 1);
        assert!(store.stop_download_job(token).unwrap());
        assert!(
            !store
                .reserve_delivery_output(token, &target, attempt)
                .unwrap()
        );
        let stopped = store.download_job(token.job_id).unwrap().unwrap();
        assert!(
            !store
                .reserve_delivery_output(stopped.token, &target, attempt)
                .unwrap()
        );
        let restarted = store
            .start_download_job(stopped.token, &root)
            .unwrap()
            .unwrap();
        assert!(
            !store
                .reserve_delivery_output(token, &target, attempt)
                .unwrap()
        );
        assert!(
            !store
                .reserve_delivery_output(restarted.token, &root.join("wrong.bin"), attempt)
                .unwrap()
        );
        assert!(
            !store
                .reserve_delivery_output(restarted.token, &target, Uuid::new_v4())
                .unwrap()
        );
        assert_eq!(live_members(), 1);
        assert!(
            !store
                .has_delivery_reservation(token.job_id, attempt)
                .unwrap()
        );
        assert!(
            store
                .reserve_delivery_output(restarted.token, &target, attempt)
                .unwrap()
        );
        assert_eq!(live_members(), 0);
        assert!(
            !store
                .reserve_delivery_output(restarted.token, &target, attempt)
                .unwrap()
        );
        let live_reservation = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        let live_snapshot = store
            .download_job_delivery_attempt(token.job_id)
            .unwrap()
            .unwrap();
        let mut wrong_reservation = live_reservation.clone();
        wrong_reservation.path = root.join("wrong.bin");
        assert!(
            !store
                .release_delivery_output(restarted.token, &wrong_reservation, &live_snapshot)
                .unwrap()
        );
        let mut wrong_attempt = live_snapshot.clone();
        wrong_attempt.attempt_id = Uuid::new_v4();
        assert!(
            !store
                .release_delivery_output(restarted.token, &live_reservation, &wrong_attempt)
                .unwrap()
        );
        assert!(
            store
                .release_delivery_output(restarted.token, &live_reservation, &live_snapshot)
                .unwrap()
        );
        assert!(
            store
                .reserve_delivery_output(restarted.token, &target, attempt)
                .unwrap()
        );
        assert!(store.request_transfer_deletion(token.job_id).unwrap());
        let deleting = store.download_job(token.job_id).unwrap().unwrap();
        let reservation = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        let snapshot = store
            .download_job_delivery_attempt(token.job_id)
            .unwrap()
            .unwrap();
        assert!(
            !store
                .release_orphaned_delivery_output(&reservation)
                .unwrap()
        );
        assert!(
            store
                .release_recovered_delivery_output(deleting.token, &reservation, Some(&snapshot))
                .unwrap()
        );
        assert!(
            !store
                .reserve_delivery_output(restarted.token, &target, attempt)
                .unwrap()
        );
        let deleting = store.download_job(token.job_id).unwrap().unwrap();
        assert!(
            !store
                .reserve_delivery_output(deleting.token, &target, attempt)
                .unwrap()
        );
        assert!(
            !store
                .has_delivery_reservation(token.job_id, attempt)
                .unwrap()
        );
        drop(store);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn reservations_are_independent_and_prevent_duplicate_claims() {
        let root = std::env::temp_dir().join(format!("emulebb-exclusion-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("sample.bin");
        let store = MetadataStore::in_memory().unwrap();
        let first = Uuid::new_v4();
        let token = prepared_job(&store, &path, first);
        let job_id = token.job_id;
        let second = Uuid::new_v4();
        assert!(store.reserve_delivery_output(token, &path, first).unwrap());
        assert!(store.delivery_output_is_excluded(&path).unwrap());
        let reservation = store
            .delivery_output_reservation(job_id, first)
            .unwrap()
            .unwrap();
        assert!(
            !store
                .release_orphaned_delivery_output(&reservation)
                .unwrap()
        );
        let recovery = store
            .download_job_delivery_attempt(job_id)
            .unwrap()
            .unwrap();
        assert!(
            store
                .settle_recovered_delivery_attempt(token, &recovery)
                .unwrap()
        );
        assert!(store.delete_transfer_manifest(job_id).is_err());
        // Normal lifecycle retains this compact owner until the barrier settles.
        // Model a genuine preexisting orphan explicitly to exercise recovery.
        store
            .connection()
            .unwrap()
            .execute("DELETE FROM download_jobs WHERE id=?1", [job_id])
            .unwrap();
        assert!(!store.reserve_delivery_output(token, &path, second).unwrap());
        let mut wrong = reservation.clone();
        wrong.reservation_id = second;
        assert!(!store.release_orphaned_delivery_output(&wrong).unwrap());
        wrong = reservation.clone();
        wrong.path = root.join("wrong.bin");
        assert!(!store.release_orphaned_delivery_output(&wrong).unwrap());
        assert!(store.delivery_output_is_excluded(&path).unwrap());
        assert!(
            store
                .release_orphaned_delivery_output(&reservation)
                .unwrap()
        );
        assert!(!store.delivery_output_is_excluded(&path).unwrap());
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn retained_exclusion_can_settle_after_its_attempt_without_impersonating_an_orphan() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-settled-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let store = MetadataStore::in_memory().unwrap();
        let path = root.join("target.bin");
        let attempt = Uuid::new_v4();
        let token = prepared_job(&store, &path, attempt);
        assert!(
            store
                .reserve_delivery_output(token, &path, attempt)
                .unwrap()
        );
        let reservation = store
            .delivery_output_reservation(token.job_id, attempt)
            .unwrap()
            .unwrap();
        let snapshot = store
            .download_job_delivery_attempt(token.job_id)
            .unwrap()
            .unwrap();
        assert!(
            !store
                .release_recovered_delivery_output(token, &reservation, None)
                .unwrap()
        );
        assert!(
            store
                .settle_recovered_delivery_attempt(token, &snapshot)
                .unwrap()
        );
        assert!(
            !store
                .release_orphaned_delivery_output(&reservation)
                .unwrap()
        );
        assert!(
            !store
                .release_recovered_delivery_output(token, &reservation, Some(&snapshot))
                .unwrap()
        );
        assert!(
            store
                .release_recovered_delivery_output(token, &reservation, None)
                .unwrap()
        );
        assert!(
            !store
                .has_delivery_reservation(token.job_id, attempt)
                .unwrap()
        );
        drop(store);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn reservation_survives_profile_reopen() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-reopen-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("profile.db");
        let target = root.join("partial.bin");
        let id = Uuid::new_v4();
        let job_id;
        {
            let store = MetadataStore::open(&database).unwrap();
            let token = prepared_job(&store, &target, id);
            job_id = token.job_id;
            assert!(store.reserve_delivery_output(token, &target, id).unwrap());
        }
        let store = MetadataStore::open(&database).unwrap();
        assert!(store.has_delivery_reservation(job_id, id).unwrap());
        assert!(store.delivery_output_is_excluded(&target).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn exclusion_survives_reopen_and_resolves_parent_aliases() {
        let root =
            std::env::temp_dir().join(format!("emulebb-exclusion-reopen-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("alias")).unwrap();
        let database = root.join("profile.db");
        let canonical_target = root.join("real").join("partial.bin");
        let alias_target = root.join("alias").join("partial.bin");
        let id = Uuid::new_v4();
        let job_id;
        {
            let store = MetadataStore::open(&database).unwrap();
            let token = prepared_job(&store, &canonical_target, id);
            job_id = token.job_id;
            assert!(
                store
                    .reserve_delivery_output(token, &canonical_target, id)
                    .unwrap()
            );
            assert!(store.delivery_output_is_excluded(&alias_target).unwrap());
        }
        let store = MetadataStore::open(&database).unwrap();
        assert!(store.has_delivery_reservation(job_id, id).unwrap());
        assert!(store.delivery_output_is_excluded(&alias_target).unwrap());
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
