use std::{fs::File, path::Path, str::FromStr};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{
    JobId, JobToken, MetadataStore, MetadataTransferDeletionTombstone,
    MetadataTransferDeletionTombstonePhase, NativeFileFingerprint,
};
use uuid::Uuid;

#[cfg(test)]
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::long_path::long_path;

use super::{
    deliver::{
        OwnedDeliveryOutput, compute_ed2k_hash_from_handle,
        remove_file_if_fingerprint_matches_retained as remove_file_if_fingerprint_matches,
    },
    fs_durability::{
        NoReplaceMoveOutcome, move_path_no_replace_retained as move_path_no_replace,
        sync_parent_directory_retained as sync_parent_directory,
    },
};

enum InspectedFile {
    Missing,
    Regular {
        file: File,
        fingerprint: NativeFileFingerprint,
    },
    Foreign,
}

enum PreparedCleanupOutcome {
    Complete,
    RetryWithNewTombstone,
}

pub(super) struct OutputCleanup<'a> {
    pub metadata: &'a MetadataStore,
    pub token: JobToken,
}
impl OutputCleanup<'_> {
    pub(super) fn cleanup_delivery_output_for_deletion(
        &self,
        job_id: JobId,
        file_hash: &str,
        authority: Option<OwnedDeliveryOutput>,
    ) -> Result<()> {
        for _ in 0..4 {
            let tombstone = match self.deletion_tombstone(job_id)? {
                Some(tombstone) => tombstone,
                None => {
                    let Some(authority) = authority.as_ref() else {
                        return Ok(());
                    };
                    match inspect_file(&authority.path)? {
                        InspectedFile::Missing => {
                            sync_parent_directory(&authority.path)?;
                            self.metadata.withdraw_local_file_path_if_verified(
                                &long_path(&authority.path),
                                file_hash,
                                &authority.fingerprint,
                            )?;
                            return Ok(());
                        }
                        InspectedFile::Regular { fingerprint, .. }
                            if fingerprint == authority.fingerprint => {}
                        InspectedFile::Regular { .. } | InspectedFile::Foreign => {
                            tracing::warn!(file_hash, path=%authority.path.display(), "preserving delivered output without exact deletion ownership");
                            return Ok(());
                        }
                    }
                    let tombstone_id = Uuid::new_v4();
                    let tombstone_path = authority
                        .path
                        .with_file_name(format!(".emulebb-delete-{tombstone_id}.tmp"));
                    self.begin_deletion_tombstone(
                        job_id,
                        tombstone_id,
                        &authority.path,
                        &tombstone_path,
                        &authority.fingerprint,
                    )?
                }
            };
            validate_tombstone(&tombstone)?;
            match tombstone.phase {
                MetadataTransferDeletionTombstonePhase::Prepared => {
                    match self.process_prepared_tombstone(file_hash, &tombstone)? {
                        PreparedCleanupOutcome::Complete => return Ok(()),
                        PreparedCleanupOutcome::RetryWithNewTombstone => continue,
                    }
                }
                MetadataTransferDeletionTombstonePhase::Moved => {
                    return self.reap_and_settle(file_hash, &tombstone);
                }
            }
        }
        anyhow::bail!("failed to allocate a collision-free deletion tombstone for {file_hash}")
    }

    fn process_prepared_tombstone(
        &self,
        file_hash: &str,
        tombstone: &MetadataTransferDeletionTombstone,
    ) -> Result<PreparedCleanupOutcome> {
        match inspect_file(&tombstone.original_path)? {
            InspectedFile::Missing => {
                sync_parent_directory(&tombstone.original_path)?;
                match inspect_file(&tombstone.tombstone_path)? {
                    InspectedFile::Missing => {
                        sync_parent_directory(&tombstone.tombstone_path)?;
                        self.settle(tombstone)?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                    InspectedFile::Regular { file, fingerprint }
                        if fingerprint.identity == tombstone.source_fingerprint.identity
                            && fingerprint.size_bytes
                                == tombstone.source_fingerprint.size_bytes =>
                    {
                        let expected_hash = Ed2kHash::from_str(file_hash)
                            .with_context(|| format!("invalid ED2K file hash {file_hash}"))?
                            .0;
                        let verified_fingerprint = verify_uncheckpointed_moved_tombstone(
                            file,
                            &tombstone.tombstone_path,
                            tombstone.source_fingerprint.size_bytes,
                            expected_hash,
                        )?
                        .with_context(|| {
                            format!(
                                "deletion tombstone {} does not contain the expected transferred bytes",
                                tombstone.tombstone_id
                            )
                        })?;
                        let moved =
                            self.mark_deletion_tombstone_moved(tombstone, &verified_fingerprint)?;
                        self.reap_and_settle(file_hash, &moved)?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                    InspectedFile::Regular { .. } | InspectedFile::Foreign => {
                        self.settle(tombstone)?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                }
            }
            InspectedFile::Regular { file, fingerprint }
                if fingerprint == tombstone.source_fingerprint =>
            {
                #[cfg(test)]
                run_before_move_hook(&tombstone.original_path, &tombstone.tombstone_path);
                match move_path_no_replace(&tombstone.original_path, &tombstone.tombstone_path)? {
                    NoReplaceMoveOutcome::AlreadyExists => {
                        drop(file);
                        self.settle(tombstone)?;
                        Ok(PreparedCleanupOutcome::RetryWithNewTombstone)
                    }
                    NoReplaceMoveOutcome::Moved => {
                        let moved_fingerprint =
                            capture_moved_fingerprint(file, &tombstone.tombstone_path)?;
                        let Some(moved_fingerprint) = moved_fingerprint else {
                            match move_path_no_replace(
                                &tombstone.tombstone_path,
                                &tombstone.original_path,
                            )? {
                                NoReplaceMoveOutcome::Moved => {
                                    self.settle(tombstone)?;
                                    tracing::warn!(
                                        file_hash,
                                        path = %tombstone.original_path.display(),
                                        "restored replacement raced into delivered-output deletion"
                                    );
                                    return Ok(PreparedCleanupOutcome::Complete);
                                }
                                NoReplaceMoveOutcome::AlreadyExists => {
                                    anyhow::bail!(
                                        "replacement raced into delivered-output deletion and could not be restored from {}",
                                        tombstone.tombstone_path.display()
                                    );
                                }
                            }
                        };
                        let moved =
                            self.mark_deletion_tombstone_moved(tombstone, &moved_fingerprint)?;
                        self.reap_and_settle(file_hash, &moved)?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                }
            }
            InspectedFile::Regular { .. } | InspectedFile::Foreign => {
                tracing::warn!(
                    file_hash,
                    path = %tombstone.original_path.display(),
                    "preserving replacement at delivered-output deletion path"
                );
                self.settle(tombstone)?;
                Ok(PreparedCleanupOutcome::Complete)
            }
        }
    }

    fn begin_deletion_tombstone(
        &self,
        id: JobId,
        tombstone_id: Uuid,
        original: &Path,
        target: &Path,
        fingerprint: &NativeFileFingerprint,
    ) -> Result<MetadataTransferDeletionTombstone> {
        self.metadata.begin_transfer_deletion_tombstone(
            id,
            tombstone_id,
            original,
            target,
            fingerprint,
        )
    }
    fn deletion_tombstone(&self, id: JobId) -> Result<Option<MetadataTransferDeletionTombstone>> {
        self.metadata.download_job_deletion_tombstone(id)
    }
    fn mark_deletion_tombstone_moved(
        &self,
        expected: &MetadataTransferDeletionTombstone,
        fingerprint: &NativeFileFingerprint,
    ) -> Result<MetadataTransferDeletionTombstone> {
        self.metadata
            .mark_transfer_deletion_tombstone_moved(
                expected.job_id,
                expected.tombstone_id,
                fingerprint,
            )?
            .context("deletion tombstone disappeared before move committed")
    }
    fn reap_and_settle(
        &self,
        file_hash: &str,
        moved: &MetadataTransferDeletionTombstone,
    ) -> Result<()> {
        // WHY: watchers are optional. The retained deletion owner must withdraw
        // the exact moved copy itself; a newer verified replacement is independent.
        self.metadata.withdraw_local_file_path_if_verified(
            &long_path(&moved.original_path),
            file_hash,
            &moved.source_fingerprint,
        )?;
        reap_moved_tombstone(moved)?;
        self.settle(moved)
    }

    fn settle(&self, expected: &MetadataTransferDeletionTombstone) -> Result<()> {
        anyhow::ensure!(
            self.metadata
                .settle_recovered_output_tombstone(self.token, expected)?,
            "deletion tombstone changed before settlement"
        );
        Ok(())
    }
}

#[cfg(test)]
type BeforeMoveHook = Box<dyn FnOnce(&Path, &Path) + Send>;

#[cfg(test)]
fn before_move_hooks() -> &'static Mutex<HashMap<std::path::PathBuf, BeforeMoveHook>> {
    static HOOKS: OnceLock<Mutex<HashMap<std::path::PathBuf, BeforeMoveHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(super) fn set_before_move_hook(original_path: &Path, hook: BeforeMoveHook) {
    before_move_hooks()
        .lock()
        .expect("deletion before-move hook mutex poisoned")
        .insert(long_path(original_path), hook);
}

#[cfg(test)]
fn run_before_move_hook(original_path: &Path, tombstone_path: &Path) {
    let hook = before_move_hooks()
        .lock()
        .expect("deletion before-move hook mutex poisoned")
        .remove(&long_path(original_path));
    if let Some(hook) = hook {
        hook(original_path, tombstone_path);
    }
}

fn validate_tombstone(tombstone: &MetadataTransferDeletionTombstone) -> Result<()> {
    anyhow::ensure!(
        tombstone.original_path.is_absolute() && tombstone.tombstone_path.is_absolute(),
        "deletion tombstone {} contains a non-absolute path",
        tombstone.tombstone_id
    );
    anyhow::ensure!(
        tombstone.original_path.parent().is_some()
            && tombstone.original_path.parent() == tombstone.tombstone_path.parent(),
        "deletion tombstone {} paths do not share one parent",
        tombstone.tombstone_id
    );
    let expected_name = format!(".emulebb-delete-{}.tmp", tombstone.tombstone_id);
    anyhow::ensure!(
        tombstone
            .tombstone_path
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new(&expected_name)),
        "deletion tombstone {} has an invalid path",
        tombstone.tombstone_id
    );
    Ok(())
}

fn reap_moved_tombstone(tombstone: &MetadataTransferDeletionTombstone) -> Result<()> {
    let moved_fingerprint = tombstone.moved_fingerprint.as_ref().with_context(|| {
        format!(
            "moved deletion tombstone {} has no moved identity",
            tombstone.tombstone_id
        )
    })?;
    match inspect_file(&tombstone.tombstone_path)? {
        InspectedFile::Missing => sync_parent_directory(&tombstone.tombstone_path),
        InspectedFile::Regular { fingerprint, .. } if fingerprint == *moved_fingerprint => {
            anyhow::ensure!(
                remove_file_if_fingerprint_matches(&tombstone.tombstone_path, moved_fingerprint,)?,
                "deletion tombstone {} changed before physical reclamation",
                tombstone.tombstone_id
            );
            Ok(())
        }
        InspectedFile::Regular { .. } | InspectedFile::Foreign => anyhow::bail!(
            "deletion tombstone {} no longer identifies the moved output at {}",
            tombstone.tombstone_id,
            tombstone.tombstone_path.display()
        ),
    }
}

fn inspect_file(path: &Path) -> Result<InspectedFile> {
    let path = long_path(path);
    let file = match open_renameable_file_without_follow(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InspectedFile::Missing);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open deletion path {}", path.display()));
        }
    };
    let metadata = file.metadata()?;
    let Some(fingerprint) = super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
    else {
        return Ok(InspectedFile::Foreign);
    };
    if super::ingest::native_file_fingerprint(&path).as_ref() != Some(&fingerprint) {
        return Ok(InspectedFile::Foreign);
    }
    Ok(InspectedFile::Regular { file, fingerprint })
}

fn verify_uncheckpointed_moved_tombstone(
    mut file: File,
    tombstone_path: &Path,
    expected_size: u64,
    expected_hash: [u8; 16],
) -> Result<Option<NativeFileFingerprint>> {
    let tombstone_path = long_path(tombstone_path);
    let metadata = file.metadata()?;
    let Some(opened_fingerprint) =
        super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
    else {
        return Ok(None);
    };
    if opened_fingerprint.size_bytes != expected_size
        || compute_ed2k_hash_from_handle(&mut file, expected_size)? != expected_hash
    {
        return Ok(None);
    }
    let verified_metadata = file.metadata()?;
    let Some(verified_fingerprint) =
        super::ingest::native_file_fingerprint_from_handle(&file, &verified_metadata)
    else {
        return Ok(None);
    };
    if opened_fingerprint != verified_fingerprint
        || super::ingest::native_file_fingerprint(&tombstone_path).as_ref()
            != Some(&verified_fingerprint)
    {
        return Ok(None);
    }
    Ok(Some(verified_fingerprint))
}

fn capture_moved_fingerprint(
    file: File,
    tombstone_path: &Path,
) -> Result<Option<NativeFileFingerprint>> {
    let tombstone_path = long_path(tombstone_path);
    let metadata = file.metadata()?;
    let Some(fingerprint) = super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
    else {
        return Ok(None);
    };
    Ok(
        (super::ingest::native_file_fingerprint(&tombstone_path).as_ref() == Some(&fingerprint))
            .then_some(fingerprint),
    )
}

#[cfg(windows)]
fn open_renameable_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_renameable_file_without_follow(path: &Path) -> std::io::Result<File> {
    super::ingest::open_regular_file_without_follow(path)
}
