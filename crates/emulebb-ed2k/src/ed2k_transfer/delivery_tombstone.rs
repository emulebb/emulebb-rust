use std::{fs::File, path::Path};

use anyhow::{Context, Result};
use emulebb_metadata::{
    MetadataTransferDeletionTombstone, MetadataTransferDeletionTombstonePhase,
    NativeFileFingerprint,
};
use uuid::Uuid;

#[cfg(test)]
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use crate::long_path::long_path;

use super::{
    Ed2kTransferRuntime,
    deliver::{OwnedDeliveryOutput, remove_file_if_fingerprint_matches},
    fs_durability::{NoReplaceMoveOutcome, move_path_no_replace, sync_parent_directory},
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

impl Ed2kTransferRuntime {
    pub(super) async fn cleanup_delivery_output_for_deletion(
        &self,
        file_hash: &str,
        authority: Option<OwnedDeliveryOutput>,
    ) -> Result<()> {
        for _ in 0..4 {
            let tombstone = match self.deletion_tombstone(file_hash).await? {
                Some(tombstone) => tombstone,
                None => {
                    let Some(authority) = authority.as_ref() else {
                        return Ok(());
                    };
                    match inspect_file(&authority.path).await? {
                        InspectedFile::Missing => {
                            sync_parent_directory(&authority.path).await?;
                            return Ok(());
                        }
                        InspectedFile::Regular { fingerprint, .. }
                            if fingerprint == authority.fingerprint => {}
                        InspectedFile::Regular { .. } | InspectedFile::Foreign => {
                            tracing::warn!(
                                file_hash,
                                path = %authority.path.display(),
                                "preserving delivered output without exact deletion ownership"
                            );
                            return Ok(());
                        }
                    }
                    let tombstone_id = Uuid::new_v4();
                    let tombstone_path = authority
                        .path
                        .with_file_name(format!(".emulebb-delete-{tombstone_id}.tmp"));
                    self.begin_deletion_tombstone(
                        file_hash,
                        tombstone_id,
                        &authority.path,
                        &tombstone_path,
                        &authority.fingerprint,
                    )
                    .await?
                }
            };
            validate_tombstone(&tombstone)?;
            match tombstone.phase {
                MetadataTransferDeletionTombstonePhase::Prepared => {
                    match self
                        .process_prepared_tombstone(file_hash, &tombstone)
                        .await?
                    {
                        PreparedCleanupOutcome::Complete => return Ok(()),
                        PreparedCleanupOutcome::RetryWithNewTombstone => continue,
                    }
                }
                MetadataTransferDeletionTombstonePhase::Moved => {
                    return reap_moved_tombstone(&tombstone).await;
                }
            }
        }
        anyhow::bail!("failed to allocate a collision-free deletion tombstone for {file_hash}")
    }

    async fn process_prepared_tombstone(
        &self,
        file_hash: &str,
        tombstone: &MetadataTransferDeletionTombstone,
    ) -> Result<PreparedCleanupOutcome> {
        match inspect_file(&tombstone.original_path).await? {
            InspectedFile::Missing => {
                sync_parent_directory(&tombstone.original_path).await?;
                match inspect_file(&tombstone.tombstone_path).await? {
                    InspectedFile::Missing => {
                        sync_parent_directory(&tombstone.tombstone_path).await?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                    InspectedFile::Regular { fingerprint, .. }
                        if fingerprint.identity == tombstone.source_fingerprint.identity
                            && fingerprint.size_bytes
                                == tombstone.source_fingerprint.size_bytes =>
                    {
                        anyhow::ensure!(
                            self.mark_deletion_tombstone_moved(
                                file_hash,
                                tombstone.tombstone_id,
                                &fingerprint,
                            )
                            .await?,
                            "deletion tombstone {} disappeared before move committed",
                            tombstone.tombstone_id
                        );
                        reap_moved_tombstone(&MetadataTransferDeletionTombstone {
                            phase: MetadataTransferDeletionTombstonePhase::Moved,
                            moved_fingerprint: Some(fingerprint),
                            ..tombstone.clone()
                        })
                        .await?;
                        Ok(PreparedCleanupOutcome::Complete)
                    }
                    InspectedFile::Regular { .. } | InspectedFile::Foreign => {
                        anyhow::bail!(
                            "deletion tombstone {} contains an unproven object at {}",
                            tombstone.tombstone_id,
                            tombstone.tombstone_path.display()
                        );
                    }
                }
            }
            InspectedFile::Regular { file, fingerprint }
                if fingerprint == tombstone.source_fingerprint =>
            {
                #[cfg(test)]
                run_before_move_hook(
                    file_hash,
                    &tombstone.original_path,
                    &tombstone.tombstone_path,
                );
                match move_path_no_replace(&tombstone.original_path, &tombstone.tombstone_path)
                    .await?
                {
                    NoReplaceMoveOutcome::AlreadyExists => {
                        drop(file);
                        anyhow::ensure!(
                            self.clear_prepared_deletion_tombstone(
                                file_hash,
                                tombstone.tombstone_id,
                            )
                            .await?,
                            "prepared deletion tombstone {} disappeared during collision recovery",
                            tombstone.tombstone_id
                        );
                        Ok(PreparedCleanupOutcome::RetryWithNewTombstone)
                    }
                    NoReplaceMoveOutcome::Moved => {
                        let moved_fingerprint =
                            capture_moved_fingerprint(file, &tombstone.tombstone_path).await?;
                        let Some(moved_fingerprint) = moved_fingerprint else {
                            match move_path_no_replace(
                                &tombstone.tombstone_path,
                                &tombstone.original_path,
                            )
                            .await?
                            {
                                NoReplaceMoveOutcome::Moved => {
                                    anyhow::ensure!(
                                        self.clear_prepared_deletion_tombstone(
                                            file_hash,
                                            tombstone.tombstone_id,
                                        )
                                        .await?,
                                        "prepared deletion tombstone {} disappeared after restoration",
                                        tombstone.tombstone_id
                                    );
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
                        anyhow::ensure!(
                            self.mark_deletion_tombstone_moved(
                                file_hash,
                                tombstone.tombstone_id,
                                &moved_fingerprint,
                            )
                            .await?,
                            "deletion tombstone {} disappeared before move committed",
                            tombstone.tombstone_id
                        );
                        reap_moved_tombstone(&MetadataTransferDeletionTombstone {
                            phase: MetadataTransferDeletionTombstonePhase::Moved,
                            moved_fingerprint: Some(moved_fingerprint),
                            ..tombstone.clone()
                        })
                        .await?;
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
                anyhow::ensure!(
                    self.clear_prepared_deletion_tombstone(file_hash, tombstone.tombstone_id)
                        .await?,
                    "prepared deletion tombstone {} disappeared while preserving replacement",
                    tombstone.tombstone_id
                );
                Ok(PreparedCleanupOutcome::Complete)
            }
        }
    }

    async fn begin_deletion_tombstone(
        &self,
        file_hash: &str,
        tombstone_id: Uuid,
        original_path: &Path,
        tombstone_path: &Path,
        source_fingerprint: &NativeFileFingerprint,
    ) -> Result<MetadataTransferDeletionTombstone> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        let original_path = original_path.to_owned();
        let tombstone_path = tombstone_path.to_owned();
        let source_fingerprint = source_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            metadata.begin_transfer_deletion_tombstone(
                &file_hash,
                tombstone_id,
                &original_path,
                &tombstone_path,
                &source_fingerprint,
            )
        })
        .await
        .context("ED2K deletion-tombstone prepare task panicked")?
    }

    async fn deletion_tombstone(
        &self,
        file_hash: &str,
    ) -> Result<Option<MetadataTransferDeletionTombstone>> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        tokio::task::spawn_blocking(move || {
            metadata.transfer_deletion_tombstone_by_hash(&file_hash)
        })
        .await
        .context("ED2K deletion-tombstone load task panicked")?
    }

    async fn mark_deletion_tombstone_moved(
        &self,
        file_hash: &str,
        tombstone_id: Uuid,
        moved_fingerprint: &NativeFileFingerprint,
    ) -> Result<bool> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        let moved_fingerprint = moved_fingerprint.clone();
        tokio::task::spawn_blocking(move || {
            metadata.mark_transfer_deletion_tombstone_moved(
                &file_hash,
                tombstone_id,
                &moved_fingerprint,
            )
        })
        .await
        .context("ED2K deletion-tombstone move task panicked")?
    }

    async fn clear_prepared_deletion_tombstone(
        &self,
        file_hash: &str,
        tombstone_id: Uuid,
    ) -> Result<bool> {
        let metadata = self.metadata.clone();
        let file_hash = file_hash.to_owned();
        tokio::task::spawn_blocking(move || {
            metadata.clear_prepared_transfer_deletion_tombstone(&file_hash, tombstone_id)
        })
        .await
        .context("ED2K deletion-tombstone clear task panicked")?
    }
}

#[cfg(test)]
type BeforeMoveHook = Box<dyn FnOnce(&Path, &Path) + Send>;

#[cfg(test)]
fn before_move_hooks() -> &'static Mutex<HashMap<String, BeforeMoveHook>> {
    static HOOKS: OnceLock<Mutex<HashMap<String, BeforeMoveHook>>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(super) fn set_before_move_hook(file_hash: &str, hook: BeforeMoveHook) {
    before_move_hooks()
        .lock()
        .expect("deletion before-move hook mutex poisoned")
        .insert(file_hash.to_owned(), hook);
}

#[cfg(test)]
fn run_before_move_hook(file_hash: &str, original_path: &Path, tombstone_path: &Path) {
    let hook = before_move_hooks()
        .lock()
        .expect("deletion before-move hook mutex poisoned")
        .remove(file_hash);
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

async fn reap_moved_tombstone(tombstone: &MetadataTransferDeletionTombstone) -> Result<()> {
    let moved_fingerprint = tombstone.moved_fingerprint.as_ref().with_context(|| {
        format!(
            "moved deletion tombstone {} has no moved identity",
            tombstone.tombstone_id
        )
    })?;
    match inspect_file(&tombstone.tombstone_path).await? {
        InspectedFile::Missing => sync_parent_directory(&tombstone.tombstone_path).await,
        InspectedFile::Regular { fingerprint, .. } if fingerprint == *moved_fingerprint => {
            anyhow::ensure!(
                remove_file_if_fingerprint_matches(&tombstone.tombstone_path, moved_fingerprint,)
                    .await?,
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

async fn inspect_file(path: &Path) -> Result<InspectedFile> {
    let path = long_path(path);
    tokio::task::spawn_blocking(move || -> Result<InspectedFile> {
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
        let Some(fingerprint) =
            super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
        else {
            return Ok(InspectedFile::Foreign);
        };
        if super::ingest::native_file_fingerprint(&path).as_ref() != Some(&fingerprint) {
            return Ok(InspectedFile::Foreign);
        }
        Ok(InspectedFile::Regular { file, fingerprint })
    })
    .await
    .context("deletion path inspection task failed")?
}

async fn capture_moved_fingerprint(
    file: File,
    tombstone_path: &Path,
) -> Result<Option<NativeFileFingerprint>> {
    let tombstone_path = long_path(tombstone_path);
    tokio::task::spawn_blocking(move || -> Result<Option<NativeFileFingerprint>> {
        let metadata = file.metadata()?;
        let Some(fingerprint) =
            super::ingest::native_file_fingerprint_from_handle(&file, &metadata)
        else {
            return Ok(None);
        };
        Ok(
            (super::ingest::native_file_fingerprint(&tombstone_path).as_ref()
                == Some(&fingerprint))
            .then_some(fingerprint),
        )
    })
    .await
    .context("deletion tombstone fingerprint task failed")?
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
