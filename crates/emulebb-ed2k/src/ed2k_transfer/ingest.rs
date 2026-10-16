//! Local payload ingest into the ED2K transfer store.

use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use emulebb_metadata::{
    MetadataImportedKnownFileEntry, NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp,
    NativePath,
};

use crate::long_path::long_path;

use super::hashset::build_md4_and_aich_hashsets_from_reader_with_progress;
use super::manifest::{piece_count, rebuild_verified_ranges};
use super::{
    Ed2kLocalIngestSummary, Ed2kPieceState, Ed2kResumeManifest, Ed2kTransferRuntime,
    Ed2kTransferState, expected_piece_length, new_transfer_job,
};

/// Hashing stage reported while a local payload is ingested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalIngestProgressStage {
    Md4,
    Aich,
}

impl LocalIngestProgressStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md4 => "md4",
            Self::Aich => "aich",
        }
    }
}

/// Read progress emitted by the blocking local ingest hash workers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalIngestProgressEvent {
    pub stage: LocalIngestProgressStage,
    pub stage_bytes_read: u64,
    pub stage_bytes_total: u64,
    pub file_bytes_read: u64,
    pub file_bytes_total: u64,
}

pub type LocalIngestProgressObserver = Arc<dyn Fn(LocalIngestProgressEvent) + Send + Sync>;

impl Ed2kTransferRuntime {
    /// Copy a local payload into the canonical ED2K transfer store and expose
    /// it as a fully verified shared file.
    pub async fn ingest_local_file(
        &self,
        source_path: &Path,
        display_name: &str,
    ) -> Result<Ed2kLocalIngestSummary> {
        self.ingest_local_file_inner(source_path, display_name, None)
            .await
    }

    pub async fn ingest_local_file_with_progress(
        &self,
        source_path: &Path,
        display_name: &str,
        observer: LocalIngestProgressObserver,
    ) -> Result<Ed2kLocalIngestSummary> {
        self.ingest_local_file_inner(source_path, display_name, Some(observer))
            .await
    }

    async fn ingest_local_file_inner(
        &self,
        source_path: &Path,
        display_name: &str,
        observer: Option<LocalIngestProgressObserver>,
    ) -> Result<Ed2kLocalIngestSummary> {
        let display_name = display_name.trim();
        if display_name.is_empty() {
            anyhow::bail!("local ED2K ingest requires a non-empty canonical name");
        }
        // Operator-facing shared-file ingest boundary: normalize the operator's
        // source path to the long-path (`\\?\`) form before it is opened/hashed,
        // so a shared file under a deep operator tree (beyond the legacy
        // MAX_PATH limit) can still be read for ingest. The internal piece-store
        // destination (`transfer_dir`/`pieces.bin`) below is deliberately left
        // short-path. (Operator-rule scope: shared-directory trees -- see
        // long_path.rs.)
        //
        // WHY (no canonicalize): we used to `canonicalize()` the verbatim path
        // here, but that silently dropped shared files whose paths carry
        // non-ASCII characters (accents/CJK), brackets, or live in subfolders.
        // On Windows `canonicalize` resolves via `GetFinalPathNameByHandle` and
        // returns an OS-re-normalized verbatim (`\\?\`) path; a verbatim path is
        // NOT re-normalized by the OS on later access, so when the canonical
        // Unicode form differs from the form the directory walk produced, the
        // returned path no longer resolves and the subsequent stat fails
        // ("failed to stat local ingest source"), skipping the file. The walk
        // (`collect_shared_directory_files`) already hands us an absolute
        // verbatim path read straight from the on-disk directory entries, so we
        // stat/hash it directly and let the manifest record that same exact path
        // for in-place upload serving -- no canonicalize round-trip is needed.
        let source_path = long_path(source_path);
        // Hash OFF the manifest lock AND off the async runtime. MD4/AICH hash
        // the whole (potentially many-GB) file with blocking `std::fs`,
        // which on a slow disk takes far longer than any HTTP timeout. Holding
        // the manifest lock across that froze every REST read (they funneled through
        // `manifests()`), and running the blocking hash inline starved a tokio
        // worker. We therefore compute both hashsets in one sequential read under
        // `spawn_blocking` with no lock held, and only take the manifest lock for the
        // short write below.
        let hash_path = source_path.clone();
        let hash_observer = observer.clone();
        let (hashsets, source_fingerprint) = tokio::task::spawn_blocking(move || {
            let mut file = open_ingest_file_without_follow(&hash_path).with_context(|| {
                format!(
                    "failed to open local ingest source without following links {}",
                    hash_path.display()
                )
            })?;
            let opened_metadata = file.metadata().with_context(|| {
                format!(
                    "failed to inspect opened local ingest source {}",
                    hash_path.display()
                )
            })?;
            let source_fingerprint = native_file_fingerprint_from_handle(&file, &opened_metadata)
                .with_context(|| {
                format!(
                    "local ingest source is not a regular file with stable native identity {}",
                    hash_path.display()
                )
            })?;
            let hash_len = source_fingerprint.size_bytes;
            if hash_len == 0 {
                anyhow::bail!("local ED2K ingest does not support zero-sized payloads");
            }
            let mut bytes_read_total = 0u64;
            let progress_observer = hash_observer.clone();
            let mut progress = move |read_delta: u64| {
                bytes_read_total = bytes_read_total.saturating_add(read_delta);
                if let Some(observer) = progress_observer.as_ref() {
                    observer(LocalIngestProgressEvent {
                        stage: LocalIngestProgressStage::Md4,
                        stage_bytes_read: bytes_read_total,
                        stage_bytes_total: hash_len,
                        file_bytes_read: bytes_read_total,
                        file_bytes_total: hash_len,
                    });
                }
            };
            let hashsets = build_md4_and_aich_hashsets_from_reader_with_progress(
                &mut file,
                hash_len,
                Some(&mut progress),
            )?;
            if let Some(observer) = hash_observer.as_ref() {
                observer(LocalIngestProgressEvent {
                    stage: LocalIngestProgressStage::Aich,
                    stage_bytes_read: hash_len,
                    stage_bytes_total: hash_len,
                    file_bytes_read: hash_len,
                    file_bytes_total: hash_len,
                });
            }
            let final_metadata = file.metadata().with_context(|| {
                format!(
                    "failed to re-inspect opened local ingest source {}",
                    hash_path.display()
                )
            })?;
            let final_fingerprint = native_file_fingerprint_from_handle(&file, &final_metadata)
                .context("opened local ingest source lost regular-file identity while hashing")?;
            if source_fingerprint != final_fingerprint {
                anyhow::bail!(
                    "local ingest source changed while hashing {}",
                    hash_path.display()
                );
            }
            let current_fingerprint = native_file_fingerprint(&hash_path).with_context(|| {
                format!(
                    "local ingest source path no longer names a regular file {}",
                    hash_path.display()
                )
            })?;
            if source_fingerprint != current_fingerprint {
                anyhow::bail!(
                    "local ingest source path was replaced while hashing {}",
                    hash_path.display()
                );
            }
            Ok::<_, anyhow::Error>((hashsets, source_fingerprint))
        })
        .await
        .context("ED2K/AICH hashing task panicked")??;
        let file_hash = hashsets.file_hash;
        let job = new_transfer_job(
            file_hash,
            display_name.to_string(),
            source_fingerprint.size_bytes,
        );
        let transfer_dir = self.transfer_dir(&job.file_hash);
        // Seed the shared, already-complete file IN PLACE: it is served for
        // upload directly from its original on-disk path. We deliberately do NOT
        // copy it into the internal piece store (`transfer_dir/pieces.bin`),
        // which would duplicate the whole (potentially hundreds-of-GB) library
        // on disk, and the manifest records `source_path` so the upload-serving
        // read path resolves to the original file and finished-file delivery
        // skips it (delivery is download-only). The resume manifest lives in
        // SQLite, so no per-hash transfer directory is created for an in-place
        // share. AICH/MD4 are computed straight from the original file in the
        // single read pass above.
        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.delivery_state = super::Ed2kDeliveryState::NotApplicable;
        manifest.source_path = Some(source_path.clone());
        manifest.source_fingerprint = Some(source_fingerprint);
        manifest.completed = true;
        // A share-in-place file belongs in the shared catalog, not the download
        // queue. Persist that state in the initial transaction so callers do not
        // need a second full manifest rewrite merely to hide its transfer row.
        manifest.transfer_row_removed = true;
        manifest.md4_hashset_acquired = true;
        manifest.md4_hashset = hashsets.md4_hashset.iter().map(hex::encode).collect();
        manifest.aich_hashset_acquired = true;
        manifest.aich_root = Some(hex::encode(hashsets.aich_hashset.master_hash));
        manifest.aich_hashset = hashsets
            .aich_hashset
            .part_hashes
            .iter()
            .map(hex::encode)
            .collect();
        manifest.pieces = (0..piece_count(manifest.file_size, manifest.piece_size))
            .map(|piece_index| Ed2kPieceState {
                piece_index,
                state: Ed2kTransferState::Verified,
                bytes_written: expected_piece_length(
                    manifest.file_size,
                    manifest.piece_size,
                    u64::from(piece_index),
                ),
                block_bitmap: None,
                ich_corrupted: false,
            })
            .collect();
        rebuild_verified_ranges(&mut manifest);
        // Only the manifest write needs the manifest lock; held briefly (no hashing
        // under it), so concurrent REST reads of `manifests()` are not starved.
        let _guard = self.lock_manifest(&manifest.file_hash).await;
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        drop(_guard);

        Ok(Ed2kLocalIngestSummary {
            file_hash: manifest.file_hash,
            display_name: manifest.display_name,
            file_size: manifest.file_size,
            md4_hashset_count: manifest.md4_hashset.len(),
            aich_root: manifest.aich_root.unwrap_or_default(),
            aich_hashset_count: manifest.aich_hashset.len(),
            transfer_dir: transfer_dir.display().to_string(),
            source_path: manifest
                .source_path
                .as_deref()
                .map(NativePath::from)
                .map(|path| path.display_path()),
        })
    }

    /// Promote a pathless stock eMule ``known.met`` row after a shared-directory
    /// scan finds a unique file-name/size/mtime identity match.
    pub async fn promote_imported_known_file(
        &self,
        entry: MetadataImportedKnownFileEntry,
        source_path: &Path,
        source_fingerprint: Option<NativeFileFingerprint>,
    ) -> Result<Ed2kLocalIngestSummary> {
        if entry.display_name.trim().is_empty() {
            anyhow::bail!("imported known file requires a non-empty canonical name");
        }
        let source_path = long_path(source_path);
        let job = super::Ed2kTransferJob {
            file_hash: entry.file_hash.clone(),
            display_name: entry.display_name.clone(),
            file_size: entry.file_size,
            piece_size: super::ED2K_PART_SIZE,
        };
        let transfer_dir = self.transfer_dir(&job.file_hash);

        let mut manifest = Ed2kResumeManifest::new(&job);
        manifest.delivery_state = super::Ed2kDeliveryState::NotApplicable;
        manifest.source_path = Some(source_path.clone());
        manifest.source_fingerprint = source_fingerprint;
        manifest.completed = true;
        manifest.transfer_row_removed = true;
        manifest.md4_hashset_acquired = true;
        manifest.md4_hashset = entry.md4_hashset.clone();
        manifest.aich_hashset_acquired = entry.aich_root.is_some();
        manifest.aich_root = entry.aich_root.clone();
        manifest.aich_hashset = entry.aich_hashset.clone();
        manifest.upload_priority = entry.upload_priority.clone();
        manifest.auto_upload_priority = entry.auto_upload_priority;
        manifest.pieces = (0..piece_count(manifest.file_size, manifest.piece_size))
            .map(|piece_index| Ed2kPieceState {
                piece_index,
                state: Ed2kTransferState::Verified,
                bytes_written: expected_piece_length(
                    manifest.file_size,
                    manifest.piece_size,
                    u64::from(piece_index),
                ),
                block_bitmap: None,
                ich_corrupted: false,
            })
            .collect();
        rebuild_verified_ranges(&mut manifest);

        let _guard = self.lock_manifest(&manifest.file_hash).await;
        self.store_manifest_unlocked(&manifest).await?;
        self.upsert_verified_catalog_entry(&manifest).await;
        drop(_guard);

        Ok(Ed2kLocalIngestSummary {
            file_hash: manifest.file_hash,
            display_name: manifest.display_name,
            file_size: manifest.file_size,
            md4_hashset_count: manifest.md4_hashset.len(),
            aich_root: manifest.aich_root.unwrap_or_default(),
            aich_hashset_count: manifest.aich_hashset.len(),
            transfer_dir: transfer_dir.display().to_string(),
            source_path: manifest
                .source_path
                .as_deref()
                .map(NativePath::from)
                .map(|path| path.display_path()),
        })
    }
}

/// Capture the native file identity and full-resolution filesystem timestamps
/// used to decide whether a persisted content hash is still reusable.
pub(crate) fn native_file_fingerprint(source_path: &Path) -> Option<NativeFileFingerprint> {
    let file = open_regular_file_without_follow(source_path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    native_file_fingerprint_from_handle(&file, &opened_metadata)
}

#[cfg(windows)]
fn open_ingest_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_ingest_file_without_follow(path: &Path) -> std::io::Result<File> {
    open_regular_file_without_follow(path)
}

#[cfg(unix)]
fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

pub(crate) fn native_file_fingerprint_from_handle(
    file: &File,
    metadata: &Metadata,
) -> Option<NativeFileFingerprint> {
    if !metadata.file_type().is_file() {
        return None;
    }
    let identity = native_file_identity_from_handle(file, metadata)?;
    let (modified, changed) = native_file_timestamps(metadata)?;
    Some(NativeFileFingerprint {
        identity,
        size_bytes: metadata.len(),
        modified,
        changed,
    })
}

#[cfg(unix)]
fn native_file_identity_from_handle(
    _file: &File,
    metadata: &Metadata,
) -> Option<NativeFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(NativeFileIdentity::Unix {
        device_id: metadata.dev(),
        inode_number: metadata.ino(),
    })
}

#[cfg(windows)]
fn native_file_identity_from_handle(
    file: &File,
    _metadata: &Metadata,
) -> Option<NativeFileIdentity> {
    use std::{
        mem::{MaybeUninit, size_of},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx,
        },
    };

    let handle = file.as_raw_handle() as HANDLE;
    let mut high_resolution = MaybeUninit::<FILE_ID_INFO>::zeroed();
    // SAFETY: `handle` belongs to the borrowed open file and the output buffer
    // has the exact type and size required by `FileIdInfo`.
    let high_resolution_result = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            high_resolution.as_mut_ptr().cast(),
            u32::try_from(size_of::<FILE_ID_INFO>()).ok()?,
        )
    };
    if high_resolution_result != 0 {
        // SAFETY: the successful API call initialized the complete structure.
        let high_resolution = unsafe { high_resolution.assume_init() };
        return Some(NativeFileIdentity::WindowsHighResolution {
            volume_serial_number: high_resolution.VolumeSerialNumber,
            file_id: u128::from_le_bytes(high_resolution.FileId.Identifier),
        });
    }

    let mut low_resolution = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `handle` belongs to the borrowed open file and the output buffer
    // has the exact type required by `GetFileInformationByHandle`.
    if unsafe { GetFileInformationByHandle(handle, low_resolution.as_mut_ptr()) } == 0 {
        return None;
    }
    // SAFETY: the successful API call initialized the complete structure.
    let low_resolution = unsafe { low_resolution.assume_init() };
    Some(NativeFileIdentity::WindowsLowResolution {
        volume_serial_number: low_resolution.dwVolumeSerialNumber,
        file_index: (u64::from(low_resolution.nFileIndexHigh) << 32)
            | u64::from(low_resolution.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn native_file_identity_from_handle(
    _file: &File,
    _metadata: &Metadata,
) -> Option<NativeFileIdentity> {
    None
}

#[cfg(unix)]
fn native_file_timestamps(
    metadata: &Metadata,
) -> Option<(NativeFileTimestamp, Option<NativeFileTimestamp>)> {
    use std::os::unix::fs::MetadataExt;

    Some((
        unix_timestamp(metadata.mtime(), metadata.mtime_nsec())?,
        Some(unix_timestamp(metadata.ctime(), metadata.ctime_nsec())?),
    ))
}

#[cfg(unix)]
fn unix_timestamp(seconds: i64, nanoseconds: i64) -> Option<NativeFileTimestamp> {
    NativeFileTimestamp::new(seconds, u32::try_from(nanoseconds).ok()?)
}

#[cfg(windows)]
fn native_file_timestamps(
    metadata: &Metadata,
) -> Option<(NativeFileTimestamp, Option<NativeFileTimestamp>)> {
    Some((system_time_timestamp(metadata.modified().ok()?)?, None))
}

#[cfg(windows)]
fn system_time_timestamp(timestamp: std::time::SystemTime) -> Option<NativeFileTimestamp> {
    match timestamp.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => NativeFileTimestamp::new(
            i64::try_from(duration.as_secs()).ok()?,
            duration.subsec_nanos(),
        ),
        Err(error) => {
            let duration = error.duration();
            let seconds = i64::try_from(duration.as_secs()).ok()?;
            if duration.subsec_nanos() == 0 {
                NativeFileTimestamp::new(seconds.checked_neg()?, 0)
            } else {
                NativeFileTimestamp::new(
                    seconds.checked_add(1)?.checked_neg()?,
                    1_000_000_000 - duration.subsec_nanos(),
                )
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn native_file_timestamps(
    _metadata: &Metadata,
) -> Option<(NativeFileTimestamp, Option<NativeFileTimestamp>)> {
    None
}

#[cfg(test)]
mod native_file_fingerprint_tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn fingerprint_is_stable_for_the_same_file() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("payload.bin");
        fs::write(&source, b"payload").unwrap();
        let first = native_file_fingerprint(&source).unwrap();
        let second = native_file_fingerprint(&source).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.size_bytes, 7);
    }

    #[test]
    fn replacement_at_the_same_path_gets_a_different_identity() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("payload.bin");
        let retained = temp.path().join("retained.bin");
        fs::write(&source, b"same-size").unwrap();
        let original = native_file_fingerprint(&source).unwrap();
        fs::rename(&source, &retained).unwrap();
        fs::write(&source, b"different").unwrap();
        let replacement = native_file_fingerprint(&source).unwrap();

        assert_eq!(original.size_bytes, replacement.size_bytes);
        assert_ne!(original.identity, replacement.identity);
        assert!(!original.safely_matches(&replacement));
    }

    #[test]
    fn fingerprint_rejects_non_file_occupant() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("payload.bin");
        fs::create_dir(&source).unwrap();

        assert!(native_file_fingerprint(&source).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn fingerprint_does_not_follow_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let target = temp.path().join("target.bin");
        let source = temp.path().join("payload.bin");
        fs::write(&target, b"payload").unwrap();
        symlink(&target, &source).unwrap();

        assert!(native_file_fingerprint(&source).is_none());
    }
}
