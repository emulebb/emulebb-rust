//! Local payload ingest into the ED2K transfer store.

use std::fs::{File, Metadata, OpenOptions};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use emulebb_metadata::{
    MetadataVerifiedLocalContent, NativeFileFingerprint, NativeFileIdentity, NativeFileTimestamp,
    NativePath,
};

use super::hashset::build_md4_and_aich_hashsets_from_reader_with_progress;
use super::{ED2K_PART_SIZE, Ed2kLocalIngestSummary, Ed2kTransferRuntime};

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

pub(super) fn encode_hashset<const N: usize>(hashes: &[[u8; N]]) -> Vec<String> {
    let mut encoded = Vec::with_capacity(hashes.len());
    for hash in hashes {
        encoded.push(hex::encode(hash));
    }
    encoded
}

/// Internal publication intent supplied by Core before owned ingestion begins.
#[derive(Default)]
pub struct LocalIngestOptions<'a> {
    pub roots: &'a [emulebb_metadata::MetadataIngestRoot],
    pub index_type: Option<&'a str>,
}

pub(super) struct PreparedLocalIngest {
    pub content: MetadataVerifiedLocalContent,
    pub recovery: emulebb_metadata::MetadataAichRecoverySet,
    pub media: emulebb_metadata::MetadataTransferMediaMetadata,
    pub summary: Ed2kLocalIngestSummary,
}

impl Ed2kTransferRuntime {
    /// Hash and register local content; root membership remains independent.
    pub async fn ingest_local_file(
        &self,
        source_path: &Path,
        display_name: &str,
    ) -> Result<Ed2kLocalIngestSummary> {
        self.ingest_local_file_owned(
            source_path,
            display_name,
            None,
            LocalIngestOptions::default(),
        )
        .await
    }

    pub async fn ingest_local_file_with_progress(
        &self,
        source_path: &Path,
        display_name: &str,
        observer: LocalIngestProgressObserver,
    ) -> Result<Ed2kLocalIngestSummary> {
        self.ingest_local_file_owned(
            source_path,
            display_name,
            Some(observer),
            LocalIngestOptions::default(),
        )
        .await
    }

    /// One retained blocking unit owns preparation, SQL, and publication after
    /// admission. Dropping this future cannot detach a metadata-store owner.
    pub async fn ingest_local_file_owned(
        &self,
        source_path: &Path,
        display_name: &str,
        observer: Option<LocalIngestProgressObserver>,
        options: LocalIngestOptions<'_>,
    ) -> Result<Ed2kLocalIngestSummary> {
        let display_name = display_name.trim();
        anyhow::ensure!(
            !display_name.is_empty(),
            "local ED2K ingest requires a non-empty canonical name"
        );
        loop {
            match self.local_mutations.submit_ingest(
                self,
                source_path,
                display_name,
                observer.as_ref(),
                &options,
            ) {
                Ok(receive) => {
                    return receive
                        .await
                        .map_err(|_| super::LocalMutationError::Unknown)?;
                }
                Err(error)
                    if matches!(
                        error.downcast_ref::<super::LocalMutationError>(),
                        Some(super::LocalMutationError::Busy)
                    ) =>
                {
                    // No manifest/stripe guard or cloned request is held while
                    // waiting. In particular a second disk must not lose work.
                    self.local_mutations.wait_for_completion().await?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Runs only inside the registry's retained blocking unit. The representation
/// lease covers hash buffers; Symphonia's aggregate parser allocation is not
/// bounded by that lease. Its actual execution is nevertheless joined at drain.
pub(super) fn prepare_local_ingest(
    source_path: &Path,
    display_name: &str,
    observer: Option<LocalIngestProgressObserver>,
) -> Result<PreparedLocalIngest> {
    let mut file = open_stable_read_file_without_follow(source_path).with_context(|| {
        format!(
            "failed to open local ingest source without following links {}",
            source_path.display()
        )
    })?;
    let opened_metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened local ingest source {}",
            source_path.display()
        )
    })?;
    let source_fingerprint = native_file_fingerprint_from_handle(&file, &opened_metadata)
        .with_context(|| {
            format!(
                "local ingest source is not a regular file with stable native identity {}",
                source_path.display()
            )
        })?;
    let hash_len = source_fingerprint.size_bytes;
    if hash_len == 0 {
        anyhow::bail!("local ED2K ingest does not support zero-sized payloads");
    }
    // WHY: the prepared representation lease is sized to the existing 256 GiB
    // recovery geometry. Reject unsupported inputs before allocating part
    // specifications or reading even the first payload block.
    anyhow::ensure!(
        hash_len <= 0x4000000000,
        "local ED2K ingest exceeds the supported 256 GiB size"
    );
    let mut bytes_read_total = 0u64;
    let progress_observer = observer.clone();
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
    if let Some(observer) = observer.as_ref() {
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
            source_path.display()
        )
    })?;
    let final_fingerprint = native_file_fingerprint_from_handle(&file, &final_metadata)
        .context("opened local ingest source lost regular-file identity while hashing")?;
    if source_fingerprint != final_fingerprint {
        anyhow::bail!(
            "local ingest source changed while hashing {}",
            source_path.display()
        );
    }
    let current_fingerprint = native_file_fingerprint(source_path).with_context(|| {
        format!(
            "local ingest source path no longer names a regular file {}",
            source_path.display()
        )
    })?;
    if source_fingerprint != current_fingerprint {
        anyhow::bail!(
            "local ingest source path was replaced while hashing {}",
            source_path.display()
        );
    }

    let file_hash = hashsets.file_hash.to_string();
    let aich_root = hex::encode(hashsets.aich_hashset.master_hash);
    let md4_hashset_count = hashsets.md4_hashset.len();
    let aich_hashset_count = hashsets.aich_hashset.part_hashes.len();
    let content = MetadataVerifiedLocalContent {
        file_hash: file_hash.clone(),
        display_name: display_name.to_owned(),
        file_size: source_fingerprint.size_bytes,
        part_size: ED2K_PART_SIZE,
        md4_hashset: encode_hashset(&hashsets.md4_hashset),
        aich_root: Some(aich_root.clone()),
        aich_hashset: encode_hashset(&hashsets.aich_hashset.part_hashes),
        path: source_path.to_path_buf(),
        fingerprint: source_fingerprint.clone(),
        upload_priority: "normal".to_owned(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
    };
    let recovery = emulebb_metadata::MetadataAichRecoverySet {
        root: hashsets.aich_hashset.master_hash,
        size: content.file_size,
        parts: hashsets.recovery_parts,
        part_roots: if hashsets.aich_hashset.part_hashes.is_empty() {
            vec![hashsets.aich_hashset.master_hash]
        } else {
            hashsets.aich_hashset.part_hashes
        },
    };
    // Preserve all existing format/fallback readers. Nothing holds publication
    // locks while the parser owns its format-specific allocations.
    let media = super::media_metadata::extract_media_metadata(source_path, display_name);
    anyhow::ensure!(
        native_file_fingerprint(source_path).as_ref() == Some(&source_fingerprint),
        "local ingest source changed during media preparation"
    );
    let media = super::transfer_sql::media_to_metadata(
        &media,
        super::transfer_sql::MEDIA_METADATA_EXTRACTOR_VERSION,
    );
    Ok(PreparedLocalIngest {
        content,
        recovery,
        media,
        summary: Ed2kLocalIngestSummary {
            file_hash,
            display_name: display_name.to_owned(),
            file_size: source_fingerprint.size_bytes,
            md4_hashset_count,
            aich_root,
            aich_hashset_count,
            path: NativePath::from(source_path).display_path(),
        },
    })
}

/// Capture the native file identity and full-resolution filesystem timestamps
/// used to decide whether a persisted content hash is still reusable.
pub(crate) fn native_file_fingerprint(source_path: &Path) -> Option<NativeFileFingerprint> {
    let file = open_regular_file_without_follow(source_path).ok()?;
    let opened_metadata = file.metadata().ok()?;
    native_file_fingerprint_from_handle(&file, &opened_metadata)
}

pub(crate) fn native_directory_identity(path: &Path) -> Option<NativeFileIdentity> {
    let directory = open_directory_without_follow(path).ok()?;
    let metadata = directory.metadata().ok()?;
    if !metadata.file_type().is_dir() {
        return None;
    }
    native_file_identity_from_handle(&directory, &metadata)
}

#[cfg(unix)]
fn open_directory_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
}

#[cfg(windows)]
fn open_directory_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_directory_without_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
pub(crate) fn open_stable_read_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
pub(crate) fn open_stable_read_file_without_follow(path: &Path) -> std::io::Result<File> {
    open_regular_file_without_follow(path)
}

#[cfg(unix)]
pub(crate) fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
pub(crate) fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_regular_file_without_follow(path: &Path) -> std::io::Result<File> {
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
    let (modified, changed) = native_file_timestamps_from_handle(file, metadata)?;
    Some(NativeFileFingerprint {
        identity,
        size_bytes: metadata.len(),
        modified,
        changed,
    })
}

#[cfg(unix)]
pub(crate) fn native_file_fingerprint_from_unix_metadata(
    metadata: &Metadata,
) -> Option<NativeFileFingerprint> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file() {
        return None;
    }
    let identity = NativeFileIdentity::Unix {
        device_id: metadata.dev(),
        inode_number: metadata.ino(),
    };
    let (modified, changed) = native_file_timestamps_from_unix_metadata(metadata)?;
    Some(NativeFileFingerprint {
        identity,
        size_bytes: metadata.len(),
        modified,
        changed,
    })
}

#[cfg(unix)]
pub(crate) fn native_file_identity_from_handle(
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
pub(crate) fn native_file_identity_from_handle(
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
pub(crate) fn native_file_identity_from_handle(
    _file: &File,
    _metadata: &Metadata,
) -> Option<NativeFileIdentity> {
    None
}

#[cfg(unix)]
fn native_file_timestamps_from_handle(
    _file: &File,
    metadata: &Metadata,
) -> Option<(NativeFileTimestamp, Option<NativeFileTimestamp>)> {
    native_file_timestamps_from_unix_metadata(metadata)
}

#[cfg(unix)]
fn native_file_timestamps_from_unix_metadata(
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
fn native_file_timestamps_from_handle(
    file: &File,
    _metadata: &Metadata,
) -> Option<(NativeFileTimestamp, Option<NativeFileTimestamp>)> {
    use std::{
        mem::{MaybeUninit, size_of},
        os::windows::io::AsRawHandle,
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx},
    };

    let handle = file.as_raw_handle() as HANDLE;
    let mut basic_info = MaybeUninit::<FILE_BASIC_INFO>::zeroed();
    // SAFETY: `handle` belongs to the borrowed open file and the output buffer
    // has the exact type and size required by `FileBasicInfo`.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            basic_info.as_mut_ptr().cast(),
            u32::try_from(size_of::<FILE_BASIC_INFO>()).ok()?,
        )
    } == 0
    {
        return None;
    }
    // SAFETY: the successful API call initialized the complete structure.
    let basic_info = unsafe { basic_info.assume_init() };
    Some((
        windows_file_time_timestamp(basic_info.LastWriteTime)?,
        Some(windows_file_time_timestamp(basic_info.ChangeTime)?),
    ))
}

#[cfg(windows)]
fn windows_file_time_timestamp(file_time_100ns: i64) -> Option<NativeFileTimestamp> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i128 = 10_000_000;

    let unix_ticks = i128::from(file_time_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS;
    let seconds = unix_ticks.div_euclid(TICKS_PER_SECOND);
    let nanoseconds = unix_ticks.rem_euclid(TICKS_PER_SECOND) * 100;
    NativeFileTimestamp::new(
        i64::try_from(seconds).ok()?,
        u32::try_from(nanoseconds).ok()?,
    )
}

#[cfg(not(any(unix, windows)))]
fn native_file_timestamps_from_handle(
    _file: &File,
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
        #[cfg(windows)]
        assert!(first.changed.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn same_size_rewrite_with_restored_mtime_changes_windows_fingerprint() {
        use std::fs::FileTimes;
        use std::thread;
        use std::time::Duration;

        let temp = tempdir().unwrap();
        let source = temp.path().join("payload.bin");
        fs::write(&source, b"original").unwrap();
        let original_modified = fs::metadata(&source).unwrap().modified().unwrap();
        let original = native_file_fingerprint(&source).unwrap();

        thread::sleep(Duration::from_millis(20));
        fs::write(&source, b"rewrote!").unwrap();
        File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_times(FileTimes::new().set_modified(original_modified))
            .unwrap();
        let rewritten = native_file_fingerprint(&source).unwrap();

        assert_eq!(original.size_bytes, rewritten.size_bytes);
        assert_eq!(original.modified, rewritten.modified);
        assert_ne!(original.changed, rewritten.changed);
        assert!(!original.safely_matches(&rewritten));
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_time_conversion_preserves_whole_seconds_and_pre_epoch_values() {
        const WINDOWS_TO_UNIX_EPOCH_100NS: i64 = 116_444_736_000_000_000;

        assert_eq!(
            windows_file_time_timestamp(WINDOWS_TO_UNIX_EPOCH_100NS),
            NativeFileTimestamp::new(0, 0)
        );
        assert_eq!(
            windows_file_time_timestamp(WINDOWS_TO_UNIX_EPOCH_100NS - 1),
            NativeFileTimestamp::new(-1, 999_999_900)
        );
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
