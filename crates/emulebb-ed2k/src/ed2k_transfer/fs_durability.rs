use std::{io, path::Path};

use anyhow::{Context, Result};

#[cfg(windows)]
use crate::long_path::long_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoReplaceMoveOutcome {
    Moved,
    AlreadyExists,
}

/// Only the rename syscall itself may trigger the direct-copy publication path.
#[derive(Debug)]
pub(super) struct AtomicMoveUnsupported(io::Error);

impl std::fmt::Display for AtomicMoveUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for AtomicMoveUnsupported {}

#[cfg(test)]
pub(super) async fn move_path_no_replace(
    source: &Path,
    destination: &Path,
) -> Result<NoReplaceMoveOutcome> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    tokio::task::spawn_blocking(move || move_path_no_replace_retained(&source, &destination))
        .await
        .context("no-replace move task failed")?
}

/// Run inside an already retained blocking I/O owner, without spawning a second
/// untracked operation. Unsupported no-replace rename stays an explicit failure.
pub(super) fn move_path_no_replace_retained(
    source: &Path,
    destination: &Path,
) -> Result<NoReplaceMoveOutcome> {
    #[cfg(test)]
    if forced_unsupported_moves()
        .lock()
        .unwrap()
        .remove(&crate::long_path::long_path(destination))
    {
        return Err(AtomicMoveUnsupported(io::Error::new(
            io::ErrorKind::Unsupported,
            "forced unsupported rename",
        ))
        .into());
    }
    let outcome = match move_path_no_replace_blocking(source, destination) {
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            return Err(AtomicMoveUnsupported(error).into());
        }
        other => other?,
    };
    if outcome == NoReplaceMoveOutcome::Moved {
        #[cfg(test)]
        if forced_parent_sync_failures()
            .lock()
            .unwrap()
            .remove(&crate::long_path::long_path(destination))
        {
            return Err(io::Error::other("forced parent sync failure after rename").into());
        }
        sync_delivery_parent_retained(destination)?;
    }
    Ok(outcome)
}

#[cfg(test)]
fn forced_unsupported_moves()
-> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static PATHS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    > = std::sync::OnceLock::new();
    PATHS.get_or_init(Default::default)
}

#[cfg(test)]
pub(super) fn force_unsupported_move(path: &Path) {
    forced_unsupported_moves()
        .lock()
        .unwrap()
        .insert(crate::long_path::long_path(path));
}

#[cfg(test)]
fn forced_parent_sync_failures()
-> &'static std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> {
    static PATHS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    > = std::sync::OnceLock::new();
    PATHS.get_or_init(Default::default)
}

#[cfg(test)]
pub(super) fn force_parent_sync_failure(path: &Path) {
    forced_parent_sync_failures()
        .lock()
        .unwrap()
        .insert(crate::long_path::long_path(path));
}

pub(super) async fn sync_parent_directory(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_parent_directory_retained(&path))
        .await
        .context("directory sync task failed")?
}

pub(super) async fn sync_delivery_parent(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_delivery_parent_retained(&path))
        .await
        .context("delivery parent sync task failed")?
}

pub(super) fn sync_delivery_parent_retained(path: &Path) -> Result<()> {
    // WHY: Publication changes the exact parent, even when it is reached
    // through a directory symlink. Syncing an ancestor would miss that entry.
    let parent = path
        .parent()
        .context("delivery path has no parent directory")?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    sync_directory(parent)
        .with_context(|| format!("failed to sync delivery parent {}", parent.display()))
}

/// The same nearest-existing-parent durability rule for retained blocking units.
pub(super) fn sync_parent_directory_retained(path: &Path) -> Result<()> {
    let mut parent = path
        .parent()
        .with_context(|| format!("path {} has no parent directory", path.display()))?
        .to_path_buf();
    loop {
        match parent.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_dir() => match sync_directory(&parent) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        anyhow::ensure!(
            parent.pop(),
            "no existing parent directory for {}",
            path.display()
        );
    }
}

#[cfg(unix)]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(path)?
        .sync_all()
}

#[cfg(not(any(unix, windows)))]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(long_path(path))?
        .sync_all()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn move_path_no_replace_blocking(
    source: &Path,
    destination: &Path,
) -> io::Result<NoReplaceMoveOutcome> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};

    // WHY: Android is a separate Rust target but uses Linux's atomic no-replace
    // rename too. Rustix also handles musl builds lacking the libc wrapper;
    // never substitute a check-then-rename that could overwrite another file.
    let error = match renameat_with(CWD, source, CWD, destination, RenameFlags::NOREPLACE) {
        Ok(()) => return Ok(NoReplaceMoveOutcome::Moved),
        Err(error) => io::Error::from(error),
    };
    match error.raw_os_error() {
        Some(libc::EEXIST) => Ok(NoReplaceMoveOutcome::AlreadyExists),
        Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("filesystem does not support atomic no-replace rename: {error}"),
        )),
        _ => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn move_path_no_replace_blocking(
    source: &Path,
    destination: &Path,
) -> io::Result<NoReplaceMoveOutcome> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "source path contains NUL"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination path contains NUL")
    })?;
    // SAFETY: both paths are NUL-terminated and valid for the duration of the
    // call. RENAME_EXCL makes publication atomic without clobbering.
    let result =
        unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        return Ok(NoReplaceMoveOutcome::Moved);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EEXIST) => Ok(NoReplaceMoveOutcome::AlreadyExists),
        Some(libc::ENOTSUP) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("filesystem does not support atomic no-replace rename: {error}"),
        )),
        _ => Err(error),
    }
}

#[cfg(windows)]
fn move_path_no_replace_blocking(
    source: &Path,
    destination: &Path,
) -> io::Result<NoReplaceMoveOutcome> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::{
        Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS},
        Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW},
    };

    let source = long_path(source)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = long_path(destination)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: both buffers are NUL-terminated UTF-16 paths and remain alive
    // for the call. Omitting REPLACE_EXISTING preserves no-clobber semantics.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved != 0 {
        return Ok(NoReplaceMoveOutcome::Moved);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32 => {
            Ok(NoReplaceMoveOutcome::AlreadyExists)
        }
        _ => Err(error),
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn move_path_no_replace_blocking(
    _source: &Path,
    _destination: &Path,
) -> io::Result<NoReplaceMoveOutcome> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace file moves are unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn syncs_nearest_existing_ancestor_when_parent_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let missing_path = root.path().join("removed-parent").join("payload.bin");

        sync_parent_directory(&missing_path).await.unwrap();
    }

    #[tokio::test]
    async fn no_replace_move_publishes_once_without_clobbering() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.tmp");
        let destination = root.path().join("destination.bin");
        std::fs::write(&source, b"first").unwrap();

        assert_eq!(
            move_path_no_replace(&source, &destination).await.unwrap(),
            NoReplaceMoveOutcome::Moved
        );
        assert!(!source.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"first");

        std::fs::write(&source, b"second").unwrap();
        assert_eq!(
            move_path_no_replace(&source, &destination).await.unwrap(),
            NoReplaceMoveOutcome::AlreadyExists
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"second");
        assert_eq!(std::fs::read(&destination).unwrap(), b"first");
    }
}
