use std::{io, path::Path};

use anyhow::{Context, Result};

#[cfg(windows)]
use crate::long_path::long_path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoReplaceMoveOutcome {
    Moved,
    AlreadyExists,
}

pub(super) async fn move_path_no_replace(
    source: &Path,
    destination: &Path,
) -> Result<NoReplaceMoveOutcome> {
    let source = source.to_path_buf();
    let destination = destination.to_path_buf();
    let sync_path = destination.clone();
    let outcome =
        tokio::task::spawn_blocking(move || move_path_no_replace_blocking(&source, &destination))
            .await
            .context("no-replace move task failed")??;
    if outcome == NoReplaceMoveOutcome::Moved {
        sync_parent_directory(&sync_path).await?;
    }
    Ok(outcome)
}

pub(super) async fn sync_file_for_publish(file: std::fs::File) -> Result<()> {
    tokio::task::spawn_blocking(move || sync_file_for_publish_blocking(&file))
        .await
        .context("file durability task failed")??;
    Ok(())
}

pub(super) async fn sync_parent_directory(path: &Path) -> Result<()> {
    let mut parent = path
        .parent()
        .with_context(|| format!("path {} has no parent directory", path.display()))?
        .to_path_buf();
    let display_path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
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
                display_path.display()
            );
        }
    })
    .await
    .context("directory sync task failed")??;
    Ok(())
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> io::Result<()> {
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

#[cfg(target_os = "macos")]
fn sync_file_for_publish_blocking(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    file.sync_all()?;
    // SAFETY: the descriptor belongs to `file` and remains valid for the call.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn sync_file_for_publish_blocking(file: &std::fs::File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(target_os = "linux")]
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
    // call. RENAME_NOREPLACE makes publication atomic without clobbering.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(NoReplaceMoveOutcome::Moved);
    }
    let error = io::Error::last_os_error();
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

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
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
