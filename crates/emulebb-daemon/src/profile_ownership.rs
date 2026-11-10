//! OS-backed ownership of a writable profile, retained by all metadata handles.

use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail, ensure};

const PROFILE_LEASE_FILE: &str = ".emulebb-profile.lock";

/// An opaque, cloneable lease for one physical profile directory.
///
/// The persistent empty file is a lock target, not an ownership marker. Never
/// remove it on release: the operating system releases ownership when the last
/// handle closes, including after process death. Locks must be supported by the
/// selected filesystem; an unsupported/failed lock is an error, never a bypass.
#[derive(Debug, Clone)]
pub struct ProfileLease {
    canonical_profile: PathBuf,
    file: Arc<File>,
}

impl ProfileLease {
    pub(crate) fn acquire(profile: &Path, create_if_missing: bool) -> Result<Self> {
        if create_if_missing {
            super::create_private_profile_dir(profile)?;
        }
        let canonical_profile = fs::canonicalize(profile)
            .with_context(|| format!("failed to resolve writable profile {}", profile.display()))?;
        ensure!(
            canonical_profile.is_dir(),
            "profile is not a directory: {}",
            profile.display()
        );
        let lock_path = canonical_profile.join(PROFILE_LEASE_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // WHY: sharing reads/writes lets contenders reach the OS lock;
            // withholding FILE_SHARE_DELETE prevents replacing the live target.
            const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;
            options.share_mode(FILE_SHARE_READ_WRITE);
        }
        let file = options.open(&lock_path).with_context(|| {
            format!(
                "failed to open ownership lock for profile {}; check profile permissions and filesystem locking support",
                profile.display()
            )
        })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { canonical_profile, file: Arc::new(file) }),
            Err(TryLockError::WouldBlock) => bail!(
                "profile is already in use: {}; stop its daemon or offline command before retrying",
                profile.display()
            ),
            Err(TryLockError::Error(error)) => Err(error).with_context(|| {
                format!(
                    "failed to acquire exclusive ownership of profile {}; check permissions and use a filesystem supporting OS file locks",
                    profile.display()
                )
            }),
        }
    }

    pub(crate) fn ensure_profile(&self, profile: &Path) -> Result<()> {
        let canonical = fs::canonicalize(profile)
            .with_context(|| format!("failed to resolve owned profile {}", profile.display()))?;
        ensure!(
            canonical == self.canonical_profile,
            "profile directory changed after ownership was acquired; load the selected profile before writing it"
        );
        Ok(())
    }

    pub(crate) fn file(&self) -> Arc<File> {
        Arc::clone(&self.file)
    }
}
