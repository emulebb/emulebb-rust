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
    directory: PathBuf,
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
        #[cfg(windows)]
        let canonical_profile = short_profile_directory(&canonical_profile).with_context(|| {
            format!(
                "failed to resolve short-path profile directory {}",
                profile.display()
            )
        })?;
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
            Ok(()) => Ok(Self { directory: canonical_profile, file: Arc::new(file) }),
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

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn file(&self) -> Arc<File> {
        Arc::clone(&self.file)
    }
}

#[cfg(windows)]
fn short_profile_directory(canonical: &Path) -> Result<PathBuf> {
    use std::{
        ffi::OsString,
        path::{Component, Prefix},
    };

    // WHY: canonicalize uses a verbatim prefix on Windows. Keep internal I/O
    // on ordinary paths and verify the spelling still names the same directory.
    let mut components = canonical.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        bail!("writable profile directory needs an absolute drive or UNC path");
    };
    let mut directory = match prefix.kind() {
        Prefix::VerbatimDisk(drive) => PathBuf::from(format!("{}:", char::from(drive))),
        Prefix::VerbatimUNC(server, share) => {
            let mut unc = OsString::from(r"\\");
            unc.push(server);
            unc.push(r"\");
            unc.push(share);
            PathBuf::from(unc)
        }
        Prefix::Disk(_) | Prefix::UNC(_, _) => return Ok(canonical.to_path_buf()),
        _ => bail!("writable profile directory needs an ordinary drive or UNC path"),
    };
    for component in components {
        directory.push(component.as_os_str());
    }
    ensure!(
        fs::canonicalize(&directory)? == canonical,
        "ordinary profile path resolves to a different directory"
    );
    Ok(directory)
}
