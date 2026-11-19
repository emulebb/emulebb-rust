//! Package-owned fresh-profile staging. Existing final profiles are never edited.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use emulebb_settings::product::ValueMode;
use rustix::fs::{CWD, OFlags, RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    OfflineSettingsOperation, PROFILE_METADATA_FILE, PROFILE_SETTINGS_FILE, ProfileLease,
    host_bootstrap,
    offline_settings::{PreparedOperation, open_owned_settings},
};

const MAX_JOURNAL_BYTES: u64 = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    profile_name: String,
    stage_name: String,
}

struct Installation {
    parent: PathBuf,
    destination: PathBuf,
    journal_path: PathBuf,
    stage: PathBuf,
    // The lock file remains in place; process death releases its OS lock.
    _lock: File,
}

/// Finish only owned first-run work. No networking, daemon startup, package SQL,
/// runtime overrides or edits to an existing final profile occur here.
/// The package must supply an existing durable profile parent (the /config mount).
pub fn initialize(profile: &Path, incoming: &Path, temporary: &Path) -> Result<()> {
    ensure!(
        profile.is_absolute() && incoming.is_absolute() && temporary.is_absolute(),
        "container profile and storage paths must be absolute"
    );
    let Some(installation) = Installation::begin(profile)? else {
        return Ok(());
    };
    installation.create_stage()?;
    let lease = ProfileLease::acquire(&installation.stage, false)?;
    prepare_stage(&lease, incoming, temporary)?;
    sync_stage(lease.directory())?;
    // WHY: keeping the profile lease across rename prevents another offline
    // writer from changing the prepared database between close and publication.
    installation.publish()?;
    drop(lease);
    Ok(())
}

impl Installation {
    fn begin(profile: &Path) -> Result<Option<Self>> {
        let name = profile
            .file_name()
            .and_then(|name| name.to_str())
            .context("container profile needs a UTF-8 directory name")?;
        let parent = profile
            .parent()
            .context("container profile has no parent")?;
        // WHY: syncing a newly created parent alone does not persist its entry
        // in every ancestor. The container supplies a durable mounted parent;
        // do not introduce an unjournaled directory hierarchy above the stage.
        let parent = parent
            .canonicalize()
            .context("profile installation parent must already exist")?;
        let destination = parent.join(name);
        let lock = private_options()
            .create(true)
            .open(parent.join(format!(".{name}.provision.lock")))?;
        ensure!(
            lock.metadata()?.is_file(),
            "installation lock must be a regular file"
        );
        lock.try_lock()
            .context("profile installation is already owned or locking is unsupported")?;
        if final_exists(&destination)? {
            sync_directory(&parent)?;
            return Ok(None);
        }
        let journal_path = parent.join(format!(".{name}.provision.json"));
        let journal = match private_options().open(&journal_path) {
            Ok(file) => {
                ensure!(
                    file.metadata()?.is_file(),
                    "provisioning journal must be a regular file"
                );
                let mut bytes = Vec::new();
                file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
                ensure!(
                    bytes.len() as u64 <= MAX_JOURNAL_BYTES,
                    "provisioning journal is too large"
                );
                serde_json::from_slice::<Journal>(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid profile provisioning journal"))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let journal = Journal {
                    profile_name: name.to_owned(),
                    stage_name: format!(".{name}.init-{}", Uuid::new_v4()),
                };
                let mut file = tempfile::NamedTempFile::new_in(&parent)?;
                serde_json::to_writer(&mut file, &journal)?;
                file.flush()?;
                file.as_file().sync_all()?;
                file.persist_noclobber(&journal_path)
                    .map_err(|error| error.error)?;
                journal
            }
            Err(error) => return Err(error).context("failed to open profile provisioning journal"),
        };
        ensure!(
            journal.profile_name == name,
            "provisioning journal names a different profile"
        );
        let prefix = format!(".{name}.init-");
        let id = journal
            .stage_name
            .strip_prefix(&prefix)
            .context("provisioning journal does not identify an owned stage")?;
        let uuid = Uuid::parse_str(id).context("invalid provisioning stage identity")?;
        ensure!(
            uuid.to_string() == id,
            "invalid provisioning stage identity"
        );
        // The ownership record must reach stable storage BEFORE stage creation.
        sync_directory(&parent)?;
        Ok(Some(Self {
            stage: parent.join(journal.stage_name),
            parent,
            destination,
            journal_path,
            _lock: lock,
        }))
    }

    fn create_stage(&self) -> Result<()> {
        match fs::symlink_metadata(&self.stage) {
            Ok(metadata) => ensure!(metadata.is_dir(), "owned profile stage is not a directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&self.stage)?;
            }
            Err(error) => return Err(error).context("failed to inspect owned profile stage"),
        }
        sync_directory(&self.parent)
    }

    fn publish(&self) -> Result<()> {
        match renameat_with(
            CWD,
            &self.stage,
            CWD,
            &self.destination,
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                sync_directory(&self.parent)?;
                fs::remove_file(&self.journal_path)?;
                sync_directory(&self.parent)
            }
            Err(rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY) => {
                ensure!(
                    final_exists(&self.destination)?,
                    "competing profile publication disappeared"
                );
                // Preserve both the winner and our owned stage/journal. There is
                // no replay into the winner and no deletion of unrelated state.
                Ok(())
            }
            Err(error) => Err(error).context(
                "atomic no-replace profile publication failed; owned stage and journal retained",
            ),
        }
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32);
    options
}

fn final_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(metadata.is_dir(), "final profile is not a directory");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("failed to inspect final profile"),
    }
}

fn prepare_stage(lease: &ProfileLease, incoming: &Path, temporary: &Path) -> Result<()> {
    // Reject redirected database/bootstrap files before either owner opens them.
    stage_data_files(lease.directory())?;
    let settings = lease.directory().join(PROFILE_SETTINGS_FILE);
    if !settings.try_exists()? {
        crate::create_default_profile_bootstrap(lease.directory(), &settings)?;
    }
    host_bootstrap::read(lease.directory())?.context("profile bootstrap is missing")?;
    let store = open_owned_settings(lease)?;
    let saved = store.load_app_settings()?.saved;
    for (key, value, mode) in [
        (
            "storage.incomingDirectory",
            incoming,
            saved.storage.incoming_directory.mode,
        ),
        (
            "storage.tempDirectory",
            temporary,
            saved.storage.temp_directory.mode,
        ),
    ] {
        if mode == ValueMode::Default {
            PreparedOperation::parse(&OfflineSettingsOperation::Set {
                key: key.to_owned(),
                value: value
                    .to_str()
                    .context("container storage path must be UTF-8")?
                    .to_owned(),
            })?
            .execute(&store)?;
        }
    }
    store.load_app_settings()?;
    // The only connection closes before sync and directory publication. No
    // runtime projection creates roots or resolves relative values in staging.
    drop(store);
    Ok(())
}

fn stage_data_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for name in [
        PROFILE_SETTINGS_FILE.to_owned(),
        PROFILE_METADATA_FILE.to_owned(),
        format!("{PROFILE_METADATA_FILE}-wal"),
        format!("{PROFILE_METADATA_FILE}-shm"),
    ] {
        let file = path.join(name);
        match fs::symlink_metadata(&file) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file(),
                    "staged profile data must be a regular file"
                );
                files.push(file);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to sync staged profile data"),
        }
    }
    Ok(files)
}

fn sync_stage(path: &Path) -> Result<()> {
    for file in stage_data_files(path)? {
        File::open(file)?.sync_all()?;
    }
    sync_directory(path)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?
        .sync_all()
        .context("profile directory durability could not be established")
}

#[cfg(test)]
mod tests;
