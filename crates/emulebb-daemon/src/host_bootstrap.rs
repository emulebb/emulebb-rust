//! Canonical bootstrap access for application hosts, serialized by the profile lease.

use std::{io::Write, path::Path};

use anyhow::{Context, Result};

use super::{
    DaemonBootstrapSettings, DaemonProfile, PROFILE_SETTINGS_FILE, ProfileLease,
    RestBootstrapSettings,
};

/// Execute application-owned maintenance only while no daemon owns this profile.
/// The operation must finish before returning; ownership never escapes this call.
pub fn while_stopped<T>(profile_dir: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let _lease = ProfileLease::acquire(profile_dir, true)?;
    operation()
}

/// Read existing settings without opening or changing the metadata database.
/// Atomic bootstrap publication permits read-only setup/status UI while the
/// daemon owns the profile. Only writes require an exclusive profile lease.
pub fn read(profile_dir: &Path) -> Result<Option<RestBootstrapSettings>> {
    let path = profile_dir.join(PROFILE_SETTINGS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    super::validate_profile_settings_permissions(&path)?;
    let text = std::fs::read_to_string(path)?;
    let bootstrap: DaemonBootstrapSettings =
        toml::from_str(&text).map_err(|error: toml::de::Error| {
            anyhow::anyhow!("invalid bootstrap: {}", error.message())
        })?;
    validate(&bootstrap.rest)?;
    Ok(Some(bootstrap.rest))
}

/// Validate the same bootstrap contract used by daemon startup.
pub fn validate(rest: &RestBootstrapSettings) -> Result<()> {
    let profile = DaemonProfile {
        rest: rest.clone(),
        ..Default::default()
    };
    profile.validate_rest_api_key()?;
    profile.rest_bind_addr()?;
    Ok(())
}

/// Atomically replace stopped-host bootstrap settings while retaining exclusive ownership.
pub fn write(profile_dir: &Path, rest: RestBootstrapSettings) -> Result<()> {
    validate(&rest)?;
    let lease = ProfileLease::acquire(profile_dir, true)?;
    let text = toml::to_string(&DaemonBootstrapSettings { rest })?;
    publish(lease.directory(), &text, Publication::Replace)
}

pub(super) enum Publication {
    Create,
    Replace,
}

/// Publish complete, synced bootstrap bytes under an already-held profile lease.
/// Creation never replaces an existing file, including one published externally.
pub(super) fn publish(profile_dir: &Path, text: &str, mode: Publication) -> Result<()> {
    // WHY: writing the final name directly can leave a truncated bootstrap after
    // interruption. Readers must see either the existing file or complete bytes.
    let mut temporary = tempfile::NamedTempFile::new_in(profile_dir)?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    let destination = profile_dir.join(PROFILE_SETTINGS_FILE);
    match mode {
        Publication::Create => temporary.persist_noclobber(destination),
        Publication::Replace => temporary.persist(destination),
    }
    .map_err(|error| error.error)
    .context("failed to publish bootstrap settings")?;
    #[cfg(unix)]
    std::fs::File::open(profile_dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_settings_keep_one_owner_and_do_not_initialize_metadata() {
        let root = tempfile::tempdir().unwrap();
        let rest = RestBootstrapSettings {
            bind_addr: Some("127.0.0.1:20017".parse().unwrap()),
            api_key: "0123456789abcdef0123456789abcdef".into(),
            web_root_dir: None,
        };
        assert!(read(root.path()).unwrap().is_none());
        write(root.path(), rest.clone()).unwrap();
        assert_eq!(read(root.path()).unwrap().unwrap().api_key, rest.api_key);
        assert!(
            !root
                .path()
                .join(super::super::PROFILE_METADATA_FILE)
                .exists()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(root.path().join(PROFILE_SETTINGS_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let _lease = ProfileLease::acquire(root.path(), false).unwrap();
        assert!(write(root.path(), rest).is_err());
        assert!(read(root.path()).unwrap().is_some());
    }

    #[test]
    fn invalid_settings_do_not_replace_the_existing_bootstrap() {
        let root = tempfile::tempdir().unwrap();
        let mut rest = RestBootstrapSettings {
            bind_addr: Some("127.0.0.1:20017".parse().unwrap()),
            api_key: "0123456789abcdef0123456789abcdef".into(),
            web_root_dir: None,
        };
        write(root.path(), rest.clone()).unwrap();
        let original = std::fs::read(root.path().join(PROFILE_SETTINGS_FILE)).unwrap();
        rest.api_key = "short".into();
        assert!(write(root.path(), rest).is_err());
        assert_eq!(
            std::fs::read(root.path().join(PROFILE_SETTINGS_FILE)).unwrap(),
            original
        );
        for text in [
            "[rest]\napi_key = '0123456789abcdef0123456789abcdef'",
            "[rest]\nunknown_field = 'sample'",
            "[rest]\nbind_addr = 'invalid'",
            "[rest]\napi_key = 'short'",
            "[unknown]\nvalue=1",
        ] {
            std::fs::write(root.path().join(PROFILE_SETTINGS_FILE), text).unwrap();
            assert!(read(root.path()).is_err());
        }
    }

    #[test]
    fn initial_publication_preserves_an_existing_file_without_truncating_it() {
        let root = tempfile::tempdir().unwrap();
        let _lease = ProfileLease::acquire(root.path(), false).unwrap();
        let path = root.path().join(PROFILE_SETTINGS_FILE);
        let existing = b"operator-owned contents";
        std::fs::write(&path, existing).unwrap();

        assert!(publish(root.path(), "replacement", Publication::Create).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), existing);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
    }

    #[test]
    fn failed_initial_publication_can_retry_without_partial_bootstrap() {
        let root = tempfile::tempdir().unwrap();
        let _lease = ProfileLease::acquire(root.path(), false).unwrap();
        let path = root.path().join(PROFILE_SETTINGS_FILE);
        std::fs::create_dir(&path).unwrap();
        assert!(publish(root.path(), "complete bytes", Publication::Create).is_err());
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);

        std::fs::remove_dir(&path).unwrap();
        publish(root.path(), "complete bytes", Publication::Create).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "complete bytes");
    }
}
