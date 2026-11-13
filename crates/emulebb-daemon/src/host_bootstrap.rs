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
    let mut temporary = tempfile::NamedTempFile::new_in(lease.directory())?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(lease.directory().join(PROFILE_SETTINGS_FILE))
        .map_err(|error| error.error)
        .context("failed to publish bootstrap settings")?;
    #[cfg(unix)]
    std::fs::File::open(lease.directory())?.sync_all()?;
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
            "[rest]\nbindAddr = '127.0.0.1:20017'",
            "[rest]\nbind_addr = 'invalid'",
            "[rest]\napi_key = 'short'",
            "[unknown]\nvalue=1",
        ] {
            std::fs::write(root.path().join(PROFILE_SETTINGS_FILE), text).unwrap();
            assert!(read(root.path()).is_err());
        }
    }
}
