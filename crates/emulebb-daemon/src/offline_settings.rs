//! Stopped-profile single-key commands use the canonical typed settings store.
use crate::DaemonProfile;
use anyhow::{Context, Result};
use emulebb_settings::product::{SettingKey, SettingsEdit};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum OfflineSettingsOperation {
    Get { key: String },
    Set { key: String, value: String },
    Reset { key: String },
}

/// Acquire the same exclusive profile lease as the daemon and imports. Only
/// Get returns stdout data; successful writes have no output or caller CAS.
pub fn run_offline_settings(
    profile_dir: PathBuf,
    operation: OfflineSettingsOperation,
) -> Result<Option<String>> {
    let (key, edit) = match &operation {
        OfflineSettingsOperation::Get { key } => (SettingKey::parse(key)?, None),
        OfflineSettingsOperation::Set { key, value } => {
            let key = SettingKey::parse(key)?;
            (
                key,
                Some(
                    SettingsEdit::setting_text(key, value)
                        .with_context(|| format!("invalid value for {}", key.as_str()))?,
                ),
            )
        }
        OfflineSettingsOperation::Reset { key } => {
            let key = SettingKey::parse(key)?;
            (
                key,
                Some(SettingsEdit {
                    reset: vec![key],
                    ..SettingsEdit::default()
                }),
            )
        }
    };
    let profile = DaemonProfile::load_for_import(profile_dir)?;
    let store = profile.open_metadata_store()?;
    if let Some(edit) = edit {
        store.edit_app_settings(&edit)?;
        Ok(None)
    } else {
        Ok(Some(
            store
                .load_app_settings()?
                .saved
                .values()
                .display_value(key)?,
        ))
    }
}
