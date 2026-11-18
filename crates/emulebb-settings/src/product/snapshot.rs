//! Bounded settings read data. The runtime owner supplies a coherent capture;
//! this model does not apply settings or infer effective values from saved ones.
use super::*;

pub const MAX_APPLY_MESSAGE_BYTES: usize = 512;
pub(super) const APPLY_FAILURE_CODE: &str = "applyFailed";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingApplyFailure {
    key: SettingKey,
    code: &'static str,
    message: String,
    truncated: bool,
}

impl SettingApplyFailure {
    /// Copy only the bounded UTF-8 prefix, without retaining the source error.
    pub fn new(key: SettingKey, message: &str) -> Self {
        let end = message.floor_char_boundary(MAX_APPLY_MESSAGE_BYTES.min(message.len()));
        Self {
            key,
            code: APPLY_FAILURE_CODE,
            message: message[..end].to_owned(),
            truncated: end < message.len(),
        }
    }

    pub fn key(&self) -> SettingKey {
        self.key
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsApplicationStatus {
    pending_restart: Vec<SettingKey>,
    failed: Vec<SettingApplyFailure>,
}

impl SettingsApplicationStatus {
    /// Each list has at most one entry per supported key. A pending restart and
    /// a failed live application may both describe the same key.
    pub fn new(
        pending_restart: Vec<SettingKey>,
        failed: Vec<SettingApplyFailure>,
    ) -> Result<Self, SettingsError> {
        let count = setting_specs().len();
        if pending_restart.len() > count || failed.len() > count {
            return Err(SettingsError::InvalidDocument);
        }
        let mut seen = HashSet::new();
        if pending_restart.iter().any(|key| !seen.insert(*key)) {
            return Err(SettingsError::InvalidDocument);
        }
        seen.clear();
        if failed.iter().any(|failure| !seen.insert(failure.key)) {
            return Err(SettingsError::InvalidDocument);
        }
        Ok(Self {
            pending_restart,
            failed,
        })
    }

    pub fn pending_restart(&self) -> &[SettingKey] {
        &self.pending_restart
    }

    pub fn failed(&self) -> &[SettingApplyFailure] {
        &self.failed
    }
}

/// Data only: the envelope carries the saved revision in meta.settingsRevision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsReadData {
    saved: SavedSettings,
    effective: SettingsValues,
    application: SettingsApplicationStatus,
}

impl SettingsReadData {
    pub fn new(
        saved: SavedSettings,
        effective: SettingsValues,
        application: SettingsApplicationStatus,
    ) -> Result<Self, SettingsError> {
        let saved = saved.resolved()?;
        let issues = effective.validate();
        if !issues.is_empty() {
            return Err(SettingsError::Validation(issues));
        }
        let snapshot = Self {
            saved,
            effective,
            application,
        };
        json_size(&snapshot, MAX_SNAPSHOT_BYTES)?;
        Ok(snapshot)
    }

    pub fn saved(&self) -> &SavedSettings {
        &self.saved
    }

    pub fn effective(&self) -> &SettingsValues {
        &self.effective
    }

    pub fn application(&self) -> &SettingsApplicationStatus {
        &self.application
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SettingsError> {
        serde_json::to_vec(self).map_err(|_| SettingsError::InvalidDocument)
    }
}

#[cfg(test)]
mod tests;
