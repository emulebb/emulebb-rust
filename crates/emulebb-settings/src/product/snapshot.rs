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

/// A validated application target, not a claim that runtime consumers accepted it.
/// The persistence owner publishes effective values only after applying them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsApplicationPlan {
    candidate: SettingsValues,
    pending_restart: Vec<SettingKey>,
}

impl SettingsApplicationPlan {
    /// Keep restart-bound values in use. If the resulting live candidate would
    /// violate a dependency, defer every desired difference until restart.
    pub fn new(
        effective: &SettingsValues,
        desired: &SettingsValues,
    ) -> Result<Self, SettingsError> {
        for values in [effective, desired] {
            let issues = values.validate();
            if !issues.is_empty() {
                return Err(SettingsError::Validation(issues));
            }
        }
        let mut candidate = effective.clone();
        for spec in setting_specs() {
            if spec.application == ApplyMode::Live {
                let key = SettingKey(spec.key);
                let copied = candidate.copy_key_from(desired, key);
                debug_assert!(copied, "compiled setting has a typed value");
            }
        }
        // WHY: individually valid desired settings can depend on restart-bound
        // changes. Applying any part of that incompatible live candidate would
        // contradict the coherent effective snapshot; leave it entirely intact.
        if !candidate.validate().is_empty() {
            candidate = effective.clone();
        }
        let pending_restart = desired.differing_keys(&candidate);
        Ok(Self {
            candidate,
            pending_restart,
        })
    }

    pub fn candidate(&self) -> &SettingsValues {
        &self.candidate
    }

    pub fn pending_restart(&self) -> &[SettingKey] {
        &self.pending_restart
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
