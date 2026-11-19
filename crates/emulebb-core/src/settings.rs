//! Canonical saved/effective settings captured under the profile owner.
use crate::{EmulebbCore, LibraryReply};
use emulebb_metadata::MetadataAppSettings;
use emulebb_settings::product::{
    SettingsApplicationStatus, SettingsError, SettingsPatch, SettingsReadData, SettingsRevision,
    SettingsValues,
};

/// One coherent read. The transport places the revision in native response meta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsSnapshot {
    revision: SettingsRevision,
    data: SettingsReadData,
}
impl SettingsSnapshot {
    pub(crate) fn new(
        saved: MetadataAppSettings,
        effective: SettingsValues,
        application: SettingsApplicationStatus,
    ) -> Result<Self, SettingsError> {
        Ok(Self {
            revision: saved.revision,
            data: SettingsReadData::new(saved.saved, effective, application)?,
        })
    }
    pub fn revision(&self) -> SettingsRevision {
        self.revision
    }
    pub fn data(&self) -> &SettingsReadData {
        &self.data
    }
    pub fn into_data(self) -> SettingsReadData {
        self.data
    }
}

/// Admitted runtime values only. SQLite remains the saved-document authority.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeSettings {
    values: SettingsValues,
    application: SettingsApplicationStatus,
}
impl RuntimeSettings {
    pub(crate) fn startup(saved: MetadataAppSettings) -> Self {
        Self {
            values: saved.saved.values(),
            application: SettingsApplicationStatus::default(),
        }
    }
    pub(crate) fn values(&self) -> &SettingsValues {
        &self.values
    }
    pub(crate) fn application(&self) -> &SettingsApplicationStatus {
        &self.application
    }
    pub(crate) fn publish(
        &mut self,
        values: SettingsValues,
        application: SettingsApplicationStatus,
    ) {
        self.values = values;
        self.application = application;
    }
}

#[derive(Debug, Clone)]
pub enum SettingsMutationError {
    Invalid(SettingsError),
    Conflict { actual: SettingsRevision },
    RevisionExhausted,
}
impl std::fmt::Display for SettingsMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(error) => std::fmt::Display::fmt(error, f),
            Self::Conflict { .. } => {
                f.write_str("Saved settings changed; read the latest revision.")
            }
            Self::RevisionExhausted => f.write_str("Saved settings revision is exhausted."),
        }
    }
}
impl std::error::Error for SettingsMutationError {}

impl EmulebbCore {
    pub async fn settings(&self) -> anyhow::Result<LibraryReply<SettingsSnapshot>> {
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner.read_settings().await?)
    }
    pub async fn update_settings(
        &self,
        patch: &SettingsPatch,
    ) -> anyhow::Result<LibraryReply<SettingsSnapshot>> {
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner.write_settings(self, patch).await??)
    }
    /// Runtime owners read admitted values, never unadmitted desired settings.
    pub async fn effective_settings(&self) -> anyhow::Result<SettingsValues> {
        self.persistence_owner.check_coherent_state()?;
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        Ok(state.settings.values().clone())
    }
    pub(crate) async fn apply_live_settings(&self, values: &SettingsValues) {
        self.ed2k_transfers
            .apply_upload_queue_policy(&crate::core_settings::ed2k_upload_queue_policy(
                self.ed2k_network
                    .as_ref()
                    .map(|network| &network.ed2k.upload_queue),
                values,
            ))
            .await;
        self.ed2k_transfers
            .apply_download_limit(values.transfers.download_limit_bytes_per_second)
            .await;
        self.ed2k_transfers.apply_download_coordinator_config(
            crate::core_settings::ed2k_download_coordinator_config(values),
        );
        self.ed2k_transfers
            .set_credit_system_enabled(values.transfers.upload.credit_system_enabled);
        self.download_attempts
            .apply_concurrency_limit(values.transfers.max_concurrent_downloads);
    }
}
