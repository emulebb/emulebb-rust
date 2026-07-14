//! Preferences upload/download policy derivation.
//!
//! Shared preference DTOs, defaults, and validation live in
//! `emulebb-settings`; this module only derives eD2K runtime policy from the
//! validated preferences.

use emulebb_ed2k::config::Ed2kUploadQueueRuntimeConfig;
use emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig;
#[cfg(test)]
pub(crate) use emulebb_settings::default_preferences;
pub(crate) use emulebb_settings::{apply_preferences_update, preferences_update_is_empty};

use crate::Preferences;

pub(crate) fn ed2k_upload_queue_policy_from_preferences(
    base: Option<&Ed2kUploadQueueRuntimeConfig>,
    preferences: &Preferences,
) -> Ed2kUploadQueueRuntimeConfig {
    let mut policy = base.cloned().unwrap_or_default();
    policy.active_slots = preferences.max_upload_slots as usize;
    policy.elastic_percent = preferences.upload_slot_elastic_percent.min(100);
    policy.upload_limit_bytes_per_sec = u64::from(preferences.upload_limit_ki_bps) * 1024;
    policy.elastic_underfill_bytes_per_sec =
        u64::from(preferences.upload_client_data_rate.max(1)) * 1024;
    policy.elastic_underfill_secs = policy.elastic_underfill_secs.max(10);
    policy.waiting_capacity = preferences.queue_size as usize;
    policy
}

/// The global (cross-transfer) download payload budget in bytes per second
/// derived from the `downloadLimitKiBps` preference. Mirrors how the upload
/// limit is derived from `uploadLimitKiBps` (see
/// `ed2k_upload_queue_policy_from_preferences`). Threaded into the transfer
/// runtime's shared download throttle.
pub(crate) fn ed2k_download_limit_bytes_per_sec_from_preferences(preferences: &Preferences) -> u64 {
    u64::from(preferences.download_limit_ki_bps) * 1024
}

/// The shared download-coordinator config derived from the live REST
/// preferences (`maxConnections` / `maxConnectionsPerFiveSeconds` /
/// `maxSourcesPerFile`), mirroring the eMule controls
/// `GetMaxConnections` / `GetMaxConperFive` / `GetConfiguredMaxSourcesPerFile`.
/// Applied at startup and on every preferences update, like the download limit.
/// The connection window and reask pacing interval keep their master-derived
/// defaults (5s window, ~10s reask floor) since the REST surface does not expose
/// them.
pub(crate) fn ed2k_download_coordinator_config_from_preferences(
    preferences: &Preferences,
) -> Ed2kDownloadCoordinatorConfig {
    Ed2kDownloadCoordinatorConfig {
        max_connections: preferences.max_connections as usize,
        max_connections_per_window: preferences.max_connections_per_five_seconds as usize,
        max_sources_per_file: preferences.max_sources_per_file as usize,
        ..Ed2kDownloadCoordinatorConfig::default()
    }
}

pub(crate) fn initial_ed2k_upload_queue_policy(
    base: Option<&Ed2kUploadQueueRuntimeConfig>,
    has_persisted_preferences: bool,
    preferences: &Preferences,
) -> Ed2kUploadQueueRuntimeConfig {
    if has_persisted_preferences || base.is_none() {
        ed2k_upload_queue_policy_from_preferences(base, preferences)
    } else {
        base.cloned().unwrap_or_default()
    }
}
