//! CoreSettings upload/download policy derivation.
//!
//! Shared core setting DTOs, defaults, and validation live in
//! `emulebb-settings`; this module only derives eD2K runtime policy from the
//! validated core_settings.

use emulebb_ed2k::config::Ed2kUploadQueueRuntimeConfig;
use emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig;
#[cfg(test)]
pub(crate) use emulebb_settings::default_core_settings;
pub(crate) use emulebb_settings::{apply_core_settings_update, core_settings_update_is_empty};

use crate::CoreSettings;

pub(crate) fn ed2k_upload_queue_policy_from_core_settings(
    base: Option<&Ed2kUploadQueueRuntimeConfig>,
    core_settings: &CoreSettings,
) -> Ed2kUploadQueueRuntimeConfig {
    let mut policy = base.cloned().unwrap_or_default();
    policy.active_slots = core_settings.max_upload_slots as usize;
    policy.elastic_percent = core_settings.upload_slot_elastic_percent.min(100);
    policy.upload_limit_bytes_per_sec = u64::from(core_settings.upload_limit_ki_bps) * 1024;
    policy.elastic_underfill_bytes_per_sec =
        u64::from(core_settings.upload_client_data_rate.max(1)) * 1024;
    policy.elastic_underfill_secs = policy.elastic_underfill_secs.max(10);
    policy.waiting_capacity = core_settings.queue_size as usize;
    policy
}

/// The global (cross-transfer) download payload budget in bytes per second
/// derived from the `downloadLimitKiBps` core setting. Mirrors how the upload
/// limit is derived from `uploadLimitKiBps` (see
/// `ed2k_upload_queue_policy_from_core_settings`). Threaded into the transfer
/// runtime's shared download throttle.
pub(crate) fn ed2k_download_limit_bytes_per_sec_from_core_settings(
    core_settings: &CoreSettings,
) -> u64 {
    u64::from(core_settings.download_limit_ki_bps) * 1024
}

/// The shared download-coordinator config derived from the live REST
/// core_settings (`maxConnections` / `maxConnectionsPerFiveSeconds` /
/// `maxSourcesPerFile`), mirroring the eMule controls
/// `GetMaxConnections` / `GetMaxConperFive` / `GetConfiguredMaxSourcesPerFile`.
/// Applied at startup and on every settings.core update, like the download limit.
/// The connection window and reask pacing interval keep their master-derived
/// defaults (5s window, ~10s reask floor) since the REST surface does not expose
/// them.
pub(crate) fn ed2k_download_coordinator_config_from_core_settings(
    core_settings: &CoreSettings,
) -> Ed2kDownloadCoordinatorConfig {
    Ed2kDownloadCoordinatorConfig {
        max_connections: core_settings.max_connections as usize,
        max_connections_per_window: core_settings.max_connections_per_five_seconds as usize,
        max_sources_per_file: core_settings.max_sources_per_file as usize,
        ..Ed2kDownloadCoordinatorConfig::default()
    }
}

pub(crate) fn initial_ed2k_upload_queue_policy(
    base: Option<&Ed2kUploadQueueRuntimeConfig>,
    has_persisted_core_settings: bool,
    core_settings: &CoreSettings,
) -> Ed2kUploadQueueRuntimeConfig {
    if has_persisted_core_settings || base.is_none() {
        ed2k_upload_queue_policy_from_core_settings(base, core_settings)
    } else {
        base.cloned().unwrap_or_default()
    }
}
