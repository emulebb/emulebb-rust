//! Runtime policy derived directly from canonical admitted product values.
use emulebb_ed2k::config::Ed2kUploadQueueRuntimeConfig;
use emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig;
use emulebb_settings::product::SettingsValues;

pub(crate) fn ed2k_upload_queue_policy(
    base: Option<&Ed2kUploadQueueRuntimeConfig>,
    values: &SettingsValues,
) -> Ed2kUploadQueueRuntimeConfig {
    let mut policy = base.cloned().unwrap_or_default();
    policy.base_slots = values.transfers.upload.base_slots as usize;
    policy.elastic_percent = values.transfers.upload.elastic_percent;
    policy.upload_limit_bytes_per_sec = values.transfers.upload_limit_bytes_per_second;
    policy.elastic_underfill_bytes_per_sec =
        values.transfers.upload.target_client_rate_bytes_per_second;
    policy.waiting_capacity = values.transfers.upload.queue_capacity as usize;
    policy.session_transfer_percent = values.transfers.upload.session_transfer_percent;
    policy.session_time_limit_secs = values.transfers.upload.session_time_limit_seconds;
    policy
}

pub(crate) fn ed2k_download_coordinator_config(
    values: &SettingsValues,
) -> Ed2kDownloadCoordinatorConfig {
    Ed2kDownloadCoordinatorConfig {
        max_connections: values.network.connections.max_connections as usize,
        max_connections_per_window: values
            .network
            .connections
            .max_new_connections_per_five_seconds as usize,
        max_half_open_connections: values.network.connections.max_half_open_connections as usize,
        max_sources_per_file: values.transfers.max_sources_per_file as usize,
        ..Ed2kDownloadCoordinatorConfig::default()
    }
}
