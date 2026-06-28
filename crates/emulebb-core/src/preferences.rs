//! Preferences defaults, update application, and upload-queue-policy derivation.
//!
//! Pure helpers that supply the default REST `Preferences`, test whether a
//! `PreferencesUpdate` is a no-op, apply a validated update field-by-field, and
//! derive the `Ed2kUploadQueuePolicyConfig` from preferences (plus the
//! per-field range validators and the upload-slot derivation). Moved verbatim
//! out of `lib.rs` during the maintainability restructuring; they carry no
//! behavior beyond what they had inline. Re-exported `pub(crate)` from the
//! crate root so the `EmulebbCore` impl, the startup path, and the test module
//! reach them by their bare names.

use anyhow::{Result, ensure};
use emulebb_ed2k::config::Ed2kUploadQueuePolicyConfig;
use emulebb_ed2k::ed2k_transfer::Ed2kDownloadCoordinatorConfig;

use crate::{Preferences, PreferencesUpdate};

pub(crate) fn default_preferences() -> Preferences {
    // Defaults aligned to the master (srchybrid/Preferences.cpp +
    // PreferenceValidationSeams.h): upload 6200 KiB/s
    // (kDefaultConfiguredUploadLimitKiB), download 12207 KiB/s
    // (kDefaultConfiguredDownloadLimitKiB), maxConnections 500
    // (GetRecommendedMaxConnections), maxConnectionsPerFiveSeconds 50
    // (GetDefaultMaxConperFive), maxSourcesPerFile 600
    // (GetDefaultMaxSourcesPerFile), maxUploadSlots 12 (kDefaultMaxUploadSlots),
    // queueSize 10000 (kDefaultQueueSize), elasticPercent 80.
    Preferences {
        upload_limit_ki_bps: 6200,
        download_limit_ki_bps: 12207,
        max_connections: 500,
        max_connections_per_five_seconds: 50,
        max_sources_per_file: 600,
        upload_client_data_rate: 32,
        max_upload_slots: 12,
        upload_slot_elastic_percent: 80,
        queue_size: 10000,
        auto_connect: false,
        reconnect: true,
        new_auto_up: true,
        new_auto_down: true,
        credit_system: true,
        safe_server_connect: true,
        network_kademlia: true,
        network_ed2k: true,
        download_auto_broadband_io: true,
    }
}

pub(crate) fn preferences_update_is_empty(update: &PreferencesUpdate) -> bool {
    update.upload_limit_ki_bps.is_none()
        && update.download_limit_ki_bps.is_none()
        && update.max_connections.is_none()
        && update.max_connections_per_five_seconds.is_none()
        && update.max_sources_per_file.is_none()
        && update.upload_client_data_rate.is_none()
        && update.max_upload_slots.is_none()
        && update.upload_slot_elastic_percent.is_none()
        && update.queue_size.is_none()
        && update.auto_connect.is_none()
        && update.reconnect.is_none()
        && update.new_auto_up.is_none()
        && update.new_auto_down.is_none()
        && update.credit_system.is_none()
        && update.safe_server_connect.is_none()
        && update.network_kademlia.is_none()
        && update.network_ed2k.is_none()
        && update.download_auto_broadband_io.is_none()
}

pub(crate) fn apply_preferences_update(
    preferences: &mut Preferences,
    update: PreferencesUpdate,
) -> Result<()> {
    if let Some(value) = update.upload_limit_ki_bps {
        ensure_finite_kibps(value, "uploadLimitKiBps")?;
        preferences.upload_limit_ki_bps = value;
    }
    if let Some(value) = update.download_limit_ki_bps {
        ensure_finite_kibps(value, "downloadLimitKiBps")?;
        preferences.download_limit_ki_bps = value;
    }
    if let Some(value) = update.max_connections {
        ensure_positive_u32(value, "maxConnections")?;
        preferences.max_connections = value;
    }
    if let Some(value) = update.max_connections_per_five_seconds {
        ensure_positive_u32(value, "maxConnectionsPerFiveSeconds")?;
        preferences.max_connections_per_five_seconds = value;
    }
    if let Some(value) = update.max_sources_per_file {
        ensure_positive_u32(value, "maxSourcesPerFile")?;
        preferences.max_sources_per_file = value;
    }
    if let Some(value) = update.upload_client_data_rate {
        ensure!(
            value > 0,
            "uploadClientDataRate must be an unsigned number in the range 1..4294967295"
        );
        preferences.upload_client_data_rate = value;
        preferences.max_upload_slots = derive_upload_slots(preferences.upload_limit_ki_bps, value);
    }
    if let Some(value) = update.max_upload_slots {
        ensure!(
            (1..=64).contains(&value),
            "maxUploadSlots must be an unsigned number in the range 1..64"
        );
        preferences.max_upload_slots = value;
    }
    if let Some(value) = update.upload_slot_elastic_percent {
        ensure!(
            value <= 100,
            "uploadSlotElasticPercent must be an unsigned number in the range 0..100"
        );
        preferences.upload_slot_elastic_percent = value;
    }
    if let Some(value) = update.queue_size {
        ensure!(
            (2000..=10000).contains(&value),
            "queueSize must be an unsigned number in the range 2000..10000"
        );
        preferences.queue_size = value;
    }
    if let Some(value) = update.auto_connect {
        preferences.auto_connect = value;
    }
    if let Some(value) = update.reconnect {
        preferences.reconnect = value;
    }
    if let Some(value) = update.new_auto_up {
        preferences.new_auto_up = value;
    }
    if let Some(value) = update.new_auto_down {
        preferences.new_auto_down = value;
    }
    if let Some(value) = update.credit_system {
        preferences.credit_system = value;
    }
    if let Some(value) = update.safe_server_connect {
        preferences.safe_server_connect = value;
    }
    if let Some(value) = update.network_kademlia {
        preferences.network_kademlia = value;
    }
    if let Some(value) = update.network_ed2k {
        preferences.network_ed2k = value;
    }
    if let Some(value) = update.download_auto_broadband_io {
        preferences.download_auto_broadband_io = value;
    }
    Ok(())
}

pub(crate) fn ed2k_upload_queue_policy_from_preferences(
    base: Option<&Ed2kUploadQueuePolicyConfig>,
    preferences: &Preferences,
) -> Ed2kUploadQueuePolicyConfig {
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
    base: Option<&Ed2kUploadQueuePolicyConfig>,
    has_persisted_preferences: bool,
    preferences: &Preferences,
) -> Ed2kUploadQueuePolicyConfig {
    if has_persisted_preferences || base.is_none() {
        ed2k_upload_queue_policy_from_preferences(base, preferences)
    } else {
        base.cloned().unwrap_or_default()
    }
}

fn ensure_finite_kibps(value: u32, name: &str) -> Result<()> {
    ensure!(
        value > 0 && value < u32::MAX,
        "{name} must be an unsigned number in the range 1..4294967294"
    );
    Ok(())
}

fn ensure_positive_u32(value: u32, name: &str) -> Result<()> {
    ensure!(
        value > 0 && value <= i32::MAX as u32,
        "{name} must be an unsigned number in the range 1..2147483647"
    );
    Ok(())
}

fn derive_upload_slots(upload_limit_ki_bps: u32, upload_client_data_rate: u32) -> u32 {
    upload_limit_ki_bps
        .div_ceil(upload_client_data_rate)
        .clamp(1, 64)
}
