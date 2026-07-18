//! Route-specific REST JSON body validators.

mod core_settings;
mod search;

use axum::response::Response;

use super::{JsonObject, invalid_body_error};

const MAX_TRANSFER_ADD_LINKS: usize = 100;
const DAEMON_SETTINGS_FIELDS: &[&str] = &[
    "incomingDir",
    "p2pBindIp",
    "p2pBindInterface",
    "ed2kUserHash",
    "hostnameLookup",
];
const HOSTNAME_LOOKUP_SETTINGS_FIELDS: &[&str] = &[
    "enabled",
    "dnsServers",
    "cacheTtlSecs",
    "maxLookupsPerTick",
    "tickIntervalSecs",
];
const ED2K_SETTINGS_FIELDS: &[&str] = &[
    "listenPort",
    "obfuscationEnabled",
    "probeSearchTerm",
    "connectTimeoutSecs",
    "serverConnectTimeoutSecs",
    "callbackTimeoutSecs",
    "reconnectIntervalSecs",
    "reconnectEnabled",
    "safeServerConnect",
    "keepaliveSecs",
    "sessionRotationSecs",
    "maxConcurrentDownloads",
    "maxNewConnectionsPerFiveSeconds",
    "maxHalfOpenConnections",
    "maxSourcesPerFile",
    "maxParallelDownloadPeers",
    "keywordServerAttemptBudget",
    "exactHashKeywordServerAttemptBudget",
    "sourceServerAttemptBudget",
    "uploadQueue",
    "downloadLimitBytesPerSec",
    "enableUdpReask",
    "publishEmuleRustIdentity",
    "addServersFromServer",
    "deadServerRetries",
];
const ED2K_UPLOAD_QUEUE_SETTINGS_FIELDS: &[&str] = &[
    "activeSlots",
    "elasticPercent",
    "uploadLimitBytesPerSec",
    "elasticUnderfillBytesPerSec",
    "elasticUnderfillSecs",
    "waitingCapacity",
    "waitingTimeoutSecs",
    "grantedTimeoutSecs",
    "uploadTimeoutSecs",
    "sessionTransferPercent",
    "sessionTimeLimitSecs",
];
const KAD_SETTINGS_FIELDS: &[&str] = &[
    "listenPort",
    "bootstrapMinRoutingContacts",
    "localStoreEnabled",
    "localStoreKeywordTtlSecs",
    "localStoreSourceTtlSecs",
    "localStoreNotesTtlSecs",
    "localStoreKeywordCapacity",
    "localStoreSourceCapacity",
    "localStoreNotesCapacity",
    "localStoreSourcePerFileCapacity",
    "localStoreNotesPerFileCapacity",
    "publishSharedFilesEnabled",
    "republishIntervalSecs",
    "publishContactFanout",
    "udpFirewallCheckEnabled",
    "udpFirewallCheckIntervalSecs",
    "tcpFirewallCheckEnabled",
    "tcpFirewallCheckIntervalSecs",
    "buddyEnabled",
    "routingMaintenanceEnabled",
    "snoopQueueDedupWindowSecs",
    "snoopQueueGeneralMaxQueriesPer600s",
    "snoopQueueGeneralDrainCooldownSecs",
    "snoopQueueSourceMaxQueriesPer600s",
    "snoopQueueSourceDrainCooldownSecs",
    "snoopQueueSourceStopAfterResults",
];
const NAT_SETTINGS_FIELDS: &[&str] = &[
    "enabled",
    "requireInitialMapping",
    "backendOrder",
    "bindIp",
    "igdIp",
    "minissdpdSocket",
    "ssdpLocalPort",
    "discoveryTimeoutSecs",
    "leaseDurationSecs",
    "renewMarginSecs",
    "externalIpOverride",
];
const VPN_GUARD_SETTINGS_FIELDS: &[&str] = &["enabled", "mode", "allowedPublicIpCidrs"];
const IP_FILTER_SETTINGS_FIELDS: &[&str] = &["enabled", "path", "level"];
const NAT_BACKEND_UPNP_MINIUPNPC: &str = "upnp_miniupnpc";
const NAT_BACKENDS: &[&str] = &[NAT_BACKEND_UPNP_MINIUPNPC];
const VPN_GUARD_MODES: &[&str] = &["off", "block"];

pub(super) fn validate_search_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    search::validate_search_create_body_fields(object)
}

pub(super) fn validate_core_settings_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    core_settings::validate_core_settings_patch_body_fields(object)
}

pub(super) fn validate_app_settings_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if object.is_empty() {
        return Err(invalid_body_error(
            "settings PATCH requires at least one settings section",
        ));
    }
    for (section, value) in object {
        let Some(section_object) = value.as_object() else {
            return Err(invalid_body_error(format!("{section} must be an object")));
        };
        match section.as_str() {
            "core" => validate_core_settings_patch_body_fields(section_object)?,
            "daemon" => {
                validate_non_empty_update_object(section_object, "settings.daemon")?;
                validate_known_settings_update_fields(
                    section_object,
                    DAEMON_SETTINGS_FIELDS,
                    "settings.daemon",
                )?;
                validate_daemon_settings_patch_body_fields(section_object)?;
                validate_nested_settings_update_object(
                    section_object,
                    "hostnameLookup",
                    "settings.daemon.hostnameLookup",
                    HOSTNAME_LOOKUP_SETTINGS_FIELDS,
                )?;
                validate_hostname_lookup_settings_patch_body_fields(section_object)?;
            }
            "ed2k" => {
                validate_non_empty_update_object(section_object, "settings.ed2k")?;
                validate_known_settings_update_fields(
                    section_object,
                    ED2K_SETTINGS_FIELDS,
                    "settings.ed2k",
                )?;
                validate_nullable_unsigned_number_min(
                    section_object,
                    "listenPort",
                    "settings.ed2k.listenPort",
                    1,
                )?;
                validate_ed2k_settings_patch_body_fields(section_object)?;
                validate_nested_settings_update_object(
                    section_object,
                    "uploadQueue",
                    "settings.ed2k.uploadQueue",
                    ED2K_UPLOAD_QUEUE_SETTINGS_FIELDS,
                )?;
                validate_ed2k_upload_queue_settings_patch_body_fields(section_object)?;
            }
            "kad" => {
                validate_non_empty_update_object(section_object, "settings.kad")?;
                validate_known_settings_update_fields(
                    section_object,
                    KAD_SETTINGS_FIELDS,
                    "settings.kad",
                )?;
                validate_kad_settings_patch_body_fields(section_object)?;
            }
            "nat" => {
                validate_non_empty_update_object(section_object, "settings.nat")?;
                validate_known_settings_update_fields(
                    section_object,
                    NAT_SETTINGS_FIELDS,
                    "settings.nat",
                )?;
                validate_nullable_unsigned_number_min(
                    section_object,
                    "ssdpLocalPort",
                    "settings.nat.ssdpLocalPort",
                    1,
                )?;
                validate_nat_settings_patch_body_fields(section_object)?;
            }
            "vpnGuard" => {
                validate_non_empty_update_object(section_object, "settings.vpnGuard")?;
                validate_known_settings_update_fields(
                    section_object,
                    VPN_GUARD_SETTINGS_FIELDS,
                    "settings.vpnGuard",
                )?;
                validate_vpn_guard_settings_patch_body_fields(section_object)?;
            }
            "ipFilter" => {
                validate_non_empty_update_object(section_object, "settings.ipFilter")?;
                validate_known_settings_update_fields(
                    section_object,
                    IP_FILTER_SETTINGS_FIELDS,
                    "settings.ipFilter",
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn validate_daemon_settings_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if let Some(incoming_dir) = object.get("incomingDir")
        && !incoming_dir.is_null()
    {
        validate_path_text_body_field(Some(incoming_dir), "incomingDir")?;
    }
    Ok(())
}

fn validate_nested_settings_update_object(
    parent: &JsonObject,
    field: &'static str,
    path: &'static str,
    allowed_fields: &'static [&'static str],
) -> Result<(), Box<Response>> {
    let Some(value) = parent.get(field) else {
        return Ok(());
    };
    let Some(object) = value.as_object() else {
        return Err(invalid_body_error(format!("{path} must be an object")));
    };
    validate_non_empty_update_object(object, path)?;
    validate_known_settings_update_fields(object, allowed_fields, path)
}

fn validate_known_settings_update_fields(
    object: &JsonObject,
    allowed_fields: &'static [&'static str],
    path: &str,
) -> Result<(), Box<Response>> {
    for name in object.keys() {
        if !allowed_fields.contains(&name.as_str()) {
            return Err(invalid_body_error(format!("unknown {path} field: {name}")));
        }
    }
    Ok(())
}

fn validate_hostname_lookup_settings_patch_body_fields(
    daemon: &JsonObject,
) -> Result<(), Box<Response>> {
    let Some(object) = daemon
        .get("hostnameLookup")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    validate_unsigned_number_min(
        object,
        "cacheTtlSecs",
        "settings.daemon.hostnameLookup.cacheTtlSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "maxLookupsPerTick",
        "settings.daemon.hostnameLookup.maxLookupsPerTick",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "tickIntervalSecs",
        "settings.daemon.hostnameLookup.tickIntervalSecs",
        5,
    )
}

fn validate_ed2k_settings_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_unsigned_number_min(
        object,
        "maxParallelDownloadPeers",
        "settings.ed2k.maxParallelDownloadPeers",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "keywordServerAttemptBudget",
        "settings.ed2k.keywordServerAttemptBudget",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "exactHashKeywordServerAttemptBudget",
        "settings.ed2k.exactHashKeywordServerAttemptBudget",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "sourceServerAttemptBudget",
        "settings.ed2k.sourceServerAttemptBudget",
        1,
    )?;
    validate_unsigned_number_range(
        object,
        "deadServerRetries",
        "settings.ed2k.deadServerRetries",
        1,
        10,
    )
}

fn validate_ed2k_upload_queue_settings_patch_body_fields(
    ed2k: &JsonObject,
) -> Result<(), Box<Response>> {
    let Some(object) = ed2k
        .get("uploadQueue")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    validate_unsigned_number_range(
        object,
        "activeSlots",
        "settings.ed2k.uploadQueue.activeSlots",
        1,
        64,
    )?;
    validate_unsigned_number_max(
        object,
        "elasticPercent",
        "settings.ed2k.uploadQueue.elasticPercent",
        100,
    )?;
    validate_unsigned_number_min(
        object,
        "elasticUnderfillSecs",
        "settings.ed2k.uploadQueue.elasticUnderfillSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "waitingTimeoutSecs",
        "settings.ed2k.uploadQueue.waitingTimeoutSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "grantedTimeoutSecs",
        "settings.ed2k.uploadQueue.grantedTimeoutSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "uploadTimeoutSecs",
        "settings.ed2k.uploadQueue.uploadTimeoutSecs",
        1,
    )?;
    validate_unsigned_number_max(
        object,
        "sessionTransferPercent",
        "settings.ed2k.uploadQueue.sessionTransferPercent",
        100,
    )
}

fn validate_kad_settings_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_nullable_unsigned_number_min(object, "listenPort", "settings.kad.listenPort", 1)?;
    validate_unsigned_number_min(
        object,
        "bootstrapMinRoutingContacts",
        "settings.kad.bootstrapMinRoutingContacts",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreKeywordTtlSecs",
        "settings.kad.localStoreKeywordTtlSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreSourceTtlSecs",
        "settings.kad.localStoreSourceTtlSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreNotesTtlSecs",
        "settings.kad.localStoreNotesTtlSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreKeywordCapacity",
        "settings.kad.localStoreKeywordCapacity",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreSourceCapacity",
        "settings.kad.localStoreSourceCapacity",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreNotesCapacity",
        "settings.kad.localStoreNotesCapacity",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreSourcePerFileCapacity",
        "settings.kad.localStoreSourcePerFileCapacity",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "localStoreNotesPerFileCapacity",
        "settings.kad.localStoreNotesPerFileCapacity",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "republishIntervalSecs",
        "settings.kad.republishIntervalSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "publishContactFanout",
        "settings.kad.publishContactFanout",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "udpFirewallCheckIntervalSecs",
        "settings.kad.udpFirewallCheckIntervalSecs",
        60,
    )?;
    validate_unsigned_number_min(
        object,
        "tcpFirewallCheckIntervalSecs",
        "settings.kad.tcpFirewallCheckIntervalSecs",
        60,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueDedupWindowSecs",
        "settings.kad.snoopQueueDedupWindowSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueGeneralMaxQueriesPer600s",
        "settings.kad.snoopQueueGeneralMaxQueriesPer600s",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueGeneralDrainCooldownSecs",
        "settings.kad.snoopQueueGeneralDrainCooldownSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueSourceMaxQueriesPer600s",
        "settings.kad.snoopQueueSourceMaxQueriesPer600s",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueSourceDrainCooldownSecs",
        "settings.kad.snoopQueueSourceDrainCooldownSecs",
        1,
    )?;
    validate_unsigned_number_min(
        object,
        "snoopQueueSourceStopAfterResults",
        "settings.kad.snoopQueueSourceStopAfterResults",
        1,
    )
}

fn validate_nat_settings_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let Some(backend_order) = object.get("backendOrder") else {
        return Ok(());
    };
    let Some(backend_order) = backend_order.as_array() else {
        return Err(invalid_nat_backend_order_error());
    };
    for backend in backend_order {
        let Some(backend) = backend.as_str() else {
            return Err(invalid_nat_backend_order_error());
        };
        if !NAT_BACKENDS.contains(&backend) {
            return Err(invalid_nat_backend_order_error());
        }
    }
    Ok(())
}

fn invalid_nat_backend_order_error() -> Box<Response> {
    invalid_body_error(format!(
        "settings.nat.backendOrder must contain only {}",
        NAT_BACKEND_UPNP_MINIUPNPC
    ))
}

fn validate_nullable_unsigned_number_min(
    object: &JsonObject,
    field: &'static str,
    path: &'static str,
    min: u64,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    validate_unsigned_number_min(object, field, path, min)
}

fn validate_vpn_guard_settings_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let Some(mode) = object.get("mode") else {
        return Ok(());
    };
    let Some(mode) = mode.as_str() else {
        return Err(invalid_body_error(
            "settings.vpnGuard.mode must be one of off, block",
        ));
    };
    if !VPN_GUARD_MODES.contains(&mode) {
        return Err(invalid_body_error(
            "settings.vpnGuard.mode must be one of off, block",
        ));
    }
    Ok(())
}

fn validate_unsigned_number_min(
    object: &JsonObject,
    field: &'static str,
    path: &'static str,
    min: u64,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(number) = value.as_u64() else {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number greater than or equal to {min}"
        )));
    };
    if number < min {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number greater than or equal to {min}"
        )));
    }
    Ok(())
}

fn validate_unsigned_number_max(
    object: &JsonObject,
    field: &'static str,
    path: &'static str,
    max: u64,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(number) = value.as_u64() else {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number less than or equal to {max}"
        )));
    };
    if number > max {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number less than or equal to {max}"
        )));
    }
    Ok(())
}

fn validate_unsigned_number_range(
    object: &JsonObject,
    field: &'static str,
    path: &'static str,
    min: u64,
    max: u64,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(number) = value.as_u64() else {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number in the range {min}..{max}"
        )));
    };
    if number < min || number > max {
        return Err(invalid_body_error(format!(
            "{path} must be an unsigned number in the range {min}..{max}"
        )));
    }
    Ok(())
}

fn validate_non_empty_update_object(object: &JsonObject, path: &str) -> Result<(), Box<Response>> {
    if object.is_empty() {
        return Err(invalid_body_error(format!(
            "{path} PATCH requires at least one setting"
        )));
    }
    Ok(())
}

pub(super) fn validate_destructive_confirmation_body_field(
    object: &JsonObject,
    field: &'static str,
    message: &'static str,
) -> Result<(), Box<Response>> {
    if object.get(field).and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(invalid_body_error(message));
    }
    Ok(())
}

pub(super) fn validate_transfer_add_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let has_link = object.contains_key("link");
    let has_links = object.contains_key("links");
    if has_link && has_links {
        return Err(invalid_body_error("link and links are mutually exclusive"));
    }
    if !has_link && !has_links {
        return Err(invalid_body_error("link or links is required"));
    }
    validate_paused_body_field(object)?;
    if let Some(link) = object.get("link") {
        validate_transfer_add_link(link)?;
    }
    if let Some(links) = object.get("links") {
        validate_transfer_add_links(links)?;
    }
    Ok(())
}

pub(super) fn validate_paused_body_field(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_optional_boolean_body_field(object, "paused")
}

pub(super) fn validate_optional_boolean_body_field(
    object: &JsonObject,
    field: &'static str,
) -> Result<(), Box<Response>> {
    if object.get(field).is_some_and(|value| !value.is_boolean()) {
        return Err(invalid_body_error(format!("{field} must be a boolean")));
    }
    Ok(())
}

pub(super) fn validate_transfer_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    let mut mutation_family_count = 0;
    if object.contains_key("priority") {
        mutation_family_count += 1;
    }
    if object.contains_key("categoryId") || object.contains_key("categoryName") {
        mutation_family_count += 1;
    }
    if object.contains_key("name") {
        mutation_family_count += 1;
    }
    if mutation_family_count == 0 {
        return Err(invalid_body_error(
            "transfer PATCH requires priority, categoryId, categoryName, or name",
        ));
    }
    if mutation_family_count > 1 {
        return Err(invalid_body_error(
            "transfer PATCH accepts only one mutation family",
        ));
    }
    if let Some(priority) = object.get("priority") {
        validate_transfer_priority_body_field(priority)?;
    }
    if let Some(name) = object.get("name") {
        validate_transfer_name_body_field(name)?;
    }
    Ok(())
}

fn validate_transfer_priority_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(priority) = value.as_str() else {
        return Err(invalid_body_error("priority must be a string"));
    };
    if !matches!(
        priority,
        "auto" | "verylow" | "low" | "normal" | "high" | "veryhigh"
    ) {
        return Err(invalid_body_error(
            "priority must be one of auto, verylow, low, normal, high, veryhigh",
        ));
    }
    Ok(())
}

fn validate_transfer_name_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(name) = value.as_str() else {
        return Err(invalid_body_error("name must be a string"));
    };
    let name = name.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if name.is_empty() {
        return Err(invalid_body_error("name must not be empty"));
    }
    if !is_valid_public_file_name(name) {
        return Err(invalid_body_error("name must be a valid eD2K filename"));
    }
    Ok(())
}

pub(super) fn validate_shared_file_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if !object.contains_key("priority")
        && !object.contains_key("comment")
        && !object.contains_key("rating")
    {
        return Err(invalid_body_error(
            "shared-file PATCH requires priority, comment, or rating",
        ));
    }
    if let Some(priority) = object.get("priority") {
        validate_shared_upload_priority_body_field(priority)?;
    }
    if object.contains_key("comment") || object.contains_key("rating") {
        validate_shared_file_comment_rating_body_fields(object)?;
    }
    Ok(())
}

fn validate_shared_upload_priority_body_field(
    value: &serde_json::Value,
) -> Result<(), Box<Response>> {
    let Some(priority) = value.as_str() else {
        return Err(invalid_body_error("priority must be a string"));
    };
    if !matches!(
        priority,
        "auto" | "verylow" | "low" | "normal" | "high" | "release"
    ) {
        return Err(invalid_body_error(
            "priority must be one of auto, verylow, low, normal, high, release",
        ));
    }
    Ok(())
}

fn validate_shared_file_comment_rating_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if !object
        .get("comment")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err(invalid_body_error("comment must be a string"));
    }

    let Some(rating) = object.get("rating").and_then(serde_json::Value::as_i64) else {
        return Err(invalid_body_error(
            "rating must be an integer between 0 and 5",
        ));
    };
    if !(0..=5).contains(&rating) {
        return Err(invalid_body_error(
            "rating must be an integer between 0 and 5",
        ));
    }
    Ok(())
}

pub(super) fn validate_shared_directories_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    let Some(roots) = object.get("roots").and_then(serde_json::Value::as_array) else {
        return Err(invalid_body_error("roots must be an array"));
    };
    for root in roots {
        validate_shared_directory_root_body(root)?;
    }
    Ok(())
}

fn validate_shared_directory_root_body(value: &serde_json::Value) -> Result<(), Box<Response>> {
    if let Some(object) = value.as_object() {
        for name in object.keys() {
            if name.as_str() != "path" {
                return Err(invalid_body_error(format!(
                    "unknown shared-directory root field: {name}"
                )));
            }
        }
        validate_path_text_body_field(object.get("path"), "path")?;
        return Ok(());
    }
    validate_path_text_body_field(Some(value), "path")
}

fn validate_path_text_body_field(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<(), Box<Response>> {
    let Some(path) = value.and_then(serde_json::Value::as_str) else {
        return Err(invalid_body_error(format!(
            "{field} must be a non-empty string path"
        )));
    };
    if path
        .trim_matches(|ch: char| ch.is_ascii_whitespace())
        .is_empty()
    {
        return Err(invalid_body_error(format!("{field} must not be empty")));
    }
    Ok(())
}

pub(super) fn validate_server_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_non_empty_text_body_field(object.get("address"), "address")?;
    validate_port_body_field(object.get("port"), "port")?;
    validate_optional_server_body_fields(object, true)
}

pub(super) fn validate_server_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    if !object.contains_key("name")
        && !object.contains_key("priority")
        && !object.contains_key("static")
        && !object.contains_key("enabled")
    {
        return Err(invalid_body_error(
            "server PATCH requires name, priority, static, or enabled",
        ));
    }
    validate_optional_server_body_fields(object, false)
}

pub(super) fn validate_url_import_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let Some(url) = object.get("url").and_then(serde_json::Value::as_str) else {
        return Err(invalid_body_error("url must be a non-empty string"));
    };
    validate_url_import_text(url, "url")
}

pub(super) fn validate_kad_bootstrap_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_non_empty_text_body_field(object.get("address"), "address")?;
    validate_port_body_field(object.get("port"), "port")
}

pub(super) fn validate_category_create_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    validate_category_core_body_fields(object, true)
}

pub(super) fn validate_category_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if object.is_empty() {
        return Err(invalid_body_error(
            "category PATCH requires at least one field",
        ));
    }
    validate_category_core_body_fields(object, false)
}

fn validate_category_core_body_fields(
    object: &JsonObject,
    require_name: bool,
) -> Result<(), Box<Response>> {
    if require_name || object.contains_key("name") {
        validate_non_empty_text_body_field(object.get("name"), "name")?;
    }
    if let Some(path) = object.get("path")
        && !path.is_null()
    {
        validate_path_text_body_field(Some(path), "path")?;
    }
    if object
        .get("comment")
        .is_some_and(|value| !value.is_string())
    {
        return Err(invalid_body_error("comment must be a string"));
    }
    if let Some(color) = object.get("color")
        && !color.is_null()
    {
        let Some(color) = color.as_u64() else {
            return Err(invalid_body_error("color must be null or an RGB integer"));
        };
        if color > 0x00ff_ffff {
            return Err(invalid_body_error("color must be null or an RGB integer"));
        }
    }
    if let Some(priority) = object.get("priority") {
        validate_category_priority_body_field(priority)?;
    }
    Ok(())
}

fn validate_category_priority_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    if let Some(priority) = value.as_u64() {
        if priority <= u32::MAX as u64 {
            return Ok(());
        }
        return Err(invalid_body_error(
            "priority must be a supported priority value",
        ));
    }
    let Some(priority) = value.as_str() else {
        return Err(invalid_body_error("priority must be a string or number"));
    };
    if !matches!(priority, "verylow" | "low" | "normal" | "high" | "veryhigh") {
        return Err(invalid_body_error(
            "priority must be one of verylow, low, normal, high, veryhigh",
        ));
    }
    Ok(())
}

pub(super) fn validate_friend_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let Some(user_hash) = object.get("userHash").and_then(serde_json::Value::as_str) else {
        return Err(invalid_body_error(
            "userHash must be a 32-character lowercase hex string",
        ));
    };
    if user_hash.len() != 32
        || !user_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_body_error(
            "userHash must be a 32-character lowercase hex string",
        ));
    }
    if let Some(name) = object.get("name") {
        validate_friend_name_body_field(name)?;
    }
    Ok(())
}

fn validate_friend_name_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(name) = value.as_str() else {
        return Err(invalid_body_error("name must be a string"));
    };
    if name.chars().any(char::is_control) {
        return Err(invalid_body_error(
            "name must be valid UTF-8 without control characters",
        ));
    }
    if name.encode_utf16().count() > 128 {
        return Err(invalid_body_error("name must be at most 128 characters"));
    }
    Ok(())
}

fn validate_optional_server_body_fields(
    object: &JsonObject,
    allow_connect: bool,
) -> Result<(), Box<Response>> {
    if object.get("name").is_some_and(|value| !value.is_string()) {
        return Err(invalid_body_error("name must be a string when provided"));
    }
    if let Some(priority) = object.get("priority") {
        validate_server_priority_body_field(priority)?;
    }
    if object
        .get("static")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_body_error("static must be a boolean"));
    }
    if object
        .get("enabled")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_body_error("enabled must be a boolean"));
    }
    if allow_connect
        && object
            .get("connect")
            .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_body_error("connect must be a boolean"));
    }
    Ok(())
}

fn validate_non_empty_text_body_field(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<(), Box<Response>> {
    let Some(text) = value.and_then(serde_json::Value::as_str) else {
        return Err(invalid_body_error(format!(
            "{field} must be a non-empty string"
        )));
    };
    if text
        .trim_matches(|ch: char| ch.is_ascii_whitespace())
        .is_empty()
    {
        return Err(invalid_body_error(format!("{field} must not be empty")));
    }
    Ok(())
}

fn validate_port_body_field(
    value: Option<&serde_json::Value>,
    field: &'static str,
) -> Result<(), Box<Response>> {
    let Some(port) = value.and_then(serde_json::Value::as_u64) else {
        return Err(invalid_body_error(format!(
            "{field} must be in the range 1..65535"
        )));
    };
    if !(1..=u16::MAX as u64).contains(&port) {
        return Err(invalid_body_error(format!(
            "{field} must be in the range 1..65535"
        )));
    }
    Ok(())
}

fn validate_server_priority_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(priority) = value.as_str() else {
        return Err(invalid_body_error("priority must be a string"));
    };
    if !matches!(priority, "low" | "normal" | "high") {
        return Err(invalid_body_error(
            "priority must be one of low, normal, high",
        ));
    }
    Ok(())
}

fn validate_transfer_add_link(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(link) = value.as_str() else {
        return Err(invalid_body_error("link must be a string"));
    };
    validate_ed2k_link_text(link, "link").map_err(invalid_body_error)
}

fn validate_transfer_add_links(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(links) = value.as_array() else {
        return Err(invalid_body_error("links must be a string array"));
    };
    if links.is_empty() {
        return Err(invalid_body_error("links must not be empty"));
    }
    if links.len() > MAX_TRANSFER_ADD_LINKS {
        return Err(invalid_body_error("links contains too many items"));
    }
    for link in links {
        let Some(link) = link.as_str() else {
            return Err(invalid_body_error("links must be a non-empty string array"));
        };
        if validate_ed2k_link_text(link, "link").is_err() {
            return Err(invalid_body_error("links must be a non-empty string array"));
        }
    }
    Ok(())
}

fn validate_ed2k_link_text(value: &str, field: &'static str) -> Result<(), String> {
    let normalized = value.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if normalized.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if normalized.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be valid UTF-8 without control characters"
        ));
    }
    if normalized.encode_utf16().count() > 2048 {
        return Err(format!("{field} must be at most 2048 characters"));
    }
    if normalized.chars().any(char::is_whitespace) {
        return Err(format!("{field} must not contain whitespace"));
    }
    if !normalized
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ed2k://"))
    {
        return Err(format!("{field} must start with ed2k://"));
    }
    Ok(())
}

fn validate_url_import_text(value: &str, field: &'static str) -> Result<(), Box<Response>> {
    let normalized = value.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if normalized.is_empty() {
        return Err(invalid_body_error(format!("{field} must not be empty")));
    }
    if normalized.chars().any(char::is_control) {
        return Err(invalid_body_error(format!(
            "{field} must be valid UTF-8 without control characters"
        )));
    }
    if normalized.encode_utf16().count() > 2048 {
        return Err(invalid_body_error(format!(
            "{field} must be at most 2048 characters"
        )));
    }
    if normalized.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err(invalid_body_error(format!(
            "{field} must not contain whitespace"
        )));
    }
    let lower = normalized.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(invalid_body_error(format!(
            "{field} must start with http:// or https://"
        )));
    }
    let host_begin = lower.find("://").expect("validated URL scheme") + 3;
    if host_begin >= normalized.len()
        || matches!(normalized.as_bytes()[host_begin], b'/' | b'?' | b'#')
    {
        return Err(invalid_body_error(format!("{field} must include a host")));
    }
    Ok(())
}

fn is_valid_public_file_name(name: &str) -> bool {
    !name.chars().any(|character| {
        matches!(
            character,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        ) || character.is_control()
    })
}
