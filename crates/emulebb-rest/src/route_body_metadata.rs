//! REST JSON body metadata validation shared by the route middleware.
//!
//! Validation is deliberately staged: object shape, unknown fields, category
//! selector normalization, route-specific rules, then destructive confirmations.

mod validators;

use crate::envelope::{api_error, json_error_message};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use validators::{
    validate_app_settings_patch_body_fields, validate_category_create_body_fields,
    validate_category_patch_body_fields, validate_destructive_confirmation_body_field,
    validate_friend_create_body_fields, validate_kad_bootstrap_body_fields,
    validate_search_create_body_fields, validate_server_create_body_fields,
    validate_server_patch_body_fields, validate_shared_directories_patch_body_fields,
    validate_shared_directory_root_body_fields, validate_shared_file_ignore_pattern_body_fields,
    validate_shared_file_ignore_rule_body_fields, validate_shared_file_patch_body_fields,
    validate_url_import_body_fields,
};

pub(super) type JsonObject = serde_json::Map<String, serde_json::Value>;

pub(crate) fn validate_json_body_fields(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), Box<Response>> {
    let value = serde_json::from_slice::<serde_json::Value>(body).map_err(|error| {
        Box::new(
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_ARGUMENT",
                json_error_message(&error),
            )
            .into_response(),
        )
    })?;
    let Some(object) = value.as_object() else {
        return Err(invalid_body_error("JSON body must be an object"));
    };
    validate_allowed_body_fields(method, path, object)?;
    validate_category_selector_body(method, path, object)?;
    validate_route_specific_body_fields(method, path, object)
}

fn validate_allowed_body_fields(
    method: &str,
    path: &str,
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    let Some(allowed_fields) = route_body_fields(method, path) else {
        return Ok(());
    };
    for name in object.keys() {
        if !allowed_fields.contains(&name.as_str()) {
            return Err(invalid_body_error(format!("unknown JSON field: {name}")));
        }
    }
    Ok(())
}

fn validate_category_selector_body(
    method: &str,
    path: &str,
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if !uses_category_selector_body(method, path) {
        return Ok(());
    }
    if let Some(category) = object.get("category") {
        if category.is_null() {
            return Ok(());
        }
        let Some(category_name) = category.as_str() else {
            return Err(invalid_body_error("category must be a string or null"));
        };
        if !emulebb_core::valid_category_name(category_name) {
            return Err(invalid_body_error("category must be a valid category name"));
        }
    }
    Ok(())
}

fn validate_route_specific_body_fields(
    method: &str,
    path: &str,
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if method == "PATCH" && path_matches_shared_file(path) {
        return validate_shared_file_patch_body_fields(object);
    }
    if method == "PATCH" && path == "/api/v1/shared-directories" {
        validate_shared_directories_patch_body_fields(object)?;
        return validate_destructive_confirmation_body(method, path, object);
    }
    if method == "POST" && path == "/api/v1/shared-directories/roots" {
        return validate_shared_directory_root_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/shared-directories/ignores" {
        return validate_shared_file_ignore_pattern_body_fields(object);
    }
    if method == "PATCH" && path_matches_shared_file_ignore_rule(path) {
        return validate_shared_file_ignore_rule_body_fields(object);
    }
    if method == "PATCH" && path == "/api/v1/app/settings" {
        validate_app_settings_patch_body_fields(object)?;
        return validate_destructive_confirmation_body(method, path, object);
    }
    if method == "POST" && path == "/api/v1/servers" {
        return validate_server_create_body_fields(object);
    }
    if method == "PATCH" && path_matches_server(path) {
        return validate_server_patch_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/categories" {
        return validate_category_create_body_fields(object);
    }
    if method == "PATCH" && path_matches_category(path) {
        return validate_category_patch_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/friends" {
        return validate_friend_create_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/searches" {
        return validate_search_create_body_fields(object);
    }
    if uses_url_import_body(method, path) {
        return validate_url_import_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/kad/operations/bootstrap" {
        return validate_kad_bootstrap_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/diagnostics/bundles" {
        return validate_destructive_confirmation_body(method, path, object);
    }
    validate_destructive_confirmation_body(method, path, object)
}

fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const DOWNLOAD_CREATE: &[&str] = &["source", "category", "intent", "redownload"];
    const DOWNLOAD_IDS: &[&str] = &["ids"];
    const DOWNLOAD_REMOVE: &[&str] = &["ids", "deleteData"];
    const DOWNLOAD_PATCH: &[&str] = &["name", "category", "sizeBytes"];
    const SEARCH_RESULT_DOWNLOAD: &[&str] = &["category", "intent", "redownload"];
    const SHARED_FILE_PATCH: &[&str] = &["priority", "comment", "rating"];
    const SHARED_DIRECTORIES_PATCH: &[&str] = &["roots", "confirmReplaceRoots"];
    const SHARED_DIRECTORY_ROOT: &[&str] = &["path"];
    const SHARED_FILE_IGNORE_PATTERN: &[&str] = &["pattern"];
    const SHARED_FILE_IGNORE_RULE: &[&str] = &["enabled"];
    const CONFIRM_SHUTDOWN: &[&str] = &["confirmShutdown"];
    const DIAGNOSTIC_BUNDLE: &[&str] = &["confirmCapture", "maxBytes"];
    const CONFIRM_CRASH: &[&str] = &["confirmCrash"];
    const APP_SETTINGS: &[&str] = &[
        "core", "daemon", "ed2k", "kad", "nat", "vpnGuard", "ipFilter",
    ];
    const CONFIRM_CLEAR_LOGS: &[&str] = &["confirmClearLogs"];
    const SERVER_CREATE: &[&str] = &["address", "port", "name", "priority", "static", "connect"];
    const SERVER_PATCH: &[&str] = &["name", "priority", "static", "enabled"];
    const CATEGORY: &[&str] = &["name", "tempDir", "destinationDir", "comment"];
    const CATEGORY_PATCH: &[&str] = &["tempDir", "destinationDir", "comment"];
    const FRIEND_CREATE: &[&str] = &["userHash", "name"];
    const SEARCH_CREATE: &[&str] = &[
        "query",
        "method",
        "type",
        "minSizeBytes",
        "maxSizeBytes",
        "minAvailability",
        "minCompleteSources",
        "minBitrateKbps",
        "minLengthSeconds",
        "extension",
        "codec",
        "title",
        "album",
        "artist",
    ];
    const URL_IMPORT: &[&str] = &["url"];
    const KAD_BOOTSTRAP: &[&str] = &["address", "port"];
    const EMPTY: &[&str] = &[];
    #[cfg(feature = "packet-diagnostics")]
    const QUEUED_LOWID_SOURCE_FIXTURE: &[&str] = &[
        "fileHash",
        "sourceIp",
        "sourceTcpPort",
        "sourceUdpPort",
        "sourceUserHash",
        "sourceUdpVersion",
        "buddyIp",
        "buddyUdpPort",
        "buddyId",
    ];
    #[cfg(feature = "packet-diagnostics")]
    const QUEUED_SOURCE_REASK_CONTROL: &[&str] = &[
        "fileHash",
        "sourceIp",
        "sourceTcpPort",
        "sourceUdpPort",
        "sourceUserHash",
        "sourceUdpVersion",
    ];
    #[cfg(feature = "packet-diagnostics")]
    const CLIENT_UDP_QUEUE_PRESSURE_FIXTURE: &[&str] = &["fileHash", "sourceIp", "sourceUdpPort"];

    #[cfg(feature = "packet-diagnostics")]
    if method == "POST" && path == "/api/v1/diagnostics/protocol-fixtures/queued-lowid-sources" {
        return Some(QUEUED_LOWID_SOURCE_FIXTURE);
    }
    #[cfg(feature = "packet-diagnostics")]
    if method == "POST" && path == "/api/v1/diagnostics/protocol-fixtures/buddy-relay-eligibility" {
        return Some(EMPTY);
    }
    #[cfg(feature = "packet-diagnostics")]
    if method == "POST" && path == "/api/v1/diagnostics/protocol-fixtures/client-udp-queue-pressure"
    {
        return Some(CLIENT_UDP_QUEUE_PRESSURE_FIXTURE);
    }
    #[cfg(feature = "packet-diagnostics")]
    if method == "POST" && path == "/api/v1/diagnostics/protocol-controls/queued-source-reasks" {
        return Some(QUEUED_SOURCE_REASK_CONTROL);
    }

    if method == "POST" && path == "/api/v1/downloads" {
        return Some(DOWNLOAD_CREATE);
    }
    if method == "POST"
        && matches!(
            path,
            "/api/v1/downloads/start" | "/api/v1/downloads/stop" | "/api/v1/downloads/verify"
        )
    {
        return Some(DOWNLOAD_IDS);
    }
    if method == "POST" && path == "/api/v1/downloads/remove" {
        return Some(DOWNLOAD_REMOVE);
    }
    if method == "PATCH" && path == "/api/v1/shared-directories" {
        return Some(SHARED_DIRECTORIES_PATCH);
    }
    if method == "POST" && path == "/api/v1/shared-directories/roots" {
        return Some(SHARED_DIRECTORY_ROOT);
    }
    if method == "POST" && path == "/api/v1/shared-directories/ignores" {
        return Some(SHARED_FILE_IGNORE_PATTERN);
    }
    if method == "POST" && path == "/api/v1/app/shutdown" {
        return Some(CONFIRM_SHUTDOWN);
    }
    if method == "POST" && path == "/api/v1/diagnostics/bundles" {
        return Some(DIAGNOSTIC_BUNDLE);
    }
    if method == "POST" && path == "/api/v1/diagnostics/crash-tests" {
        return Some(CONFIRM_CRASH);
    }
    if method == "PATCH" && path == "/api/v1/app/settings" {
        return Some(APP_SETTINGS);
    }
    if method == "POST" && path == "/api/v1/logs/operations/clear" {
        return Some(CONFIRM_CLEAR_LOGS);
    }
    if method == "POST" && path == "/api/v1/ip-filter/operations/reload" {
        return Some(EMPTY);
    }
    if method == "POST" && path == "/api/v1/nat/operations/refresh" {
        return Some(EMPTY);
    }
    if method == "POST" && path == "/api/v1/vpn-guard/operations/probe" {
        return Some(EMPTY);
    }
    if method == "POST" && path == "/api/v1/servers" {
        return Some(SERVER_CREATE);
    }
    if method == "POST" && path == "/api/v1/categories" {
        return Some(CATEGORY);
    }
    if method == "POST" && path == "/api/v1/friends" {
        return Some(FRIEND_CREATE);
    }
    if method == "POST" && path == "/api/v1/searches" {
        return Some(SEARCH_CREATE);
    }
    if uses_url_import_body(method, path) {
        return Some(URL_IMPORT);
    }
    if method == "POST" && path == "/api/v1/kad/operations/bootstrap" {
        return Some(KAD_BOOTSTRAP);
    }
    let segments = api_segments(path)?;
    match (method, segments.as_slice()) {
        ("PATCH", ["downloads", _]) => Some(DOWNLOAD_PATCH),
        ("POST", ["downloads", _, "sources", _, "operations", _]) => Some(EMPTY),
        ("PATCH", ["shared-files", _]) => Some(SHARED_FILE_PATCH),
        ("PATCH", ["shared-directories", "ignores", "defaults", _]) => {
            Some(SHARED_FILE_IGNORE_RULE)
        }
        ("PATCH", ["servers", _]) => Some(SERVER_PATCH),
        ("PATCH", ["categories", _]) => Some(CATEGORY_PATCH),
        ("POST", ["searches", _, "results", _, "operations", "download"]) => {
            Some(SEARCH_RESULT_DOWNLOAD)
        }
        _ => None,
    }
}

fn path_matches_shared_file(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["shared-files", _]))
}

fn path_matches_shared_file_ignore_rule(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| {
        matches!(
            segments.as_slice(),
            ["shared-directories", "ignores", "defaults", _]
        )
    })
}

fn path_matches_server(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["servers", _]))
}

fn path_matches_category(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["categories", _]))
}

fn uses_category_selector_body(method: &str, path: &str) -> bool {
    if method == "POST" && path == "/api/v1/downloads" {
        return true;
    }
    let Some(segments) = api_segments(path) else {
        return false;
    };
    matches!(
        (method, segments.as_slice()),
        ("PATCH", ["downloads", _])
            | (
                "POST",
                ["searches", _, "results", _, "operations", "download"]
            )
    )
}

fn uses_url_import_body(method: &str, path: &str) -> bool {
    method == "POST"
        && matches!(
            path,
            "/api/v1/servers/operations/import-met-url" | "/api/v1/kad/operations/import-nodes-url"
        )
}

fn validate_destructive_confirmation_body(
    method: &str,
    path: &str,
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if let Some((field, message)) = destructive_confirmation_field(method, path) {
        validate_destructive_confirmation_body_field(object, field, message)?;
    }
    Ok(())
}

fn destructive_confirmation_field(
    method: &str,
    path: &str,
) -> Option<(&'static str, &'static str)> {
    match (method, path) {
        ("POST", "/api/v1/app/shutdown") => {
            Some(("confirmShutdown", "confirmShutdown must be true"))
        }
        ("POST", "/api/v1/diagnostics/bundles") => {
            Some(("confirmCapture", "confirmCapture must be true"))
        }
        ("POST", "/api/v1/diagnostics/crash-tests") => {
            Some(("confirmCrash", "confirmCrash must be true"))
        }
        ("POST", "/api/v1/logs/operations/clear") => {
            Some(("confirmClearLogs", "confirmClearLogs must be true"))
        }
        ("PATCH", "/api/v1/shared-directories") => {
            Some(("confirmReplaceRoots", "confirmReplaceRoots must be true"))
        }
        _ => None,
    }
}

fn api_segments(path: &str) -> Option<Vec<&str>> {
    path.strip_prefix("/api/v1/")
        .map(|path| path.split('/').collect::<Vec<_>>())
}

pub(super) fn invalid_body_error(message: impl Into<String>) -> Box<Response> {
    Box::new(api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response())
}
