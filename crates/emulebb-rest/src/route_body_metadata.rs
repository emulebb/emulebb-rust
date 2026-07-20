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
    validate_optional_boolean_body_field, validate_paused_body_field,
    validate_search_create_body_fields, validate_server_create_body_fields,
    validate_server_patch_body_fields, validate_shared_directories_patch_body_fields,
    validate_shared_directory_root_body_fields, validate_shared_file_patch_body_fields,
    validate_transfer_add_body_fields, validate_transfer_patch_body_fields,
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
    if object.contains_key("categoryId") && object.contains_key("categoryName") {
        return Err(invalid_body_error(
            "categoryId and categoryName are mutually exclusive",
        ));
    }
    if let Some(category_id) = object.get("categoryId") {
        let Some(category_id) = category_id.as_u64() else {
            return Err(invalid_body_error("categoryId must be an unsigned number"));
        };
        if category_id > u32::MAX as u64 {
            return Err(invalid_body_error("categoryId is out of range"));
        }
        return Ok(());
    }
    if let Some(category_name) = object.get("categoryName") {
        let Some(category_name) = category_name.as_str() else {
            return Err(invalid_body_error("categoryName must be a string"));
        };
        if category_name
            .trim_matches(|ch: char| ch.is_ascii_whitespace())
            .is_empty()
        {
            return Err(invalid_body_error(
                "categoryName does not match a configured category",
            ));
        }
    }
    Ok(())
}

fn validate_route_specific_body_fields(
    method: &str,
    path: &str,
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if method == "POST" && path == "/api/v1/transfers" {
        return validate_transfer_add_body_fields(object);
    }
    if method == "PATCH" && path_matches_transfer(path) {
        return validate_transfer_patch_body_fields(object);
    }
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
    if uses_paused_body(method, path) {
        return validate_paused_body_field(object);
    }
    if method == "POST" && path == "/api/v1/diagnostics/dumps" {
        validate_destructive_confirmation_body(method, path, object)?;
        return validate_optional_boolean_body_field(object, "fullMemory");
    }
    validate_destructive_confirmation_body(method, path, object)
}

fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const TRANSFER_ADD: &[&str] = &["link", "links", "categoryId", "categoryName", "paused"];
    const TRANSFER_PATCH: &[&str] = &["name", "priority", "categoryId", "categoryName"];
    const SEARCH_RESULT_DOWNLOAD: &[&str] = &["categoryId", "categoryName", "paused"];
    const SHARED_FILE_PATCH: &[&str] = &["priority", "comment", "rating"];
    const SHARED_DIRECTORIES_PATCH: &[&str] = &["roots", "confirmReplaceRoots"];
    const SHARED_DIRECTORY_ROOT: &[&str] = &["path"];
    const CONFIRM_SHUTDOWN: &[&str] = &["confirmShutdown"];
    const DIAGNOSTIC_DUMP: &[&str] = &["confirmDump", "fullMemory"];
    const CONFIRM_CRASH: &[&str] = &["confirmCrash"];
    const APP_SETTINGS: &[&str] = &[
        "core", "daemon", "ed2k", "kad", "nat", "vpnGuard", "ipFilter",
    ];
    const CONFIRM_CLEAR_COMPLETED: &[&str] = &["confirmClearCompleted"];
    const CONFIRM_CLEAR_LOGS: &[&str] = &["confirmClearLogs"];
    const SERVER_CREATE: &[&str] = &["address", "port", "name", "priority", "static", "connect"];
    const SERVER_PATCH: &[&str] = &["name", "priority", "static", "enabled"];
    const CATEGORY: &[&str] = &["name", "path", "comment", "color", "priority"];
    const FRIEND_CREATE: &[&str] = &["userHash", "name"];
    const SEARCH_CREATE: &[&str] = &[
        "query",
        "method",
        "type",
        "minSizeBytes",
        "maxSizeBytes",
        "minAvailability",
        "extension",
    ];
    const URL_IMPORT: &[&str] = &["url"];
    const KAD_BOOTSTRAP: &[&str] = &["address", "port"];
    const EMPTY: &[&str] = &[];

    if method == "POST" && path == "/api/v1/transfers" {
        return Some(TRANSFER_ADD);
    }
    if method == "PATCH" && path == "/api/v1/shared-directories" {
        return Some(SHARED_DIRECTORIES_PATCH);
    }
    if method == "POST" && path == "/api/v1/shared-directories/roots" {
        return Some(SHARED_DIRECTORY_ROOT);
    }
    if method == "POST" && path == "/api/v1/app/shutdown" {
        return Some(CONFIRM_SHUTDOWN);
    }
    if method == "POST" && path == "/api/v1/diagnostics/dumps" {
        return Some(DIAGNOSTIC_DUMP);
    }
    if method == "POST" && path == "/api/v1/diagnostics/crash-tests" {
        return Some(CONFIRM_CRASH);
    }
    if method == "PATCH" && path == "/api/v1/app/settings" {
        return Some(APP_SETTINGS);
    }
    if method == "POST" && path == "/api/v1/transfers/operations/clear-completed" {
        return Some(CONFIRM_CLEAR_COMPLETED);
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
        ("PATCH", ["transfers", _]) => Some(TRANSFER_PATCH),
        ("PATCH", ["shared-files", _]) => Some(SHARED_FILE_PATCH),
        ("PATCH", ["servers", _]) => Some(SERVER_PATCH),
        ("PATCH", ["categories", _]) => Some(CATEGORY),
        ("POST", ["searches", _, "results", _, "operations", "download"]) => {
            Some(SEARCH_RESULT_DOWNLOAD)
        }
        _ => None,
    }
}

fn path_matches_transfer(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["transfers", _]))
}

fn path_matches_shared_file(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["shared-files", _]))
}

fn path_matches_server(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["servers", _]))
}

fn path_matches_category(path: &str) -> bool {
    api_segments(path).is_some_and(|segments| matches!(segments.as_slice(), ["categories", _]))
}

fn uses_category_selector_body(method: &str, path: &str) -> bool {
    if method == "POST" && path == "/api/v1/transfers" {
        return true;
    }
    let Some(segments) = api_segments(path) else {
        return false;
    };
    matches!(
        (method, segments.as_slice()),
        ("PATCH", ["transfers", _])
            | (
                "POST",
                ["searches", _, "results", _, "operations", "download"]
            )
    )
}

fn uses_paused_body(method: &str, path: &str) -> bool {
    method == "POST"
        && (path == "/api/v1/transfers"
            || api_segments(path).is_some_and(|segments| {
                matches!(
                    segments.as_slice(),
                    ["searches", _, "results", _, "operations", "download"]
                )
            }))
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
        ("POST", "/api/v1/diagnostics/dumps") => Some(("confirmDump", "confirmDump must be true")),
        ("POST", "/api/v1/diagnostics/crash-tests") => {
            Some(("confirmCrash", "confirmCrash must be true"))
        }
        ("POST", "/api/v1/transfers/operations/clear-completed") => Some((
            "confirmClearCompleted",
            "confirmClearCompleted must be true",
        )),
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
