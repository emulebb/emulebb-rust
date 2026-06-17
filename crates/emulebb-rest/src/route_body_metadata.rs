//! REST JSON body metadata validation shared by the route middleware.
//!
//! The ordering mirrors the MFC route seam: object-shape validation, unknown
//! fields, category selector normalization/validation, then route-specific body
//! rules.

mod validators;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::envelope::{api_error, json_error_message};
use validators::{
    validate_paused_body_field, validate_server_create_body_fields,
    validate_server_patch_body_fields, validate_shared_directories_patch_body_fields,
    validate_shared_file_add_body_fields, validate_shared_file_patch_body_fields,
    validate_transfer_add_body_fields, validate_transfer_patch_body_fields,
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
    let Some(category_id) = object.get("categoryId") else {
        return Ok(());
    };
    let Some(category_id) = category_id.as_u64() else {
        return Err(invalid_body_error("categoryId must be an unsigned number"));
    };
    if category_id > u32::MAX as u64 {
        return Err(invalid_body_error("categoryId is out of range"));
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
    if method == "POST" && path == "/api/v1/shared-files" {
        return validate_shared_file_add_body_fields(object);
    }
    if method == "PATCH" && path == "/api/v1/shared-directories" {
        return validate_shared_directories_patch_body_fields(object);
    }
    if method == "POST" && path == "/api/v1/servers" {
        return validate_server_create_body_fields(object);
    }
    if method == "PATCH" && path_matches_server(path) {
        return validate_server_patch_body_fields(object);
    }
    if uses_paused_body(method, path) {
        return validate_paused_body_field(object);
    }
    Ok(())
}

fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const TRANSFER_ADD: &[&str] = &["link", "links", "categoryId", "categoryName", "paused"];
    const TRANSFER_PATCH: &[&str] = &["name", "priority", "categoryId", "categoryName"];
    const SEARCH_RESULT_DOWNLOAD: &[&str] = &["categoryId", "categoryName", "paused"];
    const SHARED_FILE_PATCH: &[&str] = &["priority", "comment", "rating"];
    const SHARED_FILE_ADD: &[&str] = &["path"];
    const SHARED_DIRECTORIES_PATCH: &[&str] = &["roots", "confirmReplaceRoots"];
    const SERVER_CREATE: &[&str] = &["address", "port", "name", "priority", "static", "connect"];
    const SERVER_PATCH: &[&str] = &["name", "priority", "static"];

    if method == "POST" && path == "/api/v1/transfers" {
        return Some(TRANSFER_ADD);
    }
    if method == "POST" && path == "/api/v1/shared-files" {
        return Some(SHARED_FILE_ADD);
    }
    if method == "PATCH" && path == "/api/v1/shared-directories" {
        return Some(SHARED_DIRECTORIES_PATCH);
    }
    if method == "POST" && path == "/api/v1/servers" {
        return Some(SERVER_CREATE);
    }
    let segments = api_segments(path)?;
    match (method, segments.as_slice()) {
        ("PATCH", ["transfers", _]) => Some(TRANSFER_PATCH),
        ("PATCH", ["shared-files", _]) => Some(SHARED_FILE_PATCH),
        ("PATCH", ["servers", _]) => Some(SERVER_PATCH),
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

fn api_segments(path: &str) -> Option<Vec<&str>> {
    path.strip_prefix("/api/v1/")
        .map(|path| path.split('/').collect::<Vec<_>>())
}

pub(super) fn invalid_body_error(message: impl Into<String>) -> Box<Response> {
    Box::new(api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response())
}
