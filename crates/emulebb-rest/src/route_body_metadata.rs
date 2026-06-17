//! REST JSON body metadata validation shared by the route middleware.
//!
//! The ordering mirrors the MFC route seam: unknown fields first, category
//! selector normalization/validation, then route-specific body rules.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::envelope::{api_error, json_error_message};

type JsonObject = serde_json::Map<String, serde_json::Value>;

pub(crate) fn validate_json_body_fields(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), Box<Response>> {
    if route_body_fields(method, path).is_none() {
        return Ok(());
    }
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
        return Ok(());
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
    if uses_paused_body(method, path) {
        return validate_paused_body_field(object);
    }
    Ok(())
}

fn validate_transfer_add_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    let has_link = object.contains_key("link");
    let has_links = object.contains_key("links");
    if has_link && has_links {
        return Err(invalid_body_error("link and links are mutually exclusive"));
    }
    if !has_link && !has_links {
        return Err(invalid_body_error("link or links is required"));
    }
    validate_paused_body_field(object)
}

fn validate_paused_body_field(object: &JsonObject) -> Result<(), Box<Response>> {
    if object
        .get("paused")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_body_error("paused must be a boolean"));
    }
    Ok(())
}

fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const TRANSFER_ADD: &[&str] = &["link", "links", "categoryId", "categoryName", "paused"];
    const TRANSFER_PATCH: &[&str] = &["name", "priority", "categoryId", "categoryName"];
    const SEARCH_RESULT_DOWNLOAD: &[&str] = &["categoryId", "categoryName", "paused"];

    if method == "POST" && path == "/api/v1/transfers" {
        return Some(TRANSFER_ADD);
    }
    let segments = api_segments(path)?;
    match (method, segments.as_slice()) {
        ("PATCH", ["transfers", _]) => Some(TRANSFER_PATCH),
        ("POST", ["searches", _, "results", _, "operations", "download"]) => {
            Some(SEARCH_RESULT_DOWNLOAD)
        }
        _ => None,
    }
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

fn invalid_body_error(message: impl Into<String>) -> Box<Response> {
    Box::new(api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response())
}
