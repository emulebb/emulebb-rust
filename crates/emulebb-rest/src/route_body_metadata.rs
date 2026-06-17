//! REST JSON body metadata validation shared by the route middleware.
//!
//! The ordering mirrors the MFC route seam: object-shape validation, unknown
//! fields, category selector normalization/validation, then route-specific body
//! rules.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::envelope::{api_error, json_error_message};

type JsonObject = serde_json::Map<String, serde_json::Value>;
const MAX_TRANSFER_ADD_LINKS: usize = 100;

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
    validate_paused_body_field(object)?;
    if let Some(link) = object.get("link") {
        validate_transfer_add_link(link)?;
    }
    if let Some(links) = object.get("links") {
        validate_transfer_add_links(links)?;
    }
    Ok(())
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

fn validate_transfer_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
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

fn validate_shared_file_patch_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
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

fn route_body_fields(method: &str, path: &str) -> Option<&'static [&'static str]> {
    const TRANSFER_ADD: &[&str] = &["link", "links", "categoryId", "categoryName", "paused"];
    const TRANSFER_PATCH: &[&str] = &["name", "priority", "categoryId", "categoryName"];
    const SEARCH_RESULT_DOWNLOAD: &[&str] = &["categoryId", "categoryName", "paused"];
    const SHARED_FILE_PATCH: &[&str] = &["priority", "comment", "rating"];

    if method == "POST" && path == "/api/v1/transfers" {
        return Some(TRANSFER_ADD);
    }
    let segments = api_segments(path)?;
    match (method, segments.as_slice()) {
        ("PATCH", ["transfers", _]) => Some(TRANSFER_PATCH),
        ("PATCH", ["shared-files", _]) => Some(SHARED_FILE_PATCH),
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

fn is_valid_public_file_name(name: &str) -> bool {
    !name.chars().any(|character| {
        matches!(
            character,
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
        ) || character.is_control()
    })
}

fn invalid_body_error(message: impl Into<String>) -> Box<Response> {
    Box::new(api_error(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message).into_response())
}
