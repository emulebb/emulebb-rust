//! Current route-body validators; product settings validate in their typed owner.
mod search;
use super::{JsonObject, invalid_body_error};
use axum::response::Response;

pub(super) fn validate_search_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    search::validate_search_create_body_fields(object)
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

pub(super) fn validate_optional_boolean_body_field(
    object: &JsonObject,
    field: &'static str,
) -> Result<(), Box<Response>> {
    if object.get(field).is_some_and(|value| !value.is_boolean()) {
        return Err(invalid_body_error(format!("{field} must be a boolean")));
    }
    Ok(())
}

pub(super) fn validate_library_file_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if !object.contains_key("uploadPriority")
        && !object.contains_key("comment")
        && !object.contains_key("rating")
    {
        return Err(invalid_body_error(
            "library file PATCH requires uploadPriority, comment, or rating",
        ));
    }
    if let Some(priority) = object.get("uploadPriority") {
        validate_library_upload_priority_body_field(priority)?;
    }
    if object.contains_key("comment") || object.contains_key("rating") {
        validate_shared_file_comment_rating_body_fields(object)?;
    }
    Ok(())
}

fn validate_library_upload_priority_body_field(
    value: &serde_json::Value,
) -> Result<(), Box<Response>> {
    let Some(priority) = value.as_str() else {
        return Err(invalid_body_error("uploadPriority must be a string"));
    };
    if !matches!(
        priority,
        "auto" | "verylow" | "low" | "normal" | "high" | "release"
    ) {
        return Err(invalid_body_error(
            "uploadPriority must be one of auto, verylow, low, normal, high, release",
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

pub(super) fn validate_library_root_create_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    for name in object.keys() {
        if !matches!(name.as_str(), "path" | "watchEnabled") {
            return Err(invalid_body_error(format!(
                "unknown library root field: {name}"
            )));
        }
    }
    validate_path_text_body_field(object.get("path"), "path")?;
    validate_optional_boolean_body_field(object, "watchEnabled")
}

pub(super) fn validate_library_root_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if !object
        .get("watchEnabled")
        .is_some_and(serde_json::Value::is_boolean)
    {
        return Err(invalid_body_error("watchEnabled must be a boolean"));
    }
    Ok(())
}

pub(super) fn validate_shared_file_ignore_pattern_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    let Some(pattern) = object.get("pattern").and_then(|value| value.as_str()) else {
        return Err(invalid_body_error("pattern must be a non-empty string"));
    };
    if pattern.is_empty() {
        return Err(invalid_body_error("pattern must be a non-empty string"));
    }
    Ok(())
}

pub(super) fn validate_shared_file_ignore_rule_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if object.keys().any(|name| name != "enabled") {
        return Err(invalid_body_error(
            "shared-file ignore rule only accepts enabled",
        ));
    }
    let Some(enabled) = object.get("enabled") else {
        return Err(invalid_body_error("enabled is required"));
    };
    if !enabled.is_boolean() {
        return Err(invalid_body_error("enabled must be a boolean"));
    }
    Ok(())
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
        if !object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(emulebb_core::valid_category_name)
        {
            return Err(invalid_body_error(
                "name must be 1-64 ASCII letters, digits, or hyphens and start with a letter or digit",
            ));
        }
    }
    for name in ["tempDir", "destinationDir"] {
        if let Some(path) = object.get(name)
            && !path.is_null()
        {
            validate_path_text_body_field(Some(path), name)?;
        }
    }
    if object
        .get("comment")
        .is_some_and(|value| !value.is_string())
    {
        return Err(invalid_body_error("comment must be a string"));
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
