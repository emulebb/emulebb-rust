//! Route-specific REST JSON body validators.

mod preferences;
mod search;

use axum::response::Response;

use super::{JsonObject, invalid_body_error};

const MAX_TRANSFER_ADD_LINKS: usize = 100;

pub(super) fn validate_search_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    search::validate_search_create_body_fields(object)
}

pub(super) fn validate_preferences_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    preferences::validate_preferences_patch_body_fields(object)
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
    if object
        .get("paused")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(invalid_body_error("paused must be a boolean"));
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

pub(super) fn validate_shared_file_add_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    validate_path_text_body_field(object.get("path"), "path")
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
            if !matches!(name.as_str(), "path" | "recursive") {
                return Err(invalid_body_error(format!(
                    "unknown shared-directory root field: {name}"
                )));
            }
        }
        validate_path_text_body_field(object.get("path"), "path")?;
        if object
            .get("recursive")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(invalid_body_error("recursive must be a boolean"));
        }
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
    {
        return Err(invalid_body_error(
            "server PATCH requires name, priority, or static",
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
