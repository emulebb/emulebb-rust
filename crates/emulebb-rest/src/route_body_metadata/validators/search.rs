//! Search-create request-body validation.

use axum::response::Response;

use super::super::{JsonObject, invalid_body_error};

const SEARCH_METHOD_ERROR: &str = "method must be one of automatic, server, global, kad";
const SEARCH_TYPE_ERROR: &str = "type is not supported";

pub(super) fn validate_search_create_body_fields(object: &JsonObject) -> Result<(), Box<Response>> {
    validate_search_query_body_field(object.get("query"))?;
    if let Some(method) = object.get("method") {
        validate_search_method_body_field(method)?;
    }
    if let Some(search_type) = object.get("type") {
        validate_search_type_body_field(search_type)?;
    }
    for field in ["extension", "codec", "title", "album", "artist"] {
        validate_optional_search_text_field(object, field)?;
    }
    let min_size = parse_optional_unsigned_body_field(object, "minSizeBytes")?;
    let max_size = parse_optional_unsigned_body_field(object, "maxSizeBytes")?;
    if let (Some(min_size), Some(max_size)) = (min_size, max_size)
        && max_size < min_size
    {
        return Err(invalid_body_error(
            "maxSizeBytes must be greater than or equal to minSizeBytes",
        ));
    }
    if let Some(min_availability) = parse_optional_unsigned_body_field(object, "minAvailability")?
        && min_availability > 1_000_000
    {
        return Err(invalid_body_error(
            "minAvailability must be an unsigned number in the range 0..1000000",
        ));
    }
    if let Some(min_complete_sources) =
        parse_optional_unsigned_body_field(object, "minCompleteSources")?
        && min_complete_sources > 1_000_000
    {
        return Err(invalid_body_error(
            "minCompleteSources must be an unsigned number in the range 0..1000000",
        ));
    }
    if let Some(min_bitrate) = parse_optional_unsigned_body_field(object, "minBitrateKbps")?
        && min_bitrate > u64::from(u32::MAX)
    {
        return Err(invalid_body_error(
            "minBitrateKbps must be an unsigned 32-bit number",
        ));
    }
    if let Some(min_length) = parse_optional_unsigned_body_field(object, "minLengthSeconds")?
        && min_length > u64::from(u32::MAX)
    {
        return Err(invalid_body_error(
            "minLengthSeconds must be an unsigned 32-bit number",
        ));
    }
    Ok(())
}

fn validate_optional_search_text_field(
    object: &JsonObject,
    field: &'static str,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_str() else {
        return Err(invalid_body_error(format!("{field} must be a string")));
    };
    if value.chars().any(char::is_control) {
        return Err(invalid_body_error(format!(
            "{field} must not contain control characters"
        )));
    }
    if value.chars().count() > 256 {
        return Err(invalid_body_error(format!(
            "{field} must be at most 256 characters"
        )));
    }
    Ok(())
}

fn validate_search_query_body_field(
    value: Option<&serde_json::Value>,
) -> Result<(), Box<Response>> {
    let Some(query) = value.and_then(serde_json::Value::as_str) else {
        return Err(invalid_body_error("query must be a string"));
    };
    let normalized = normalize_ascii_whitespace(query);
    if normalized.is_empty() {
        return Err(invalid_body_error("query must not be empty"));
    }
    if normalized.chars().any(char::is_control) {
        return Err(invalid_body_error(
            "query must be valid UTF-8 without control characters",
        ));
    }
    if normalized.encode_utf16().count() > 160 {
        return Err(invalid_body_error("query must be at most 160 characters"));
    }
    Ok(())
}

fn validate_search_method_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(method) = value.as_str() else {
        return Err(invalid_body_error("method must be a string"));
    };
    if !matches!(method, "automatic" | "server" | "global" | "kad") {
        return Err(invalid_body_error(SEARCH_METHOD_ERROR));
    }
    Ok(())
}

fn validate_search_type_body_field(value: &serde_json::Value) -> Result<(), Box<Response>> {
    let Some(search_type) = value.as_str() else {
        return Err(invalid_body_error("type must be a string"));
    };
    if !matches!(
        search_type,
        "" | "arc" | "audio" | "iso" | "image" | "pro" | "video" | "doc" | "emulecollection"
    ) {
        return Err(invalid_body_error(SEARCH_TYPE_ERROR));
    }
    Ok(())
}

fn parse_optional_unsigned_body_field(
    object: &JsonObject,
    field: &'static str,
) -> Result<Option<u64>, Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(invalid_body_error(format!(
            "{field} must be an unsigned number"
        )));
    };
    Ok(Some(value))
}

fn normalize_ascii_whitespace(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}
