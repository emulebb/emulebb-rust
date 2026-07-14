//! Nested app settings core-section PATCH request-body validation.

use axum::response::Response;
use emulebb_core::{CoreSettingFieldKind, core_setting_field};

use super::super::{JsonObject, invalid_body_error};

pub(super) fn validate_core_settings_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if object.is_empty() {
        return Err(invalid_body_error(
            "settings.core PATCH requires at least one core setting",
        ));
    }

    for (field_name, value) in object {
        let Some(field) = core_setting_field(field_name) else {
            return Err(invalid_body_error(format!(
                "unknown settings.core field: {field_name}"
            )));
        };
        match field.kind {
            CoreSettingFieldKind::Number => validate_unsigned_core_setting(field_name, value)?,
            CoreSettingFieldKind::Boolean => validate_boolean_core_setting(field_name, value)?,
        }
    }

    Ok(())
}

fn validate_unsigned_core_setting(
    field: &str,
    value: &serde_json::Value,
) -> Result<(), Box<Response>> {
    let Some(spec) = core_setting_field(field) else {
        return Ok(());
    };
    let min = spec.min.unwrap_or(0);
    let max = spec.max.unwrap_or(u32::MAX);
    let message = format!("{field} must be an unsigned number in the range {min}..{max}");
    let Some(value) = value.as_u64() else {
        return Err(invalid_body_error(message));
    };
    if !(u64::from(min)..=u64::from(max)).contains(&value) {
        return Err(invalid_body_error(message));
    }
    Ok(())
}

fn validate_boolean_core_setting(
    field: &str,
    value: &serde_json::Value,
) -> Result<(), Box<Response>> {
    if !value.is_boolean() {
        return Err(invalid_body_error(format!("{field} must be a boolean")));
    }
    Ok(())
}
