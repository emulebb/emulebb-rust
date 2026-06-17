//! App-preferences PATCH request-body validation.

use axum::response::Response;

use super::super::{JsonObject, invalid_body_error};

pub(super) fn validate_preferences_patch_body_fields(
    object: &JsonObject,
) -> Result<(), Box<Response>> {
    if object.is_empty() {
        return Err(invalid_body_error(
            "preferences PATCH requires at least one preference",
        ));
    }

    validate_unsigned_preference(
        object,
        "uploadLimitKiBps",
        "uploadLimitKiBps must be an unsigned number in the range 1..4294967294",
        |value| (1..=4_294_967_294).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "downloadLimitKiBps",
        "downloadLimitKiBps must be an unsigned number in the range 1..4294967294",
        |value| (1..=4_294_967_294).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "maxConnections",
        "maxConnections must be an unsigned number in the range 1..2147483647",
        |value| (1..=2_147_483_647).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "maxConnectionsPerFiveSeconds",
        "maxConnectionsPerFiveSeconds must be an unsigned number in the range 1..2147483647",
        |value| (1..=2_147_483_647).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "maxSourcesPerFile",
        "maxSourcesPerFile must be an unsigned number in the range 1..2147483647",
        |value| (1..=2_147_483_647).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "uploadClientDataRate",
        "uploadClientDataRate must be an unsigned number in the range 1..4294967295",
        |value| (1..=u32::MAX as u64).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "maxUploadSlots",
        "maxUploadSlots must be an unsigned number in the range 1..64",
        |value| (1..=64).contains(&value),
    )?;
    validate_unsigned_preference(
        object,
        "uploadSlotElasticPercent",
        "uploadSlotElasticPercent must be an unsigned number in the range 0..100",
        |value| value <= 100,
    )?;
    validate_unsigned_preference(
        object,
        "queueSize",
        "queueSize must be an unsigned number in the range 2000..10000",
        |value| (2_000..=10_000).contains(&value),
    )?;

    for field in [
        "autoConnect",
        "newAutoUp",
        "newAutoDown",
        "creditSystem",
        "safeServerConnect",
        "networkKademlia",
        "networkEd2k",
        "downloadAutoBroadbandIo",
    ] {
        validate_boolean_preference(object, field)?;
    }

    Ok(())
}

fn validate_unsigned_preference(
    object: &JsonObject,
    field: &'static str,
    message: &'static str,
    is_valid: impl Fn(u64) -> bool,
) -> Result<(), Box<Response>> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let Some(value) = value.as_u64() else {
        return Err(invalid_body_error(message));
    };
    if !is_valid(value) {
        return Err(invalid_body_error(message));
    }
    Ok(())
}

fn validate_boolean_preference(
    object: &JsonObject,
    field: &'static str,
) -> Result<(), Box<Response>> {
    if object.get(field).is_some_and(|value| !value.is_boolean()) {
        return Err(invalid_body_error(format!("{field} must be a boolean")));
    }
    Ok(())
}
