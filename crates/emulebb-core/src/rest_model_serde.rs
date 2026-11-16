use serde::Deserialize;

use crate::rest_model::NullableStringField;

pub(crate) fn deserialize_nullable_string_field<'de, D>(
    deserializer: D,
) -> std::result::Result<NullableStringField, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Ok(NullableStringField::Null(())),
        serde_json::Value::String(value) => Ok(NullableStringField::Value(value)),
        _ => Err(serde::de::Error::custom("path must be a string or null")),
    }
}

pub(crate) fn deserialize_nullable_category<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

pub(crate) fn deserialize_optional_paused_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Bool(value) => Ok(Some(value)),
        _ => Err(serde::de::Error::custom("paused must be a boolean")),
    }
}
