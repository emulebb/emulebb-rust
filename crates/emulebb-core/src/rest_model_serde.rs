use serde::Deserialize;

use crate::rest_model::{NullableStringField, NullableU32Field};

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

pub(crate) fn deserialize_nullable_u32_field<'de, D>(
    deserializer: D,
) -> std::result::Result<NullableU32Field, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Null => Ok(NullableU32Field::Null(())),
        serde_json::Value::Number(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(NullableU32Field::Value)
            .ok_or_else(|| serde::de::Error::custom("color must be null or an RGB integer")),
        _ => Err(serde::de::Error::custom(
            "color must be null or an RGB integer",
        )),
    }
}

pub(crate) fn deserialize_optional_category_id<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(value) => {
            let Some(value) = value.as_u64() else {
                return Err(serde::de::Error::custom(
                    "categoryId must be an unsigned number",
                ));
            };
            u32::try_from(value)
                .map(Some)
                .map_err(|_| serde::de::Error::custom("categoryId is out of range"))
        }
        _ => Err(serde::de::Error::custom(
            "categoryId must be an unsigned number",
        )),
    }
}
