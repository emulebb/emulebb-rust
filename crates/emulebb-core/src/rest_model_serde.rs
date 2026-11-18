use serde::Deserialize;

use crate::rest_model::NullableStringField;

/// Omission is represented by the field default; an explicit value must have
/// its declared non-null type.
pub(crate) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

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

/// Canonical native job IDs are decimal strings on the wire, independent of hashes.
pub(crate) mod job_id {
    use emulebb_metadata::JobId;
    use serde::Deserialize;
    pub fn serialize<S: serde::Serializer>(id: &JobId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(id)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<JobId, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Wire text delegates to the native intent parser, keeping one value domain.
pub(crate) mod download_intent {
    use emulebb_metadata::DownloadIntent;
    use serde::Deserialize;
    pub fn default() -> DownloadIntent {
        DownloadIntent::Started
    }
    pub fn serialize<S: serde::Serializer>(
        intent: &DownloadIntent,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(intent.as_str())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DownloadIntent, D::Error> {
        DownloadIntent::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Optional positive i64 identities use exact decimal strings on the wire.
pub(crate) mod optional_decimal_id {
    use serde::{Deserialize, Serialize};
    pub fn serialize<S: serde::Serializer>(
        value: &Option<i64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|id| id.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<i64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                let id = value.parse::<i64>().map_err(serde::de::Error::custom)?;
                if id <= 0 || id.to_string() != value {
                    return Err(serde::de::Error::custom(
                        "identity must be a canonical positive decimal string",
                    ));
                }
                Ok(id)
            })
            .transpose()
    }
}

#[cfg(test)]
mod optional_identity_tests {
    #[test]
    fn linked_search_identity_roundtrips_above_json_integer_precision() {
        let request: crate::SearchCreate =
            serde_json::from_str(r#"{"query":"sample","parentSearchId":"9007199254740993"}"#)
                .unwrap();
        assert_eq!(request.parent_search_id, Some(9007199254740993));
        assert_eq!(
            serde_json::to_value(request).unwrap()["parentSearchId"],
            "9007199254740993"
        );
    }
}
