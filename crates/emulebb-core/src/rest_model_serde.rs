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
