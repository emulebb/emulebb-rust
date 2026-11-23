//! Native PATCH input and bounded sizing before an owner clones a request.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SettingsPatch {
    pub expected_revision: SettingsRevision,
    #[serde(default)]
    pub set: SettingsPartial,
    #[serde(default)]
    pub reset: Vec<SettingKey>,
}
impl SettingsPatch {
    /// Decode a bounded native request, collecting independent supplied-leaf issues.
    /// The final typed decode also checks exact structure and duplicate JSON fields.
    pub fn from_json(body: &[u8]) -> Result<Self, SettingsError> {
        if body.len() > MAX_PATCH_BYTES {
            return Err(SettingsError::DocumentTooLarge);
        }
        let mut issues = Vec::new();
        let mut object_groups = true;
        {
            // WHY: validate only an object and release its generic backing
            // before constructing the strict typed patch.
            let raw: serde_json::Map<String, Value> = decode_json(body)?;
            if let Some(set) = raw.get("set") {
                SettingsPartial::validate_json_fields(set, &mut issues, &mut object_groups);
            }
        }
        if !issues.is_empty() {
            return Err(SettingsError::Validation(issues));
        }
        if !object_groups {
            return Err(SettingsError::InvalidDocument);
        }
        decode_json(body)
    }
    pub fn into_parts(self) -> (SettingsRevision, SettingsEdit) {
        (
            self.expected_revision,
            SettingsEdit {
                set: self.set,
                reset: self.reset,
            },
        )
    }
    /// Counts actual UTF-8 JSON bytes without allocating a serialized request.
    /// Transport still owns the separate cap on original body bytes/whitespace.
    pub fn payload_bytes(&self) -> Result<usize, SettingsError> {
        json_size(self, MAX_PATCH_BYTES)
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, SettingsError> {
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let document = T::deserialize(&mut decoder).map_err(|_| SettingsError::InvalidDocument)?;
    decoder.end().map_err(|_| SettingsError::InvalidDocument)?;
    Ok(document)
}

impl SettingsEdit {
    /// Offline single-key input: ordinary values are text, nullable leaves
    /// accept literal null, and only list-valued leaves use inline JSON.
    pub fn setting_text(key: SettingKey, input: &str) -> Result<Self, SettingsError> {
        if input.len() > MAX_PATCH_BYTES {
            return Err(SettingsError::DocumentTooLarge);
        }
        let spec = setting_specs()
            .iter()
            .find(|spec| spec.key == key.as_str())
            .ok_or(SettingsError::UnknownKey)?;
        let value = if spec.nullable && input == "null" {
            Value::Null
        } else {
            match spec.rule {
                Rule::Boolean => {
                    Value::Bool(input.parse().map_err(|_| SettingsError::InvalidValue)?)
                }
                Rule::Integer { .. } => Value::from(
                    input
                        .parse::<u64>()
                        .map_err(|_| SettingsError::InvalidValue)?,
                ),
                Rule::DnsServers | Rule::NatBackends | Rule::Ipv4Cidrs => {
                    serde_json::from_str(input).map_err(|_| SettingsError::InvalidValue)?
                }
                _ => Value::String(input.into()),
            }
        };
        let mut edit = Self::default();
        if !edit.set.set_key(key, &value)? {
            return Err(SettingsError::UnknownKey);
        }
        Ok(edit)
    }
}

impl SettingsValues {
    /// One resolved value for offline stdout; lists use compact JSON and text
    /// values remain literal. This does not serialize unrelated settings.
    pub fn display_value(&self, key: SettingKey) -> Result<String, SettingsError> {
        match self.value_json(key)?.ok_or(SettingsError::UnknownKey)? {
            Value::String(value) => Ok(value),
            value => Ok(value.to_string()),
        }
    }
}

pub fn json_size(value: &impl Serialize, limit: usize) -> Result<usize, SettingsError> {
    let mut writer = Count {
        bytes: 0,
        limit,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return Err(if writer.exceeded {
            SettingsError::DocumentTooLarge
        } else {
            SettingsError::InvalidDocument
        });
    }
    Ok(writer.bytes)
}
struct Count {
    bytes: usize,
    limit: usize,
    exceeded: bool,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit - self.bytes {
            self.exceeded = true;
            return Err(std::io::Error::other("settings JSON size limit"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_json_collects_type_and_rule_issues_without_echoing_input() {
        let body = serde_json::json!({"expectedRevision":"1","set":{
            "network":{"nickname":"", "nat":{"enabled":"private-input"}},
            "transfers":{"upload":{"baseSlots":0}},
            "security":{"vpnGuard":{"mode":"private-input"}}
        }})
        .to_string();
        let error = SettingsPatch::from_json(body.as_bytes()).unwrap_err();
        let SettingsError::Validation(issues) = &error else {
            panic!("expected field issues");
        };
        assert_eq!(
            issues.iter().map(|i| (i.key, i.code)).collect::<Vec<_>>(),
            vec![
                ("network.nickname", "invalid-value"),
                ("network.nat.enabled", "invalid-type"),
                ("transfers.upload.baseSlots", "invalid-value"),
                ("security.vpnGuard.mode", "invalid-type"),
            ]
        );
        assert!(!error.to_string().contains("private-input"));
    }

    #[test]
    fn native_json_retains_exact_typed_structure_and_duplicate_checks() {
        for body in [
            r#"{"expectedRevision":"1","set":{"network":{"nickname":"First","nickname":"Second"}}}"#,
            r#"{"expectedRevision":"1","expectedRevision":"2","set":{"network":{"nickname":"First"}}}"#,
            r#"{"expectedRevision":"1","set":{"network":false}}"#,
            r#"{"expectedRevision":1,"set":{"network":{"nickname":"First"}}}"#,
            r#"{"expectedRevision":"1","extension":true}"#,
            r#"["1",{},[]]"#,
            r#"{"expectedRevision":"1","set":[],"reset":["network.nickname"]}"#,
            r#"{"expectedRevision":"1","set":{"network":[]},"reset":["network.nickname"]}"#,
            r#"{"expectedRevision":"1"} {}"#,
        ] {
            assert_eq!(
                SettingsPatch::from_json(body.as_bytes()).unwrap_err(),
                SettingsError::InvalidDocument
            );
        }
        let body = br#"{"expectedRevision":"1","set":{"network":{"nat":{"pcpServerIp":null}}}}"#;
        assert_eq!(
            SettingsPatch::from_json(body).unwrap(),
            serde_json::from_slice::<SettingsPatch>(body).unwrap()
        );
        assert_eq!(
            SettingsPatch::from_json(&vec![b' '; MAX_PATCH_BYTES + 1]).unwrap_err(),
            SettingsError::DocumentTooLarge
        );
    }

    #[test]
    fn one_key_text_input_uses_the_catalog_types_and_shared_candidate_validation() {
        let initial = SavedSettings::default();
        let key = SettingKey::parse("network.nickname").unwrap();
        let saved = initial
            .edited(&SettingsEdit::setting_text(key, "\"Sample\"").unwrap())
            .unwrap();
        assert_eq!(saved.values().display_value(key).unwrap(), "\"Sample\"");
        let key = SettingKey::parse("transfers.maxConcurrentDownloads").unwrap();
        let saved = initial
            .edited(&SettingsEdit::setting_text(key, "7").unwrap())
            .unwrap();
        assert_eq!(saved.values().display_value(key).unwrap(), "7");
        let cleared = saved
            .edited(&SettingsEdit::setting_text(key, "null").unwrap())
            .unwrap();
        assert_eq!(cleared.values().display_value(key).unwrap(), "null");
        assert!(SettingsEdit::setting_text(key, "1.5").is_err());
        let key = SettingKey::parse("network.nat.backendOrder").unwrap();
        let saved = initial
            .edited(&SettingsEdit::setting_text(key, "[\"upnp\",\"pcp-natpmp\"]").unwrap())
            .unwrap();
        assert_eq!(
            saved.values().display_value(key).unwrap(),
            "[\"upnp\",\"pcp-natpmp\"]"
        );
        assert!(
            initial
                .edited(&SettingsEdit::setting_text(key, "[\"upnp\",\"upnp\"]").unwrap())
                .is_err()
        );
    }

    #[test]
    fn native_patch_requires_exact_revision_and_preserves_partial_presence() {
        let patch:SettingsPatch=serde_json::from_value(json!({"expectedRevision":"9007199254740993","set":{"network":{"p2p":{"bindInterface":null}}},"reset":["network.nickname"]})).unwrap();
        assert_eq!(patch.expected_revision.get(), 9_007_199_254_740_993);
        assert_eq!(
            patch.set.network.p2p.bind_interface,
            PartialValue::Set(None)
        );
        assert_eq!(patch.set.network.nickname, PartialValue::Unchanged);
        let original = SavedSettings::default();
        let (revision, edit) = patch.into_parts();
        assert_eq!(revision.get(), 9_007_199_254_740_993);
        assert!(original.edited(&edit).is_ok());
        for invalid in [
            json!({"set":{}}),
            json!({"expectedRevision":1}),
            json!({"expectedRevision":"1","unexpected":true}),
            json!({"expectedRevision":"01"}),
        ] {
            assert!(serde_json::from_value::<SettingsPatch>(invalid).is_err());
        }
    }

    #[test]
    fn request_sizing_is_exact_for_json_escapes_and_enforces_the_boundary() {
        let mut patch: SettingsPatch = serde_json::from_value(
            json!({"expectedRevision":"1","set":{"storage":{"incomingDirectory":""}}}),
        )
        .unwrap();
        let overhead = patch.payload_bytes().unwrap();
        let prefix = "界\"\\".repeat(1000);
        let escaped = serde_json::to_string(&prefix).unwrap().len() - 2;
        let path = prefix + &"x".repeat(MAX_PATCH_BYTES - overhead - escaped);
        patch.set.storage.incoming_directory = PartialValue::Set(PathBuf::from(&path));
        assert_eq!(patch.payload_bytes().unwrap(), MAX_PATCH_BYTES);
        assert_eq!(serde_json::to_vec(&patch).unwrap().len(), MAX_PATCH_BYTES);
        patch.set.storage.incoming_directory = PartialValue::Set(PathBuf::from(path + "x"));
        assert_eq!(patch.payload_bytes(), Err(SettingsError::DocumentTooLarge));
    }

    #[test]
    fn declaration_derived_keyed_copy_and_diff_touch_only_the_selected_leaf() {
        let initial = SettingsValues::default();
        let mut source = initial.clone();
        source.transfers.max_concurrent_downloads = Some(7);
        source.network.nickname = "Sample".into();
        let keys = initial.differing_keys(&source);
        assert_eq!(keys.len(), 2);
        let key = SettingKey::parse("transfers.maxConcurrentDownloads").unwrap();
        assert!(keys.contains(&key));
        assert_eq!(source.value_json(key).unwrap(), Some(json!(7)));
        assert_eq!(initial.value_json(key).unwrap(), Some(Value::Null));
        let mut copied = initial.clone();
        assert!(copied.copy_key_from(&source, key));
        assert_eq!(copied.transfers.max_concurrent_downloads, Some(7));
        assert_eq!(copied.network, initial.network);
        assert_eq!(
            copied.differing_keys(&source),
            vec![SettingKey::parse("network.nickname").unwrap()]
        );
    }
}
