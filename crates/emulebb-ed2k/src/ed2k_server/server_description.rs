//! UDP server-description request/response codec.

use anyhow::{Context, Result};

use super::{
    ST_AUXPORTSLIST, ST_DESCRIPTION, ST_DYNIP, ST_SERVERNAME, ST_VERSION,
    tag_codec::{DecodedTagValue, decode_tag_value},
};

const INVALID_SERVER_DESCRIPTION_LENGTH: u16 = 0xF0FF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServerDescription {
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
    pub(super) dynamic_host: Option<String>,
    pub(super) version: Option<String>,
    pub(super) auxiliary_ports: Vec<u16>,
}

pub(super) fn server_description_challenge() -> u32 {
    (u32::from(rand::random::<u16>()) << 16) | u32::from(INVALID_SERVER_DESCRIPTION_LENGTH)
}

pub(super) fn decode_server_description_response(
    payload: &[u8],
    expected_challenge: u32,
) -> Result<Option<ServerDescription>> {
    if payload.len() >= 8
        && u16::from_le_bytes([payload[0], payload[1]]) == INVALID_SERVER_DESCRIPTION_LENGTH
    {
        let challenge = u32::from_le_bytes(payload[..4].try_into().expect("four-byte challenge"));
        if challenge != expected_challenge {
            return Ok(None);
        }
        let tag_count = u32::from_le_bytes(payload[4..8].try_into().expect("four-byte tag count"));
        let mut cursor = &payload[8..];
        let mut name = None;
        let mut description = None;
        let mut dynamic_host = None;
        let mut version = None;
        let mut auxiliary_ports = Vec::new();
        for _ in 0..tag_count {
            let (tag_name, tag_value, rest) = decode_tag_value(cursor)?;
            cursor = rest;
            match (tag_name, tag_value) {
                (Some(ST_SERVERNAME), Some(DecodedTagValue::String(value))) => name = Some(value),
                (Some(ST_DESCRIPTION), Some(DecodedTagValue::String(value))) => {
                    description = Some(value);
                }
                (Some(ST_DYNIP), Some(DecodedTagValue::String(value))) => {
                    dynamic_host = valid_dynamic_host(&value);
                }
                (Some(ST_VERSION), Some(DecodedTagValue::String(value))) => {
                    version = nonempty_trimmed(value);
                }
                (Some(ST_VERSION), Some(DecodedTagValue::Unsigned(value))) => {
                    let value = value as u32;
                    version = Some(format!("{}.{:02}", value >> 16, value & 0xffff));
                }
                (Some(ST_AUXPORTSLIST), Some(DecodedTagValue::String(value))) => {
                    auxiliary_ports = parse_auxiliary_ports(&value);
                }
                _ => {}
            }
        }
        return Ok(Some(ServerDescription {
            name,
            description,
            dynamic_host,
            version,
            auxiliary_ports,
        }));
    }

    let (name, rest) = decode_legacy_string(payload).context("invalid legacy server name")?;
    let (description, _) =
        decode_legacy_string(rest).context("invalid legacy server description")?;
    Ok(Some(ServerDescription {
        name: Some(name),
        description: Some(description),
        dynamic_host: None,
        version: None,
        auxiliary_ports: Vec::new(),
    }))
}

pub(super) fn valid_dynamic_host(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() < 51 && value.parse::<std::net::Ipv4Addr>().is_err())
        .then(|| value.to_string())
}

fn nonempty_trimmed(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_auxiliary_ports(value: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for field in value.split(',') {
        if let Ok(port) = field.trim().parse::<u16>()
            && port != 0
            && !ports.contains(&port)
        {
            ports.push(port);
        }
    }
    ports
}

fn decode_legacy_string(payload: &[u8]) -> Result<(String, &[u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short string length");
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < 2 + len {
        anyhow::bail!("short string body");
    }
    Ok((
        String::from_utf8_lossy(&payload[2..2 + len]).into_owned(),
        &payload[2 + len..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_server::tag_codec::{push_string_tag, push_u32_tag};

    #[test]
    fn challenge_has_the_invalid_legacy_length_prefix() {
        for _ in 0..32 {
            assert_eq!(server_description_challenge() as u16, 0xF0FF);
        }
    }

    #[test]
    fn decodes_challenge_tag_response_and_rejects_mismatch() {
        let challenge = 0x1234_F0FFu32;
        let mut payload = challenge.to_le_bytes().to_vec();
        payload.extend_from_slice(&5u32.to_le_bytes());
        push_string_tag(&mut payload, ST_SERVERNAME, "Example Server");
        push_string_tag(&mut payload, ST_DESCRIPTION, "Example Description");
        push_string_tag(&mut payload, ST_DYNIP, "server.example.test");
        push_u32_tag(&mut payload, ST_VERSION, (17 << 16) | 6);
        push_string_tag(&mut payload, ST_AUXPORTSLIST, "4661, 4662,0,bad,4661");

        let decoded = decode_server_description_response(&payload, challenge)
            .unwrap()
            .expect("matching challenge");
        assert_eq!(decoded.name.as_deref(), Some("Example Server"));
        assert_eq!(decoded.description.as_deref(), Some("Example Description"));
        assert_eq!(decoded.dynamic_host.as_deref(), Some("server.example.test"));
        assert_eq!(decoded.version.as_deref(), Some("17.06"));
        assert_eq!(decoded.auxiliary_ports, vec![4661, 4662]);
        assert!(
            decode_server_description_response(&payload, 0x5678_F0FF)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn decodes_legacy_string_response() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&6u16.to_le_bytes());
        payload.extend_from_slice(b"Server");
        payload.extend_from_slice(&11u16.to_le_bytes());
        payload.extend_from_slice(b"Description");

        let decoded = decode_server_description_response(&payload, 0)
            .unwrap()
            .expect("legacy response");
        assert_eq!(decoded.name.as_deref(), Some("Server"));
        assert_eq!(decoded.description.as_deref(), Some("Description"));
        assert_eq!(decoded.dynamic_host, None);
        assert_eq!(decoded.version, None);
        assert!(decoded.auxiliary_ports.is_empty());
    }

    #[test]
    fn dynamic_host_rejects_ipv4_empty_and_overlong_values() {
        assert_eq!(
            valid_dynamic_host(" server.example ").as_deref(),
            Some("server.example")
        );
        assert_eq!(valid_dynamic_host("192.0.2.5"), None);
        assert_eq!(valid_dynamic_host(""), None);
        assert_eq!(valid_dynamic_host(&"x".repeat(51)), None);
    }
}
