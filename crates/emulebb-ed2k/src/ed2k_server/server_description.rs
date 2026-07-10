//! UDP server-description request/response codec.

use anyhow::{Context, Result};

use super::{ST_DESCRIPTION, ST_SERVERNAME, decode_tag};

const INVALID_SERVER_DESCRIPTION_LENGTH: u16 = 0xF0FF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServerDescription {
    pub(super) name: Option<String>,
    pub(super) description: Option<String>,
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
        for _ in 0..tag_count {
            let (tag_name, tag_value, rest) = decode_tag(cursor)?;
            cursor = rest;
            match tag_name {
                Some(ST_SERVERNAME) => name = tag_value,
                Some(ST_DESCRIPTION) => description = tag_value,
                _ => {}
            }
        }
        return Ok(Some(ServerDescription { name, description }));
    }

    let (name, rest) = decode_legacy_string(payload).context("invalid legacy server name")?;
    let (description, _) =
        decode_legacy_string(rest).context("invalid legacy server description")?;
    Ok(Some(ServerDescription {
        name: Some(name),
        description: Some(description),
    }))
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
    use crate::ed2k_server::tag_codec::push_string_tag;

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
        payload.extend_from_slice(&2u32.to_le_bytes());
        push_string_tag(&mut payload, ST_SERVERNAME, "Example Server");
        push_string_tag(&mut payload, ST_DESCRIPTION, "Example Description");

        let decoded = decode_server_description_response(&payload, challenge)
            .unwrap()
            .expect("matching challenge");
        assert_eq!(decoded.name.as_deref(), Some("Example Server"));
        assert_eq!(decoded.description.as_deref(), Some("Example Description"));
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
    }
}
