use anyhow::{Context, Result};

use super::{
    TAG_SHORT_NAME_MASK, TAGTYPE_BLOB, TAGTYPE_BOOL, TAGTYPE_BOOLARRAY, TAGTYPE_FLOAT32,
    TAGTYPE_HASH, TAGTYPE_STR1, TAGTYPE_STRING, TAGTYPE_UINT8, TAGTYPE_UINT16, TAGTYPE_UINT32,
    TAGTYPE_UINT64,
};

#[derive(Debug, Clone, PartialEq)]
pub(super) enum DecodedTagValue {
    String(String),
    Unsigned(u64),
    Bool(bool),
    Float32(f32),
    Hash([u8; 16]),
    Blob(Vec<u8>),
    BoolArray(Vec<u8>),
}

pub(super) fn push_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
    payload.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_short_u32_tag(payload: &mut Vec<u8>, name: u8, value: u32) {
    payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT32);
    payload.push(name);
    payload.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn push_short_u8_tag(payload: &mut Vec<u8>, name: u8, value: u8) {
    payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT8);
    payload.push(name);
    payload.push(value);
}

/// eMule `CTag::WriteNewEd2kTag` integer down-sizing: emit `value` as the smallest
/// UINT type that holds it (u8 <=255, u16 <=65535, u32 <=4G, else u64), short-name.
/// Matches stock's OP_OFFERFILES FT_FILESIZE / FT_FILESIZE_HI encoding (a small
/// file's size tag is a u8/u16, not always u32).
pub(super) fn push_short_int_tag(payload: &mut Vec<u8>, name: u8, value: u64) {
    if value <= u64::from(u8::MAX) {
        payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT8);
        payload.push(name);
        payload.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT16);
        payload.push(name);
        payload.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u64::from(u32::MAX) {
        payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT32);
        payload.push(name);
        payload.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        payload.push(TAG_SHORT_NAME_MASK | TAGTYPE_UINT64);
        payload.push(name);
        payload.extend_from_slice(&value.to_le_bytes());
    }
}

pub(super) fn ed2k_string_tag_type(len: usize) -> u8 {
    if (1..=16).contains(&len) {
        TAGTYPE_STR1 + u8::try_from(len - 1).expect("string tag length fits in u8")
    } else {
        TAGTYPE_STRING
    }
}

pub(super) fn push_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    // Server login string tags use eMule `CTag::WriteTagToFile`: always
    // `TAGTYPE_STRING` with a u16 length prefix, NEVER the `WriteNewEd2kTag`
    // compact-string optimization (that is `push_short_string_tag`, used for
    // OP_OFFERFILES). Emitting a compact STR type here (0x15…) produced a hybrid
    // no stock writer can generate — a unique non-stock fingerprint on every login.
    let value_bytes = value.as_bytes();
    payload.push(TAGTYPE_STRING);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(name);
    payload.extend_from_slice(
        &u16::try_from(value_bytes.len())
            .expect("string tag length fits in u16")
            .to_le_bytes(),
    );
    payload.extend_from_slice(value_bytes);
}

pub(super) fn push_short_string_tag(payload: &mut Vec<u8>, name: u8, value: &str) {
    let value_bytes = value.as_bytes();
    let type_byte = ed2k_string_tag_type(value_bytes.len());
    payload.push(TAG_SHORT_NAME_MASK | type_byte);
    payload.push(name);
    if type_byte == TAGTYPE_STRING {
        payload.extend_from_slice(
            &u16::try_from(value_bytes.len())
                .expect("string tag length fits in u16")
                .to_le_bytes(),
        );
    }
    payload.extend_from_slice(value_bytes);
}

pub(super) fn decode_ed2k_string(payload: &[u8]) -> Result<Option<String>> {
    if payload.len() < 2 {
        return Ok(None);
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < len + 2 {
        anyhow::bail!("short ED2K string payload");
    }
    Ok(Some(
        String::from_utf8_lossy(&payload[2..2 + len]).into_owned(),
    ))
}

pub(super) fn decode_tag(bytes: &[u8]) -> Result<(Option<u8>, Option<String>, &[u8])> {
    let (tag_name, tag_value, rest) = decode_tag_value(bytes)?;
    let string_value = match tag_value {
        Some(DecodedTagValue::String(value)) => Some(value),
        _ => None,
    };
    Ok((tag_name, string_value, rest))
}

pub(super) fn decode_tag_value(
    mut bytes: &[u8],
) -> Result<(Option<u8>, Option<DecodedTagValue>, &[u8])> {
    if bytes.len() < 2 {
        anyhow::bail!("short ED2K tag header");
    }
    let type_byte = bytes[0];
    let short_name = (type_byte & TAG_SHORT_NAME_MASK) != 0;
    let base_type = type_byte & !TAG_SHORT_NAME_MASK;
    bytes = &bytes[1..];

    let tag_name = if short_name {
        let name = bytes[0];
        bytes = &bytes[1..];
        Some(name)
    } else {
        if bytes.len() < 2 {
            anyhow::bail!("short ED2K long-name length");
        }
        let name_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        bytes = &bytes[2..];
        if bytes.len() < name_len {
            anyhow::bail!("short ED2K long-name bytes");
        }
        let name = if name_len == 1 { Some(bytes[0]) } else { None };
        bytes = &bytes[name_len..];
        name
    };

    let decoded_value = match base_type {
        TAGTYPE_STRING => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K string tag length");
            }
            let len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            bytes = &bytes[2..];
            if bytes.len() < len {
                anyhow::bail!("short ED2K string tag value");
            }
            let value = String::from_utf8_lossy(&bytes[..len]).into_owned();
            bytes = &bytes[len..];
            Some(DecodedTagValue::String(value))
        }
        TAGTYPE_STR1..=0x20 => {
            let len = usize::from(base_type - TAGTYPE_STR1 + 1);
            if bytes.len() < len {
                anyhow::bail!("short ED2K compact string tag value");
            }
            let value = String::from_utf8_lossy(&bytes[..len]).into_owned();
            bytes = &bytes[len..];
            Some(DecodedTagValue::String(value))
        }
        TAGTYPE_UINT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K uint32 tag value");
            }
            let value = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            bytes = &bytes[4..];
            Some(DecodedTagValue::Unsigned(u64::from(value)))
        }
        TAGTYPE_UINT64 => {
            if bytes.len() < 8 {
                anyhow::bail!("short ED2K uint64 tag value");
            }
            let value = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            bytes = &bytes[8..];
            Some(DecodedTagValue::Unsigned(value))
        }
        TAGTYPE_UINT16 => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K uint16 tag value");
            }
            let value = u16::from_le_bytes(bytes[..2].try_into().unwrap());
            bytes = &bytes[2..];
            Some(DecodedTagValue::Unsigned(u64::from(value)))
        }
        TAGTYPE_UINT8 | TAGTYPE_BOOL => {
            if bytes.is_empty() {
                anyhow::bail!("short ED2K uint8/bool tag value");
            }
            let value = bytes[0];
            bytes = &bytes[1..];
            if base_type == TAGTYPE_BOOL {
                Some(DecodedTagValue::Bool(value != 0))
            } else {
                Some(DecodedTagValue::Unsigned(u64::from(value)))
            }
        }
        TAGTYPE_FLOAT32 => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K float32 tag value");
            }
            let value = f32::from_le_bytes(bytes[..4].try_into().unwrap());
            bytes = &bytes[4..];
            Some(DecodedTagValue::Float32(value))
        }
        TAGTYPE_HASH => {
            if bytes.len() < 16 {
                anyhow::bail!("short ED2K hash tag value");
            }
            let value: [u8; 16] = bytes[..16].try_into().unwrap();
            bytes = &bytes[16..];
            Some(DecodedTagValue::Hash(value))
        }
        TAGTYPE_BOOLARRAY => {
            if bytes.len() < 2 {
                anyhow::bail!("short ED2K bool-array tag length");
            }
            let bit_len = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
            bytes = &bytes[2..];
            let byte_len = (bit_len / 8).saturating_add(1);
            if bytes.len() < byte_len {
                anyhow::bail!("short ED2K bool-array tag value");
            }
            let value = bytes[..byte_len].to_vec();
            bytes = &bytes[byte_len..];
            Some(DecodedTagValue::BoolArray(value))
        }
        TAGTYPE_BLOB => {
            if bytes.len() < 4 {
                anyhow::bail!("short ED2K blob tag length");
            }
            let blob_len = usize::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
                .context("ED2K blob tag length overflow")?;
            bytes = &bytes[4..];
            if bytes.len() < blob_len {
                anyhow::bail!("short ED2K blob tag value");
            }
            let value = bytes[..blob_len].to_vec();
            bytes = &bytes[blob_len..];
            Some(DecodedTagValue::Blob(value))
        }
        _ => anyhow::bail!("unsupported ED2K tag type 0x{base_type:02X}"),
    };

    Ok((tag_name, decoded_value, bytes))
}
