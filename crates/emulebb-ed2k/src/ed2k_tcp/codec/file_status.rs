use anyhow::Result;

use crate::ed2k_transfer::ED2K_PART_SIZE;

use super::super::{OP_EDONKEYPROT, OP_FILESTATUS};
use super::encode_packet;

pub(in crate::ed2k_tcp) fn decode_file_status_payload(
    payload: &[u8],
) -> Result<(emulebb_kad_proto::Ed2kHash, u16)> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_FILESTATUS payload size {}", payload.len());
    }
    let returned_hash = emulebb_kad_proto::Ed2kHash::from_bytes(payload[..16].try_into()?);
    let part_count = u16::from_le_bytes([payload[16], payload[17]]);
    let expected_bitfield_len = usize::from(part_count).div_ceil(8);
    if payload.len() < 18 + expected_bitfield_len {
        anyhow::bail!(
            "invalid OP_FILESTATUS payload size {} for part_count {}",
            payload.len(),
            part_count
        );
    }
    Ok((returned_hash, part_count))
}

/// Decodes the peer's advertised per-part availability from an OP_FILESTATUS
/// payload. Bits are LSB-first within each byte (mirrors
/// `encode_request_filename_ext_info`). A `part_count` of 0 means the peer holds
/// the complete file; the caller maps that to an all-available bitmap of the
/// expected length.
pub(in crate::ed2k_tcp) fn decode_file_status_availability(
    payload: &[u8],
) -> Result<(emulebb_kad_proto::Ed2kHash, Vec<bool>)> {
    let (returned_hash, part_count) = decode_file_status_payload(payload)?;
    let mut bitmap = Vec::with_capacity(usize::from(part_count));
    let bitfield = &payload[18..];
    for index in 0..usize::from(part_count) {
        let present = (bitfield[index / 8] >> (index % 8)) & 1 == 1;
        bitmap.push(present);
    }
    Ok((returned_hash, bitmap))
}

pub(in crate::ed2k_tcp) fn validate_file_status_part_count(
    part_count: u16,
    file_size: u64,
) -> Result<()> {
    if part_count == 0 {
        return Ok(());
    }
    let expected = expected_file_status_part_count(file_size);
    if part_count != expected {
        anyhow::bail!("OP_FILESTATUS part_count {part_count} expected {expected}");
    }
    Ok(())
}

fn expected_file_status_part_count(file_size: u64) -> u16 {
    let part_count = file_size.div_ceil(ED2K_PART_SIZE);
    u16::try_from(part_count).unwrap_or(u16::MAX)
}

pub(in crate::ed2k_tcp) fn encode_file_status_complete(
    file_hash: &emulebb_kad_proto::Ed2kHash,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EDONKEYPROT, OP_FILESTATUS, &payload)
}

pub(in crate::ed2k_tcp) fn encode_file_status_body_complete() -> Vec<u8> {
    0u16.to_le_bytes().to_vec()
}

/// Like the legacy skip helper but also returns the peer's per-part
/// availability bitmap (LSB-first within each byte). Empty when `part_count`
/// is 0, which the caller maps to "complete file".
pub(in crate::ed2k_tcp) fn decode_file_status_body_availability(
    payload: &[u8],
) -> Result<(Vec<bool>, &[u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_FILESTATUS body");
    }
    let part_count = u16::from_le_bytes([payload[0], payload[1]]);
    let bitfield_len = usize::from(part_count).div_ceil(8);
    let expected_len = 2 + bitfield_len;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_FILESTATUS body {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    let bitfield = &payload[2..expected_len];
    let bitmap = (0..usize::from(part_count))
        .map(|index| (bitfield[index / 8] >> (index % 8)) & 1 == 1)
        .collect();
    Ok((bitmap, &payload[expected_len..]))
}
