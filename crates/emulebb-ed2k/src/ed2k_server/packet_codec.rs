use std::io::{Read, Write};

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use flate2::{Compression, write::ZlibEncoder};

use super::{
    MAX_SERVER_DECOMPRESSED_PACKET_LEN, OP_EDONKEYPROT, OP_PACKEDPROT, TCP_PACKET_HEADER_LEN,
};

pub(super) fn encode_packet(opcode: u8, payload: &[u8], use_compression: bool) -> Result<Vec<u8>> {
    let protocol = if use_compression {
        OP_PACKEDPROT
    } else {
        OP_EDONKEYPROT
    };
    let encoded_payload = if use_compression {
        encode_packed_payload(payload)?
    } else {
        payload.to_vec()
    };
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + encoded_payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(encoded_payload.len() + 1).context("payload too large")?).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(&encoded_payload);
    Ok(bytes)
}

pub(super) fn decode_server_payload(protocol: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    if protocol != OP_PACKEDPROT {
        return Ok(payload);
    }

    let mut decoder = ZlibDecoder::new(payload.as_slice());
    let mut decoded = Vec::with_capacity(
        payload
            .len()
            .saturating_mul(10)
            .saturating_add(300)
            .min(MAX_SERVER_DECOMPRESSED_PACKET_LEN),
    );
    let mut chunk = [0u8; 4096];
    loop {
        let read = decoder.read(&mut chunk).context("zlib inflate failed")?;
        if read == 0 {
            break;
        }
        if decoded.len().saturating_add(read) > MAX_SERVER_DECOMPRESSED_PACKET_LEN {
            anyhow::bail!(
                "decompressed ED2K server packet exceeded {} bytes",
                MAX_SERVER_DECOMPRESSED_PACKET_LEN
            );
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok(decoded)
}

fn encode_packed_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .context("failed to deflate ED2K server payload")?;
    encoder
        .finish()
        .context("failed to finalize ED2K server payload compression")
}
