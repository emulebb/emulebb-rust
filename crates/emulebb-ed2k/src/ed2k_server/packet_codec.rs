use std::io::{Read, Write};

use anyhow::{Context, Result};
use flate2::read::ZlibDecoder;
use flate2::{Compression, write::ZlibEncoder};

use super::{
    MAX_SERVER_DECOMPRESSED_PACKET_LEN, OP_EDONKEYPROT, OP_OFFERFILES, OP_PACKEDPROT,
    TCP_PACKET_HEADER_LEN,
};

/// Whether a server-bound packet of `opcode` is eligible for zlib packing on the
/// TCP path. eMule packs **only** OP_OFFERFILES toward the server
/// (CSharedFileList::SendListToServer, SharedFileList.cpp:2723-2725); every other
/// server-bound opcode (OP_SEARCHREQUEST, OP_GETSOURCES, OP_GETSERVERLIST,
/// OP_QUERY_MORE_RESULT, OP_CALLBACKREQUEST, OP_LOGINREQUEST, keepalive) is sent
/// uncompressed as OP_EDONKEYPROT (0xE3) regardless of SRV_TCPFLG_COMPRESSION.
pub(super) fn server_opcode_allows_compression(opcode: u8) -> bool {
    opcode == OP_OFFERFILES
}

pub(super) fn encode_packet(opcode: u8, payload: &[u8], use_compression: bool) -> Result<Vec<u8>> {
    // WHY: eMule keeps the packed form only when it is strictly smaller than the
    // raw payload (Packet::PackPacket keep-if-smaller rule, Packets.cpp:259
    // `newsize < size`; SharedFileList.cpp:2724-2727 sends the uncompressed packet
    // otherwise). So an incompressible or tiny payload — e.g. the 0-file
    // OP_OFFERFILES keepalive, which zlib expands — goes out as OP_EDONKEYPROT even
    // when the caller permits compression. `use_compression` is set true by the
    // caller only for OP_OFFERFILES on a compression-capable server.
    let packed_payload = if use_compression {
        let candidate = encode_packed_payload(payload)?;
        (candidate.len() < payload.len()).then_some(candidate)
    } else {
        None
    };
    let (protocol, encoded_payload): (u8, &[u8]) = match packed_payload.as_deref() {
        Some(packed) => (OP_PACKEDPROT, packed),
        None => (OP_EDONKEYPROT, payload),
    };
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + encoded_payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(encoded_payload.len() + 1).context("payload too large")?).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(encoded_payload);
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
