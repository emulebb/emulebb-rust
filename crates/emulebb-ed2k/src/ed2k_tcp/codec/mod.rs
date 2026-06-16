use std::{io::Read, net::Ipv4Addr};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use flate2::read::ZlibDecoder;

use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferState};

mod buddy;
mod hashset;
mod source_exchange;
mod upload;

pub(in crate::ed2k_tcp) use buddy::{
    encode_buddy_ping, encode_buddy_pong, encode_kad_callback_relay,
};
pub(super) use source_exchange::{
    SourceExchangePeer, decode_answer_sources2_payload, decode_answer_sources_payload,
    decode_request_sources_payload, encode_answer_sources, encode_answer_sources2,
    encode_request_sources, encode_request_sources2, encode_request_sources2_subpayload,
    source_exchange_entry_count,
};

const MAX_CLIENT_MSG_LEN: usize = 450;

use super::{
    Ed2kFileIdentifier, MAX_PEER_DECOMPRESSED_PACKET_LEN, OP_ACCEPTUPLOADREQ, OP_AICHANSWER,
    OP_AICHFILEHASHANS, OP_AICHFILEHASHREQ, OP_AICHREQUEST, OP_ASKSHAREDDENIEDANS,
    OP_ASKSHAREDFILESANSWER, OP_EDONKEYPROT, OP_EMULEPROT, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_MULTIPACKETANSWER,
    OP_MULTIPACKETANSWER_EXT2, OP_PACKEDPROT, OP_PORTTEST, OP_PUBLICIP_ANSWER, OP_QUEUERANKING,
    OP_REQFILENAMEANSWER, OP_REQUESTFILENAME, OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
    OP_SETREQFILEID, OP_STARTUPLOADREQ, TCP_PACKET_HEADER_LEN,
};
pub(super) use hashset::{
    decode_hashset_answer, decode_hashset_answer2, decode_hashset_request2, encode_hashset_answer,
    encode_hashset_answer2, encode_hashset_request, encode_hashset_request2,
};
pub(super) use upload::{
    build_upload_part_packets, decode_compressed_part_fragment, decode_request_parts_payload,
    decode_sending_part_payload, encode_request_parts_batch, inflate_compressed_part_fragment,
};
#[cfg(test)]
pub(super) use upload::{encode_compressed_part_fragment, encode_sending_part};

pub(super) fn decode_peer_payload(protocol: u8, payload: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    if protocol != OP_PACKEDPROT {
        return Ok((protocol, payload));
    }

    let mut decoder = ZlibDecoder::new(payload.as_slice());
    let mut decoded = Vec::with_capacity(
        payload
            .len()
            .saturating_mul(10)
            .saturating_add(300)
            .min(MAX_PEER_DECOMPRESSED_PACKET_LEN),
    );
    let mut chunk = [0u8; 4096];
    loop {
        let read = decoder.read(&mut chunk).context("zlib inflate failed")?;
        if read == 0 {
            break;
        }
        if decoded.len().saturating_add(read) > MAX_PEER_DECOMPRESSED_PACKET_LEN {
            anyhow::bail!(
                "decompressed ED2K peer packet exceeded {} bytes",
                MAX_PEER_DECOMPRESSED_PACKET_LEN
            );
        }
        decoded.extend_from_slice(&chunk[..read]);
    }
    Ok((OP_EMULEPROT, decoded))
}

pub(super) fn decode_file_status_payload(
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
pub(super) fn decode_file_status_availability(
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

pub(super) fn validate_file_status_part_count(part_count: u16, file_size: u64) -> Result<()> {
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

pub(super) fn encode_file_status_complete(file_hash: &emulebb_kad_proto::Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&0u16.to_le_bytes());
    encode_packet(OP_EDONKEYPROT, OP_FILESTATUS, &payload)
}

pub(super) fn encode_packet(protocol: u8, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(TCP_PACKET_HEADER_LEN + payload.len());
    bytes.push(protocol);
    bytes.extend_from_slice(
        &(u32::try_from(payload.len() + 1).expect("payload too large")).to_le_bytes(),
    );
    bytes.push(opcode);
    bytes.extend_from_slice(payload);
    bytes
}

#[cfg(test)]
pub(super) fn encode_packed_packet(opcode: u8, payload: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(payload)
        .context("failed to deflate ED2K peer payload")?;
    let packed_payload = encoder
        .finish()
        .context("failed to finalize ED2K peer payload compression")?;
    Ok(encode_packet(OP_PACKEDPROT, opcode, &packed_payload))
}

pub(super) fn decode_file_hash_payload(payload: &[u8]) -> Result<Ed2kHash> {
    if payload.len() < 16 {
        anyhow::bail!("expected 16-byte file hash payload, got {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    Ok(Ed2kHash::from_bytes(hash))
}

pub(super) fn decode_optional_file_hash_payload(payload: &[u8]) -> Option<Ed2kHash> {
    let mut hash = [0u8; 16];
    hash.copy_from_slice(payload.get(..16)?);
    Some(Ed2kHash::from_bytes(hash))
}

pub(super) fn decode_exact_file_hash_payload(payload: &[u8], context: &str) -> Result<Ed2kHash> {
    if payload.len() != 16 {
        anyhow::bail!("invalid {context} payload size {}", payload.len());
    }
    decode_file_hash_payload(payload)
}

pub(super) fn encode_file_req_ans_nofil(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_FILEREQANSNOFIL, &file_hash.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClientIdChange {
    pub(super) new_user_id: u32,
    pub(super) new_server_ip: u32,
    pub(super) trailing_len: usize,
}

pub(super) fn decode_client_id_change_payload(payload: &[u8]) -> Result<ClientIdChange> {
    if payload.len() < 8 {
        anyhow::bail!("short OP_CHANGE_CLIENT_ID payload {}", payload.len());
    }
    Ok(ClientIdChange {
        new_user_id: u32::from_le_bytes(payload[..4].try_into().unwrap()),
        new_server_ip: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
        trailing_len: payload.len() - 8,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct KadCallbackRequest {
    pub(super) buddy_check: [u8; 16],
    pub(super) file_hash: Ed2kHash,
    pub(super) peer_ip: Ipv4Addr,
    pub(super) peer_tcp_port: u16,
    pub(super) trailing_len: usize,
}

pub(super) fn decode_kad_callback_payload(payload: &[u8]) -> Result<KadCallbackRequest> {
    if payload.len() < 38 {
        anyhow::bail!("short OP_CALLBACK payload {}", payload.len());
    }
    let raw_peer_ip = u32::from_le_bytes(payload[32..36].try_into().unwrap());
    Ok(KadCallbackRequest {
        buddy_check: payload[..16].try_into().unwrap(),
        file_hash: Ed2kHash(payload[16..32].try_into().unwrap()),
        peer_ip: Ipv4Addr::from(raw_peer_ip.to_be_bytes()),
        peer_tcp_port: u16::from_le_bytes(payload[36..38].try_into().unwrap()),
        trailing_len: payload.len() - 38,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReaskCallbackTcp {
    pub(super) dest_ip: Ipv4Addr,
    pub(super) dest_port: u16,
    pub(super) file_hash: Ed2kHash,
    pub(super) extended_info_len: usize,
}

pub(super) fn decode_reask_callback_tcp_payload(payload: &[u8]) -> Result<ReaskCallbackTcp> {
    if payload.len() < 22 {
        anyhow::bail!("short OP_REASKCALLBACKTCP payload {}", payload.len());
    }
    let raw_dest_ip = u32::from_le_bytes(payload[..4].try_into().unwrap());
    Ok(ReaskCallbackTcp {
        dest_ip: Ipv4Addr::from(raw_dest_ip.to_be_bytes()),
        dest_port: u16::from_le_bytes(payload[4..6].try_into().unwrap()),
        file_hash: Ed2kHash(payload[6..22].try_into().unwrap()),
        extended_info_len: payload.len() - 22,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClientMessage {
    pub(super) message_len: usize,
    pub(super) accepted_len: usize,
}

pub(super) fn decode_client_message_payload(payload: &[u8]) -> Result<ClientMessage> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_MESSAGE payload {}", payload.len());
    }
    let message_len = usize::from(u16::from_le_bytes(payload[..2].try_into().unwrap()));
    if payload.len() != message_len + 2 {
        anyhow::bail!(
            "invalid OP_MESSAGE payload size {} for message_len {}",
            payload.len(),
            message_len
        );
    }
    Ok(ClientMessage {
        message_len,
        accepted_len: message_len.min(MAX_CLIENT_MSG_LEN),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ChatCaptchaRequest {
    pub(super) tag_count: u8,
    pub(super) data_len: usize,
}

pub(super) fn decode_chat_captcha_request_payload(payload: &[u8]) -> Result<ChatCaptchaRequest> {
    let Some((&tag_count, data)) = payload.split_first() else {
        anyhow::bail!("short OP_CHATCAPTCHAREQ payload 0");
    };
    Ok(ChatCaptchaRequest {
        tag_count,
        data_len: data.len(),
    })
}

pub(super) fn decode_chat_captcha_result_payload(payload: &[u8]) -> Result<u8> {
    let Some((&status, _)) = payload.split_first() else {
        anyhow::bail!("short OP_CHATCAPTCHARES payload 0");
    };
    Ok(status)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreviewRequest {
    pub(super) file_hash: Ed2kHash,
    pub(super) trailing_len: usize,
}

pub(super) fn decode_preview_request_payload(payload: &[u8]) -> Result<PreviewRequest> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_REQUESTPREVIEW payload {}", payload.len());
    }
    Ok(PreviewRequest {
        file_hash: Ed2kHash(payload[..16].try_into().unwrap()),
        trailing_len: payload.len() - 16,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreviewAnswer {
    pub(super) file_hash: Ed2kHash,
    pub(super) frame_count: u8,
    pub(super) frame_payload_bytes: usize,
    pub(super) trailing_len: usize,
}

pub(super) fn decode_preview_answer_payload(payload: &[u8]) -> Result<PreviewAnswer> {
    if payload.len() < 17 {
        anyhow::bail!("short OP_PREVIEWANSWER payload {}", payload.len());
    }
    let file_hash = Ed2kHash(payload[..16].try_into().unwrap());
    let frame_count = payload[16];
    let mut offset = 17usize;
    let mut frame_payload_bytes = 0usize;
    for _ in 0..frame_count {
        if payload.len() < offset + 4 {
            anyhow::bail!("short OP_PREVIEWANSWER frame length");
        }
        let frame_len = usize::try_from(u32::from_le_bytes(
            payload[offset..offset + 4].try_into().unwrap(),
        ))
        .context("OP_PREVIEWANSWER frame length overflow")?;
        offset += 4;
        if frame_len > payload.len() || payload.len() < offset + frame_len {
            anyhow::bail!(
                "short OP_PREVIEWANSWER frame {} expected {}",
                payload.len().saturating_sub(offset),
                frame_len
            );
        }
        frame_payload_bytes = frame_payload_bytes
            .checked_add(frame_len)
            .context("OP_PREVIEWANSWER frame bytes overflow")?;
        offset += frame_len;
    }
    Ok(PreviewAnswer {
        file_hash,
        frame_count,
        frame_payload_bytes,
        trailing_len: payload.len() - offset,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AichRecoveryRequest {
    pub(super) file_hash: Ed2kHash,
    pub(super) part: u16,
    pub(super) master_hash: [u8; 20],
}

/// Encode an OP_AICHREQUEST soliciting ICH block recovery for one corrupt part,
/// mirroring `CUpDownClient::SendAICHRequest`:
/// `<file hash 16><part u16 LE><master hash 20>`.
pub(super) fn encode_aich_recovery_request(
    file_hash: &Ed2kHash,
    part: u16,
    master_hash: [u8; 20],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + 2 + 20);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&part.to_le_bytes());
    payload.extend_from_slice(&master_hash);
    encode_packet(OP_EMULEPROT, OP_AICHREQUEST, &payload)
}

pub(super) fn decode_aich_recovery_request_payload(payload: &[u8]) -> Result<AichRecoveryRequest> {
    if payload.len() != 38 {
        anyhow::bail!("invalid OP_AICHREQUEST payload size {}", payload.len());
    }
    Ok(AichRecoveryRequest {
        file_hash: Ed2kHash(payload[..16].try_into().unwrap()),
        part: u16::from_le_bytes(payload[16..18].try_into().unwrap()),
        master_hash: payload[18..38].try_into().unwrap(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AichRecoveryAnswer {
    pub(super) file_hash: Ed2kHash,
    pub(super) part: Option<u16>,
    pub(super) master_hash: Option<[u8; 20]>,
    pub(super) recovery_payload_len: usize,
}

pub(super) fn decode_aich_recovery_answer_payload(payload: &[u8]) -> Result<AichRecoveryAnswer> {
    if payload.len() == 16 {
        return Ok(AichRecoveryAnswer {
            file_hash: Ed2kHash(payload[..16].try_into().unwrap()),
            part: None,
            master_hash: None,
            recovery_payload_len: 0,
        });
    }
    if payload.len() < 38 {
        anyhow::bail!("short OP_AICHANSWER payload {}", payload.len());
    }
    Ok(AichRecoveryAnswer {
        file_hash: Ed2kHash(payload[..16].try_into().unwrap()),
        part: Some(u16::from_le_bytes(payload[16..18].try_into().unwrap())),
        master_hash: Some(payload[18..38].try_into().unwrap()),
        recovery_payload_len: payload.len() - 38,
    })
}

pub(super) fn encode_aich_recovery_failure_answer(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHANSWER, &file_hash.0)
}

/// Encode a successful OP_AICHANSWER carrying real recovery data, mirroring
/// `CUpDownClient::ProcessAICHRequest`'s success packet:
/// `<file hash 16><part u16><master hash 20><recovery body>`.
pub(super) fn encode_aich_recovery_answer(
    file_hash: &Ed2kHash,
    part: u16,
    master_hash: [u8; 20],
    recovery_body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16 + 2 + 20 + recovery_body.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&part.to_le_bytes());
    payload.extend_from_slice(&master_hash);
    payload.extend_from_slice(recovery_body);
    encode_packet(OP_EMULEPROT, OP_AICHANSWER, &payload)
}

pub(super) fn encode_accept_upload_req() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, &[])
}

pub(super) fn encode_queue_ranking(rank: u16) -> Vec<u8> {
    let mut payload = [0u8; 12];
    payload[..2].copy_from_slice(&rank.to_le_bytes());
    encode_packet(OP_EMULEPROT, OP_QUEUERANKING, &payload)
}

pub(super) fn decode_edonkey_queue_rank_payload(payload: &[u8]) -> Result<u32> {
    if payload.len() < 4 {
        anyhow::bail!("short OP_QUEUERANK payload {}", payload.len());
    }
    Ok(u32::from_le_bytes(payload[..4].try_into().unwrap()))
}

pub(super) fn decode_emule_queue_ranking_payload(payload: &[u8]) -> Result<u16> {
    if payload.len() != 12 {
        anyhow::bail!("invalid OP_QUEUERANKING payload size {}", payload.len());
    }
    Ok(u16::from_le_bytes(payload[..2].try_into().unwrap()))
}

pub(super) fn encode_public_ip_answer(ip: Ipv4Addr) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_PUBLICIP_ANSWER, &ip.octets())
}

pub(super) fn decode_public_ip_answer_payload(payload: &[u8]) -> Result<Ipv4Addr> {
    if payload.len() != 4 {
        anyhow::bail!("invalid OP_PUBLICIP_ANSWER payload size {}", payload.len());
    }
    Ok(Ipv4Addr::new(
        payload[0], payload[1], payload[2], payload[3],
    ))
}

pub(super) fn encode_port_test_answer() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_PORTTEST, &[0x12])
}

pub(super) fn encode_start_upload_req(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_STARTUPLOADREQ, &file_hash.0)
}

pub(super) fn ed2k_file_part_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    u16::try_from(file_size.div_ceil(ED2K_PART_SIZE)).unwrap_or(u16::MAX)
}

pub(super) fn encode_request_filename_ext_info(manifest: &Ed2kResumeManifest) -> Vec<u8> {
    let piece_count = u16::try_from(manifest.pieces.len()).unwrap_or(u16::MAX);
    let bitfield_len = usize::from(piece_count).div_ceil(8);
    let mut payload = Vec::with_capacity(2 + bitfield_len + 2);
    payload.extend_from_slice(&piece_count.to_le_bytes());
    let mut current_byte = 0u8;
    for (index, piece) in manifest.pieces.iter().enumerate() {
        if piece.state == Ed2kTransferState::Verified {
            current_byte |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            payload.push(current_byte);
            current_byte = 0;
        }
    }
    if piece_count % 8 != 0 {
        payload.push(current_byte);
    }
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload
}

pub(super) fn skip_request_filename_ext_info(payload: &[u8], file_size: u64) -> Result<&[u8]> {
    if payload.len() < 2 {
        anyhow::bail!("short OP_REQUESTFILENAME ext-info payload");
    }
    let part_count = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    let expected_parts = usize::from(ed2k_file_part_count(file_size));
    let bitfield_len = part_count.div_ceil(8);
    let expected_len = 2 + bitfield_len + 2;
    if payload.len() < expected_len {
        anyhow::bail!(
            "short OP_REQUESTFILENAME ext-info payload {} expected at least {}",
            payload.len(),
            expected_len
        );
    }
    if expected_parts != 0 && part_count != expected_parts {
        anyhow::bail!(
            "OP_REQUESTFILENAME part count mismatch {} expected {}",
            part_count,
            expected_parts
        );
    }
    Ok(&payload[expected_len..])
}

pub(super) fn encode_request_filename(
    file_hash: &Ed2kHash,
    manifest: &Ed2kResumeManifest,
) -> Vec<u8> {
    let ext_info = encode_request_filename_ext_info(manifest);
    let mut payload = Vec::with_capacity(16 + ext_info.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&ext_info);
    encode_packet(OP_EDONKEYPROT, OP_REQUESTFILENAME, &payload)
}

pub(super) fn encode_aich_file_hash_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHREQ, &file_hash.0)
}

pub(super) fn encode_aich_file_hash_answer(file_hash: &Ed2kHash, aich_root: [u8; 20]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&aich_root);
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHANS, &payload)
}

pub(super) fn encode_set_req_file_id(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_SETREQFILEID, &file_hash.0)
}

pub(super) fn encode_request_filename_answer_body(file_name: &str) -> Result<Vec<u8>> {
    encode_ed2k_string_body(file_name, "ED2K string")
}

fn encode_ed2k_string_body(value: &str, context: &str) -> Result<Vec<u8>> {
    let value = value.as_bytes();
    let mut payload = Vec::with_capacity(2 + value.len());
    payload.extend_from_slice(
        &(u16::try_from(value.len()).with_context(|| format!("{context} too large"))?)
            .to_le_bytes(),
    );
    payload.extend_from_slice(value);
    Ok(payload)
}

pub(super) fn decode_request_filename_answer_body(payload: &[u8]) -> Result<(String, &[u8])> {
    decode_ed2k_string_body(payload, "OP_REQFILENAMEANSWER")
}

fn decode_ed2k_string_body<'a>(payload: &'a [u8], context: &str) -> Result<(String, &'a [u8])> {
    if payload.len() < 2 {
        anyhow::bail!("short {context} string body");
    }
    let len = usize::from(u16::from_le_bytes([payload[0], payload[1]]));
    if payload.len() < 2 + len {
        anyhow::bail!("short {context} string");
    }
    Ok((
        String::from_utf8_lossy(&payload[2..2 + len]).into_owned(),
        &payload[2 + len..],
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SharedFilesAnswer {
    pub(super) file_count: u32,
    pub(super) entry_bytes: usize,
}

pub(super) fn encode_empty_shared_files_answer() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ASKSHAREDFILESANSWER, &0u32.to_le_bytes())
}

pub(super) fn encode_shared_browse_denied_answer() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ASKSHAREDDENIEDANS, &[])
}

pub(super) fn decode_shared_files_answer_payload(payload: &[u8]) -> Result<SharedFilesAnswer> {
    if payload.len() < 4 {
        anyhow::bail!("short OP_ASKSHAREDFILESANSWER payload {}", payload.len());
    }
    Ok(SharedFilesAnswer {
        file_count: u32::from_le_bytes(payload[..4].try_into().unwrap()),
        entry_bytes: payload.len() - 4,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SharedDirsAnswer {
    pub(super) dir_count: u32,
    pub(super) dirs: Vec<String>,
}

pub(super) fn decode_shared_dirs_answer_payload(payload: &[u8]) -> Result<SharedDirsAnswer> {
    if payload.len() < 4 {
        anyhow::bail!("short OP_ASKSHAREDDIRSANS payload {}", payload.len());
    }
    let dir_count = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let mut remaining = &payload[4..];
    let mut dirs = Vec::new();
    for _ in 0..dir_count {
        let (dir, rest) = decode_ed2k_string_body(remaining, "OP_ASKSHAREDDIRSANS")?;
        dirs.push(dir);
        remaining = rest;
    }
    Ok(SharedDirsAnswer { dir_count, dirs })
}

pub(super) fn decode_shared_files_dir_request_payload(payload: &[u8]) -> Result<String> {
    let (dir, _) = decode_ed2k_string_body(payload, "OP_ASKSHAREDFILESDIR")?;
    Ok(dir)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SharedFilesDirAnswer {
    pub(super) dir: String,
    pub(super) file_count: u32,
    pub(super) entry_bytes: usize,
}

pub(super) fn decode_shared_files_dir_answer_payload(
    payload: &[u8],
) -> Result<SharedFilesDirAnswer> {
    let (dir, remaining) = decode_ed2k_string_body(payload, "OP_ASKSHAREDFILESDIRANS")?;
    let files = decode_shared_files_answer_payload(remaining)?;
    Ok(SharedFilesDirAnswer {
        dir,
        file_count: files.file_count,
        entry_bytes: files.entry_bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileDescription {
    pub(super) rating: u8,
    pub(super) comment: String,
}

pub(super) fn decode_file_description_payload(payload: &[u8]) -> Result<FileDescription> {
    if payload.len() < 5 {
        anyhow::bail!("short OP_FILEDESC payload {}", payload.len());
    }
    let rating = payload[0];
    let comment_len = usize::try_from(u32::from_le_bytes(payload[1..5].try_into().unwrap()))
        .context("OP_FILEDESC comment length overflow")?;
    if payload.len() < 5 + comment_len {
        anyhow::bail!(
            "short OP_FILEDESC comment {} expected {}",
            payload.len() - 5,
            comment_len
        );
    }
    let comment = String::from_utf8_lossy(&payload[5..5 + comment_len]).into_owned();
    Ok(FileDescription { rating, comment })
}

pub(super) fn decode_request_filename_answer(payload: &[u8]) -> Result<(Ed2kHash, String)> {
    let file_hash = decode_file_hash_payload(payload)?;
    let (file_name, _) = decode_request_filename_answer_body(&payload[16..])?;
    Ok((file_hash, file_name))
}

pub(super) fn encode_file_status_body_complete() -> Vec<u8> {
    0u16.to_le_bytes().to_vec()
}

/// Like the legacy skip helper but also returns the peer's per-part
/// availability bitmap (LSB-first within each byte). Empty when `part_count`
/// is 0, which the caller maps to "complete file".
pub(super) fn decode_file_status_body_availability(payload: &[u8]) -> Result<(Vec<bool>, &[u8])> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerSourceExchangeRequest {
    None,
    V1,
    V2,
}

pub(super) fn encode_multipacket_ext2_request(
    file_identifier: &Ed2kFileIdentifier,
    manifest: &Ed2kResumeManifest,
    source_exchange_request: PeerSourceExchangeRequest,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    payload.push(OP_REQUESTFILENAME);
    payload.extend_from_slice(&encode_request_filename_ext_info(manifest));
    if manifest.file_size > ED2K_PART_SIZE {
        payload.push(OP_SETREQFILEID);
    }
    match source_exchange_request {
        PeerSourceExchangeRequest::None => {}
        PeerSourceExchangeRequest::V1 => payload.push(OP_REQUESTSOURCES),
        PeerSourceExchangeRequest::V2 => {
            payload.push(OP_REQUESTSOURCES2);
            payload.extend_from_slice(&encode_request_sources2_subpayload());
        }
    }
    encode_packet(OP_EMULEPROT, OP_MULTIPACKET_EXT2, &payload)
}

pub(super) fn encode_multipacket_request(
    file_hash: &Ed2kHash,
    manifest: &Ed2kResumeManifest,
    use_ext_envelope: bool,
    source_exchange_request: PeerSourceExchangeRequest,
    include_aich_request: bool,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&file_hash.0);
    if use_ext_envelope {
        payload.extend_from_slice(&manifest.file_size.to_le_bytes());
    }
    payload.push(OP_REQUESTFILENAME);
    payload.extend_from_slice(&encode_request_filename_ext_info(manifest));
    if manifest.file_size > ED2K_PART_SIZE {
        payload.push(OP_SETREQFILEID);
    }
    match source_exchange_request {
        PeerSourceExchangeRequest::None => {}
        PeerSourceExchangeRequest::V1 => payload.push(OP_REQUESTSOURCES),
        PeerSourceExchangeRequest::V2 => {
            payload.push(OP_REQUESTSOURCES2);
            payload.extend_from_slice(&encode_request_sources2_subpayload());
        }
    }
    if include_aich_request {
        payload.push(OP_AICHFILEHASHREQ);
    }
    let opcode = if use_ext_envelope {
        OP_MULTIPACKET_EXT
    } else {
        OP_MULTIPACKET
    };
    encode_packet(OP_EMULEPROT, opcode, &payload)
}

pub(super) fn encode_multipacket_ext2_answer(
    file_identifier: &Ed2kFileIdentifier,
    file_name: &str,
    include_filename_answer: bool,
    include_file_status: bool,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if include_file_status {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(&encode_file_status_body_complete());
    }
    Ok(encode_packet(
        OP_EMULEPROT,
        OP_MULTIPACKETANSWER_EXT2,
        &payload,
    ))
}

pub(super) fn encode_multipacket_answer(
    file_hash: &Ed2kHash,
    file_name: &str,
    include_filename_answer: bool,
    include_file_status: bool,
    aich_root: Option<[u8; 20]>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&file_hash.0);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if include_file_status {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(&encode_file_status_body_complete());
    }
    if let Some(aich_root) = aich_root {
        payload.push(OP_AICHFILEHASHANS);
        payload.extend_from_slice(&aich_root);
    }
    Ok(encode_packet(OP_EMULEPROT, OP_MULTIPACKETANSWER, &payload))
}

pub(super) fn encode_request_filename_answer(
    file_hash: &Ed2kHash,
    file_name: &str,
) -> Result<Vec<u8>> {
    let body = encode_request_filename_answer_body(file_name)?;
    let mut payload = Vec::with_capacity(16 + body.len());
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&body);
    Ok(encode_packet(
        OP_EDONKEYPROT,
        OP_REQFILENAMEANSWER,
        &payload,
    ))
}

pub(super) fn decode_aich_file_hash_answer(payload: &[u8]) -> Result<(Ed2kHash, [u8; 20])> {
    if payload.len() < 36 {
        anyhow::bail!("short OP_AICHFILEHASHANS payload {}", payload.len());
    }
    Ok((
        Ed2kHash::from_bytes(payload[..16].try_into()?),
        payload[16..36].try_into()?,
    ))
}
