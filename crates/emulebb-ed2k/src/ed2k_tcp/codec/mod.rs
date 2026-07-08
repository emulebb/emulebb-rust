use std::{io::Read, net::Ipv4Addr};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;
use flate2::read::ZlibDecoder;

use crate::ed2k_transfer::{Ed2kResumeManifest, Ed2kTransferState, ed2k_part_count};

mod aich;
mod buddy;
mod file_desc;
mod file_status;
mod hashset;
mod multipacket;
mod source_exchange;
mod upload;

pub(super) use aich::{
    AichRecoveryAnswer, decode_aich_file_hash_answer, decode_aich_recovery_answer_payload,
    decode_aich_recovery_request_payload, encode_aich_file_hash_answer,
    encode_aich_file_hash_request, encode_aich_recovery_answer,
    encode_aich_recovery_failure_answer, encode_aich_recovery_request,
};
pub(in crate::ed2k_tcp) use buddy::{
    encode_buddy_ping, encode_buddy_pong, encode_kad_callback_relay,
};
pub(super) use file_desc::{decode_file_description_payload, encode_file_desc};
#[cfg(test)]
pub(super) use file_status::decode_file_status_payload;
pub(super) use file_status::{
    decode_file_status_availability, decode_file_status_body_availability, encode_file_status,
    validate_file_status_part_count,
};
pub(super) use source_exchange::{
    SourceExchangePeer, decode_answer_sources_payload, decode_answer_sources2_payload,
    decode_request_sources_payload, encode_answer_sources2, encode_request_sources2,
    encode_request_sources2_subpayload, source_exchange_entry_count,
};
// SX1 live encoders are no longer used in production (source exchange is SX2-only,
// REF-002 / sx1-live-source-exchange omission); kept for codec round-trip tests.
#[cfg(test)]
pub(super) use source_exchange::{encode_answer_sources, encode_request_sources};

const MAX_CLIENT_MSG_LEN: usize = 450;

use super::{
    MAX_PEER_DECOMPRESSED_PACKET_LEN, OP_ACCEPTUPLOADREQ, OP_ASKSHAREDDENIEDANS,
    OP_ASKSHAREDFILESANSWER, OP_EDONKEYPROT, OP_EMULEPROT, OP_FILEDESC, OP_FILEREQANSNOFIL,
    OP_OUTOFPARTREQS, OP_PACKEDPROT, OP_PORTTEST, OP_PUBLICIP_ANSWER, OP_QUEUERANKING,
    OP_REQFILENAMEANSWER, OP_REQUESTFILENAME, OP_SETREQFILEID, OP_STARTUPLOADREQ,
    TCP_PACKET_HEADER_LEN,
};
pub(super) use hashset::{
    decode_hashset_answer, decode_hashset_answer2, decode_hashset_request2, encode_hashset_answer,
    encode_hashset_answer2, encode_hashset_request, encode_hashset_request2,
};
pub(super) use multipacket::{
    PeerSourceExchangeRequest, encode_multipacket_answer, encode_multipacket_ext2_answer,
    encode_multipacket_ext2_request, encode_multipacket_request,
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

/// Frame an eD2k peer packet with a zlib-packed payload, flipping the protocol
/// byte to OP_PACKEDPROT (0xD4). Mirrors eMule `Packet::PackPacket` compression
/// (Packets.cpp:258); the keep-if-smaller decision is left to the caller.
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
    // The dest IP travels in natural network byte order: the oracle buddy relay
    // wrote sockAddr.sin_addr.s_addr verbatim via PokeUInt32 (ClientUDPSocket.cpp
    // OP_REASKCALLBACKUDP relay) and ListenSocket.cpp OP_REASKCALLBACKTCP reads it
    // straight back as a network-order address. Read the four octets as-is
    // (a.b.c.d -> [a,b,c,d]). Contrast the sibling OP_CALLBACK field, which carries
    // the IP in Kad host order and is byte-reversed on decode.
    let dest_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&payload[..4]).unwrap());
    Ok(ReaskCallbackTcp {
        dest_ip,
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

pub(super) fn encode_accept_upload_req() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_ACCEPTUPLOADREQ, &[])
}

pub(super) fn encode_out_of_part_reqs() -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_OUTOFPARTREQS, &[])
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

/// Encode the OP_REQUESTFILENAME / multipacket ext-info: the embedded
/// `CPartFile::WritePartStatus` partstatus (u16 ED2K part count + one
/// `IsCompleteBD(uPart)` bit per ED2K part, LSB-first) followed by the
/// CompleteSourcesCount u16 (here always 0). The ED2K part count
/// ([`crate::ed2k_transfer::ed2k_part_count`]) is one more than the data-part
/// count at an exact PARTSIZE multiple; that trailing EOF slice is always
/// complete, so it is marked `true`.
pub(super) fn encode_request_filename_ext_info(manifest: &Ed2kResumeManifest) -> Vec<u8> {
    let ed2k_part_count = ed2k_part_count(manifest.file_size);
    let data_part_count = manifest.pieces.len();
    let bitfield_len = usize::from(ed2k_part_count).div_ceil(8);
    let mut payload = Vec::with_capacity(2 + bitfield_len + 2);
    payload.extend_from_slice(&ed2k_part_count.to_le_bytes());
    let mut current_byte = 0u8;
    for index in 0..usize::from(ed2k_part_count) {
        // Data parts follow their verified state; the trailing exact-multiple
        // EOF slice (index >= data_part_count) is always complete.
        let complete =
            index >= data_part_count || manifest.pieces[index].state == Ed2kTransferState::Verified;
        if complete {
            current_byte |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            payload.push(current_byte);
            current_byte = 0;
        }
    }
    if !ed2k_part_count.is_multiple_of(8) {
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
    // ext-info partstatus carries m_iED2KPartCount (size/PARTSIZE+1), not the
    // data-part count.
    let expected_parts = usize::from(ed2k_part_count(file_size));
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

pub(super) fn decode_request_filename_answer(payload: &[u8]) -> Result<(Ed2kHash, String)> {
    let file_hash = decode_file_hash_payload(payload)?;
    let (file_name, _) = decode_request_filename_answer_body(&payload[16..])?;
    Ok((file_hash, file_name))
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
