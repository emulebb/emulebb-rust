use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;

use super::super::{
    OP_AICHANSWER, OP_AICHFILEHASHANS, OP_AICHFILEHASHREQ, OP_AICHREQUEST, OP_EMULEPROT,
};
use super::encode_packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct AichRecoveryRequest {
    pub(in crate::ed2k_tcp) file_hash: Ed2kHash,
    pub(in crate::ed2k_tcp) part: u16,
    pub(in crate::ed2k_tcp) master_hash: [u8; 20],
}

/// Encode an OP_AICHREQUEST soliciting ICH block recovery for one corrupt part,
/// mirroring `CUpDownClient::SendAICHRequest`:
/// `<file hash 16><part u16 LE><master hash 20>`.
pub(in crate::ed2k_tcp) fn encode_aich_recovery_request(
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

pub(in crate::ed2k_tcp) fn decode_aich_recovery_request_payload(
    payload: &[u8],
) -> Result<AichRecoveryRequest> {
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
pub(in crate::ed2k_tcp) struct AichRecoveryAnswer {
    pub(in crate::ed2k_tcp) file_hash: Ed2kHash,
    pub(in crate::ed2k_tcp) part: Option<u16>,
    pub(in crate::ed2k_tcp) master_hash: Option<[u8; 20]>,
    pub(in crate::ed2k_tcp) recovery_payload_len: usize,
}

pub(in crate::ed2k_tcp) fn decode_aich_recovery_answer_payload(
    payload: &[u8],
) -> Result<AichRecoveryAnswer> {
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

pub(in crate::ed2k_tcp) fn encode_aich_recovery_failure_answer(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHANSWER, &file_hash.0)
}

/// Encode a successful OP_AICHANSWER carrying real recovery data, mirroring
/// `CUpDownClient::ProcessAICHRequest`'s success packet:
/// `<file hash 16><part u16><master hash 20><recovery body>`.
pub(in crate::ed2k_tcp) fn encode_aich_recovery_answer(
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

pub(in crate::ed2k_tcp) fn encode_aich_file_hash_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHREQ, &file_hash.0)
}

pub(in crate::ed2k_tcp) fn encode_aich_file_hash_answer(
    file_hash: &Ed2kHash,
    aich_root: [u8; 20],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&aich_root);
    encode_packet(OP_EMULEPROT, OP_AICHFILEHASHANS, &payload)
}

pub(in crate::ed2k_tcp) fn decode_aich_file_hash_answer(
    payload: &[u8],
) -> Result<(Ed2kHash, [u8; 20])> {
    if payload.len() < 36 {
        anyhow::bail!("short OP_AICHFILEHASHANS payload {}", payload.len());
    }
    Ok((
        Ed2kHash::from_bytes(payload[..16].try_into()?),
        payload[16..36].try_into()?,
    ))
}
