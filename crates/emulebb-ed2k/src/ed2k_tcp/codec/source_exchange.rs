use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use super::super::{
    ED2K_SOURCE_EXCHANGE2_VERSION, OP_ANSWERSOURCES, OP_ANSWERSOURCES2, OP_EMULEPROT,
    OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
};
use super::{decode_file_hash_payload, encode_packet};

pub(in crate::ed2k_tcp) fn encode_request_sources2_subpayload() -> [u8; 3] {
    let mut payload = [0u8; 3];
    payload[0] = ED2K_SOURCE_EXCHANGE2_VERSION;
    payload[1..].copy_from_slice(&0u16.to_le_bytes());
    payload
}

pub(in crate::ed2k_tcp) fn encode_request_sources2(file_hash: &Ed2kHash) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19);
    payload.extend_from_slice(&encode_request_sources2_subpayload());
    payload.extend_from_slice(&file_hash.0);
    encode_packet(OP_EMULEPROT, OP_REQUESTSOURCES2, &payload)
}

pub(in crate::ed2k_tcp) fn encode_request_sources(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EMULEPROT, OP_REQUESTSOURCES, &file_hash.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) struct SourceExchangePeer {
    pub(in crate::ed2k_tcp) ip: [u8; 4],
    pub(in crate::ed2k_tcp) tcp_port: u16,
    pub(in crate::ed2k_tcp) server_ip: u32,
    pub(in crate::ed2k_tcp) server_port: u16,
    pub(in crate::ed2k_tcp) user_hash: Option<[u8; 16]>,
    pub(in crate::ed2k_tcp) connect_options: u8,
}

pub(in crate::ed2k_tcp) fn encode_answer_sources(
    file_hash: &Ed2kHash,
    sources: &[SourceExchangePeer],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(18 + sources.len() * 12);
    payload.extend_from_slice(&file_hash.0);
    encode_source_exchange_entries(&mut payload, 1, sources);
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES, &payload)
}

pub(in crate::ed2k_tcp) fn encode_answer_sources2(
    file_hash: &Ed2kHash,
    version: u8,
    sources: &[SourceExchangePeer],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(19 + sources.len() * 29);
    payload.push(version);
    payload.extend_from_slice(&file_hash.0);
    encode_source_exchange_entries(&mut payload, version, sources);
    encode_packet(OP_EMULEPROT, OP_ANSWERSOURCES2, &payload)
}

pub(in crate::ed2k_tcp) fn source_exchange_entry_count(
    version: u8,
    sources: &[SourceExchangePeer],
) -> usize {
    let include_user_hash = version >= 2;
    sources
        .iter()
        .filter(|source| !include_user_hash || source.user_hash.is_some())
        .take(501)
        .count()
}

fn encode_source_exchange_entries(
    payload: &mut Vec<u8>,
    version: u8,
    sources: &[SourceExchangePeer],
) {
    let include_connect_options = version >= 4;
    let include_user_hash = version >= 2;
    let max_sources = source_exchange_entry_count(version, sources);
    payload.extend_from_slice(
        &u16::try_from(max_sources)
            .expect("source exchange count is capped")
            .to_le_bytes(),
    );
    for source in sources
        .iter()
        .filter(|source| !include_user_hash || source.user_hash.is_some())
        .take(501)
    {
        let client_id = if version < 3 {
            u32::from_le_bytes(source.ip)
        } else {
            u32::from_be_bytes(source.ip)
        };
        payload.extend_from_slice(&client_id.to_le_bytes());
        payload.extend_from_slice(&source.tcp_port.to_le_bytes());
        payload.extend_from_slice(&source.server_ip.to_le_bytes());
        payload.extend_from_slice(&source.server_port.to_le_bytes());
        if include_user_hash {
            payload.extend_from_slice(&source.user_hash.expect("filtered sources have user hash"));
        }
        if include_connect_options {
            payload.push(source.connect_options);
        }
    }
}

pub(in crate::ed2k_tcp) fn decode_request_sources_payload(
    opcode: u8,
    payload: &[u8],
) -> Result<(Ed2kHash, u8)> {
    match opcode {
        OP_REQUESTSOURCES => Ok((decode_file_hash_payload(payload)?, 0)),
        OP_REQUESTSOURCES2 => {
            if payload.len() < 19 {
                anyhow::bail!("short OP_REQUESTSOURCES2 payload {}", payload.len());
            }
            Ok((decode_file_hash_payload(&payload[3..])?, payload[0]))
        }
        _ => anyhow::bail!("unsupported source request opcode 0x{opcode:02X}"),
    }
}

pub(in crate::ed2k_tcp) fn decode_answer_sources2_payload(
    payload: &[u8],
) -> Result<(Ed2kHash, Vec<SourceExchangePeer>)> {
    if payload.len() < 1 + 16 + 2 {
        anyhow::bail!("short OP_ANSWERSOURCES2 payload {}", payload.len());
    }
    let version = payload[0];
    if !(1..=ED2K_SOURCE_EXCHANGE2_VERSION).contains(&version) {
        anyhow::bail!("unsupported OP_ANSWERSOURCES2 version {version}");
    }

    let file_hash = Ed2kHash(payload[1..17].try_into().unwrap());
    let count = usize::from(u16::from_le_bytes([payload[17], payload[18]]));
    let sources =
        decode_source_exchange_entries(version, count, &payload[19..], "OP_ANSWERSOURCES2")?;

    Ok((file_hash, sources))
}

pub(in crate::ed2k_tcp) fn decode_answer_sources_payload(
    payload: &[u8],
    peer_source_exchange_version: u8,
) -> Result<(Ed2kHash, Vec<SourceExchangePeer>)> {
    if payload.len() < 16 + 2 {
        anyhow::bail!("short OP_ANSWERSOURCES payload {}", payload.len());
    }

    let file_hash = Ed2kHash(payload[..16].try_into().unwrap());
    let count = usize::from(u16::from_le_bytes([payload[16], payload[17]]));
    let sources_payload = &payload[18..];
    let version = infer_source_exchange1_payload_version(
        count,
        sources_payload,
        peer_source_exchange_version,
    )?;
    let sources =
        decode_source_exchange_entries(version, count, sources_payload, "OP_ANSWERSOURCES")?;

    Ok((file_hash, sources))
}

fn infer_source_exchange1_payload_version(
    count: usize,
    sources_payload: &[u8],
    peer_source_exchange_version: u8,
) -> Result<u8> {
    let v1_size = count
        .checked_mul(source_exchange_entry_size(1))
        .context("OP_ANSWERSOURCES source count overflow")?;
    if sources_payload.len() == v1_size {
        if peer_source_exchange_version < 1 {
            anyhow::bail!("peer does not advertise source exchange 1 support");
        }
        return Ok(1);
    }

    let v2_or_v3_size = count
        .checked_mul(source_exchange_entry_size(2))
        .context("OP_ANSWERSOURCES source count overflow")?;
    if sources_payload.len() == v2_or_v3_size {
        if peer_source_exchange_version < 2 {
            anyhow::bail!(
                "peer source exchange version {} is too old for hash-bearing OP_ANSWERSOURCES",
                peer_source_exchange_version
            );
        }
        return Ok(if peer_source_exchange_version == 2 {
            2
        } else {
            3
        });
    }

    let v4_size = count
        .checked_mul(source_exchange_entry_size(4))
        .context("OP_ANSWERSOURCES source count overflow")?;
    if sources_payload.len() == v4_size {
        if peer_source_exchange_version < 4 {
            anyhow::bail!(
                "peer source exchange version {} is too old for connect-option OP_ANSWERSOURCES",
                peer_source_exchange_version
            );
        }
        return Ok(4);
    }

    anyhow::bail!(
        "corrupt OP_ANSWERSOURCES payload count={} size={}",
        count,
        sources_payload.len()
    );
}

fn decode_source_exchange_entries(
    version: u8,
    count: usize,
    sources_payload: &[u8],
    opcode_name: &str,
) -> Result<Vec<SourceExchangePeer>> {
    let entry_size = source_exchange_entry_size(version);
    let expected_size = count
        .checked_mul(entry_size)
        .with_context(|| format!("{opcode_name} source count overflow"))?;
    if sources_payload.len() != expected_size {
        anyhow::bail!(
            "corrupt {opcode_name} payload version={} count={} size={}",
            version,
            count,
            sources_payload.len()
        );
    }

    let mut sources = Vec::with_capacity(count);
    for entry in sources_payload.chunks_exact(entry_size) {
        let ip = if version < 3 {
            entry[..4].try_into().unwrap()
        } else {
            u32::from_le_bytes(entry[..4].try_into().unwrap()).to_be_bytes()
        };
        let tcp_port = u16::from_le_bytes(entry[4..6].try_into().unwrap());
        let server_ip = u32::from_le_bytes(entry[6..10].try_into().unwrap());
        let server_port = u16::from_le_bytes(entry[10..12].try_into().unwrap());
        let user_hash = if version >= 2 {
            Some(entry[12..28].try_into().unwrap())
        } else {
            None
        };
        let connect_options = if version >= 4 { entry[28] } else { 0 };
        sources.push(SourceExchangePeer {
            ip,
            tcp_port,
            server_ip,
            server_port,
            user_hash,
            connect_options,
        });
    }

    Ok(sources)
}

const fn source_exchange_entry_size(version: u8) -> usize {
    match version {
        1 => 4 + 2 + 4 + 2,
        2 | 3 => 4 + 2 + 4 + 2 + 16,
        _ => 4 + 2 + 4 + 2 + 16 + 1,
    }
}
