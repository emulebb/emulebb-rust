use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kAichHashset};

use super::super::{
    Ed2kFileIdentifier, Ed2kHashsetAnswer2, Ed2kHashsetRequestOptions, Ed2kMd4HashsetDecode,
    OP_EDONKEYPROT, OP_EMULEPROT, OP_HASHSETANSWER, OP_HASHSETANSWER2, OP_HASHSETREQUEST,
    OP_HASHSETREQUEST2,
};
use super::encode_packet;

pub(in crate::ed2k_tcp) fn encode_hashset_request(file_hash: &Ed2kHash) -> Vec<u8> {
    encode_packet(OP_EDONKEYPROT, OP_HASHSETREQUEST, &file_hash.0)
}

pub(in crate::ed2k_tcp) fn encode_hashset_request2(
    file_identifier: &Ed2kFileIdentifier,
    request_options: Ed2kHashsetRequestOptions,
) -> Result<Vec<u8>> {
    anyhow::ensure!(
        request_options.has_known_request(),
        "OP_HASHSETREQUEST2 expects at least one known hashset request"
    );
    let mut payload = Vec::with_capacity(46);
    file_identifier.encode_into(&mut payload);
    payload.push(request_options.encode());
    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETREQUEST2, &payload))
}

pub(in crate::ed2k_tcp) fn encode_hashset_answer(
    file_hash: &Ed2kHash,
    md4_hashset: &[[u8; 16]],
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(16 + 2 + (md4_hashset.len() * 16));
    encode_md4_hashset_body(file_hash, md4_hashset, &mut payload)?;
    Ok(encode_packet(OP_EDONKEYPROT, OP_HASHSETANSWER, &payload))
}

pub(in crate::ed2k_tcp) fn encode_hashset_answer2(
    file_identifier: &Ed2kFileIdentifier,
    md4_hashset: Option<&[[u8; 16]]>,
    aich_hashset: Option<&Ed2kAichHashset>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(48);
    file_identifier.encode_into(&mut payload);

    let include_md4 = md4_hashset.is_some_and(|hashset| {
        !hashset.is_empty()
            || file_identifier
                .file_size
                .is_some_and(|file_size| file_size > ED2K_PART_SIZE)
    });
    let include_aich = aich_hashset.is_some();
    payload.push(
        Ed2kHashsetRequestOptions {
            request_md4: include_md4,
            request_aich: include_aich,
        }
        .encode(),
    );
    if let Some(hashset) = md4_hashset.filter(|_| include_md4) {
        encode_md4_hashset_body(&file_identifier.file_hash, hashset, &mut payload)?;
    }
    if let Some(hashset) = aich_hashset {
        encode_aich_hashset_body(hashset, &mut payload)?;
    }

    Ok(encode_packet(OP_EMULEPROT, OP_HASHSETANSWER2, &payload))
}

fn encode_md4_hashset_body(
    file_hash: &Ed2kHash,
    md4_hashset: &[[u8; 16]],
    payload: &mut Vec<u8>,
) -> Result<()> {
    let count = u16::try_from(md4_hashset.len()).context("MD4 hashset entry count exceeds u16")?;
    payload.extend_from_slice(&file_hash.0);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in md4_hashset {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

fn encode_aich_hashset_body(hashset: &Ed2kAichHashset, payload: &mut Vec<u8>) -> Result<()> {
    let count =
        u16::try_from(hashset.part_hashes.len()).context("AICH hashset entry count exceeds u16")?;
    payload.extend_from_slice(&hashset.master_hash);
    payload.extend_from_slice(&count.to_le_bytes());
    for part_hash in &hashset.part_hashes {
        payload.extend_from_slice(part_hash);
    }
    Ok(())
}

pub(in crate::ed2k_tcp) fn decode_hashset_request2(
    payload: &[u8],
) -> Result<(Ed2kFileIdentifier, Ed2kHashsetRequestOptions)> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, _)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETREQUEST2 payload");
    };
    Ok((file_identifier, Ed2kHashsetRequestOptions::decode(options)))
}

pub(in crate::ed2k_tcp) fn decode_hashset_answer(
    payload: &[u8],
) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    let (file_hash, hashset, _) = decode_md4_hashset_body(payload)?;
    Ok((file_hash, hashset))
}

pub(in crate::ed2k_tcp) fn decode_hashset_answer2(payload: &[u8]) -> Result<Ed2kHashsetAnswer2> {
    let (file_identifier, remaining) = Ed2kFileIdentifier::decode(payload)?;
    let Some((&options, mut remaining)) = remaining.split_first() else {
        anyhow::bail!("short OP_HASHSETANSWER2 payload");
    };
    let options = Ed2kHashsetRequestOptions::decode(options);
    let md4_hashset = if options.request_md4 {
        let (returned_hash, hashset, rest) = decode_md4_hashset_body(remaining)?;
        if returned_hash != file_identifier.file_hash {
            anyhow::bail!(
                "OP_HASHSETANSWER2 MD4 section was for {} instead of {}",
                returned_hash,
                file_identifier.file_hash
            );
        }
        remaining = rest;
        Some(hashset)
    } else {
        None
    };
    let aich_hashset = if options.request_aich {
        let (hashset, _) = decode_aich_hashset_body(remaining)?;
        if let Some(expected_root) = file_identifier.aich_root
            && hashset.master_hash != expected_root
        {
            anyhow::bail!(
                "OP_HASHSETANSWER2 AICH section root mismatch for {}",
                file_identifier.file_hash
            );
        }
        Some(hashset)
    } else {
        None
    };
    Ok(Ed2kHashsetAnswer2 {
        file_identifier,
        md4_hashset,
        aich_hashset,
    })
}

fn decode_md4_hashset_body(payload: &[u8]) -> Result<Ed2kMd4HashsetDecode<'_>> {
    if payload.len() < 18 {
        anyhow::bail!("short OP_HASHSETANSWER payload {}", payload.len());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let count = usize::from(u16::from_le_bytes([payload[16], payload[17]]));
    let expected = 18 + (count * 16);
    if payload.len() < expected {
        anyhow::bail!(
            "short OP_HASHSETANSWER payload length {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut hashset = Vec::with_capacity(count);
    let mut cursor = 18usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 16];
        part_hash.copy_from_slice(&payload[cursor..cursor + 16]);
        hashset.push(part_hash);
        cursor += 16;
    }
    Ok((Ed2kHash::from_bytes(hash), hashset, &payload[cursor..]))
}

fn decode_aich_hashset_body(payload: &[u8]) -> Result<(Ed2kAichHashset, &[u8])> {
    if payload.len() < 22 {
        anyhow::bail!("short AICH hashset body {}", payload.len());
    }
    let mut master_hash = [0u8; 20];
    master_hash.copy_from_slice(&payload[..20]);
    let count = usize::from(u16::from_le_bytes([payload[20], payload[21]]));
    let expected = 22 + (count * 20);
    if payload.len() < expected {
        anyhow::bail!(
            "short AICH hashset body {} expected at least {}",
            payload.len(),
            expected
        );
    }
    let mut part_hashes = Vec::with_capacity(count);
    let mut cursor = 22usize;
    for _ in 0..count {
        let mut part_hash = [0u8; 20];
        part_hash.copy_from_slice(&payload[cursor..cursor + 20]);
        part_hashes.push(part_hash);
        cursor += 20;
    }
    Ok((
        Ed2kAichHashset {
            master_hash,
            part_hashes,
        },
        &payload[cursor..],
    ))
}
