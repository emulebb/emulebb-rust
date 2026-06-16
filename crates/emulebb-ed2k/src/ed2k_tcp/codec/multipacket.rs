use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kResumeManifest};

use super::super::{
    Ed2kFileIdentifier, OP_AICHFILEHASHANS, OP_AICHFILEHASHREQ, OP_EMULEPROT, OP_FILESTATUS,
    OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_MULTIPACKET_EXT2, OP_MULTIPACKETANSWER,
    OP_MULTIPACKETANSWER_EXT2, OP_REQFILENAMEANSWER, OP_REQUESTFILENAME, OP_REQUESTSOURCES,
    OP_REQUESTSOURCES2, OP_SETREQFILEID,
};
use super::{
    encode_packet, encode_request_filename_answer_body, encode_request_filename_ext_info,
    encode_request_sources2_subpayload,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ed2k_tcp) enum PeerSourceExchangeRequest {
    None,
    V1,
    V2,
}

pub(in crate::ed2k_tcp) fn encode_multipacket_ext2_request(
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

pub(in crate::ed2k_tcp) fn encode_multipacket_request(
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

pub(in crate::ed2k_tcp) fn encode_multipacket_ext2_answer(
    file_identifier: &Ed2kFileIdentifier,
    file_name: &str,
    include_filename_answer: bool,
    file_status_body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    file_identifier.encode_into(&mut payload);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if let Some(status_body) = file_status_body {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(status_body);
    }
    Ok(encode_packet(
        OP_EMULEPROT,
        OP_MULTIPACKETANSWER_EXT2,
        &payload,
    ))
}

pub(in crate::ed2k_tcp) fn encode_multipacket_answer(
    file_hash: &Ed2kHash,
    file_name: &str,
    include_filename_answer: bool,
    file_status_body: Option<&[u8]>,
    aich_root: Option<[u8; 20]>,
) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&file_hash.0);
    if include_filename_answer {
        payload.push(OP_REQFILENAMEANSWER);
        payload.extend_from_slice(&encode_request_filename_answer_body(file_name)?);
    }
    if let Some(status_body) = file_status_body {
        payload.push(OP_FILESTATUS);
        payload.extend_from_slice(status_body);
    }
    if let Some(aich_root) = aich_root {
        payload.push(OP_AICHFILEHASHANS);
        payload.extend_from_slice(&aich_root);
    }
    Ok(encode_packet(OP_EMULEPROT, OP_MULTIPACKETANSWER, &payload))
}
