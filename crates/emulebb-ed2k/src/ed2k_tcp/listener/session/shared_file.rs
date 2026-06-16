use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        ED2K_SOURCE_EXCHANGE2_VERSION, Ed2kFileIdentifier, Ed2kTransport, OP_AICHFILEHASHREQ,
        OP_MULTIPACKET_EXT, OP_REQUESTFILENAME, OP_REQUESTSOURCES, OP_REQUESTSOURCES2,
        OP_SETREQFILEID,
    },
    ed2k_transfer::{Ed2kSharedEntry, Ed2kTransferRuntime},
};

use super::super::super::codec::{
    SourceExchangePeer, decode_exact_file_hash_payload, decode_file_hash_payload,
    decode_hashset_request2, decode_request_sources_payload, encode_aich_file_hash_answer,
    encode_answer_sources, encode_answer_sources2, encode_file_req_ans_nofil, encode_file_status,
    encode_hashset_answer, encode_hashset_answer2, encode_multipacket_answer,
    encode_multipacket_ext2_answer, encode_request_filename_answer, skip_request_filename_ext_info,
    source_exchange_entry_count,
};
use super::super::super::dump::dump_ed2k_tcp_listener_send;

pub(in crate::ed2k_tcp) async fn handle_multipacket_ext2_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested_identifier, mut remaining) = Ed2kFileIdentifier::decode(payload)?;
    let requested = requested_identifier.file_hash;
    // A partfile is a valid requested file only once it holds at least one
    // complete part (master ListenSocket.cpp file-request fallback:
    // downloadqueue file with GetCompletedSize() >= PARTSIZE).
    let Some(shared) = transfer_runtime.local_servable_entry(&requested).await? else {
        send_nofile(transport, peer_addr, &requested, "multipacket_ext2_nofil").await?;
        return Ok(Some(requested));
    };
    let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
    if !shared_identifier.matches_relaxed(&requested_identifier) {
        send_nofile(
            transport,
            peer_addr,
            &requested,
            "multipacket_ext2_mismatch",
        )
        .await?;
        return Ok(Some(requested));
    }

    let mut include_filename = false;
    let mut include_status = false;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            OP_REQUESTFILENAME => {
                let rest = skip_request_filename_ext_info(remaining, shared.file_size)?;
                remaining = rest;
                include_filename = true;
            }
            OP_SETREQFILEID => {
                include_status = true;
            }
            OP_REQUESTSOURCES => {
                let sources = source_exchange_peers(transfer_runtime, &requested, peer_addr.ip()).await?;
                let reply = encode_answer_sources(&requested, &sources);
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
                transport
                    .write_all(&reply)
                    .await
                    .with_context(|| format!("failed to send OP_ANSWERSOURCES to {peer_addr}"))?;
            }
            OP_REQUESTSOURCES2 => {
                if remaining.len() < 3 {
                    anyhow::bail!("short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET_EXT2");
                }
                let requested_version = remaining[0];
                remaining = &remaining[3..];
                if requested_version == 0 {
                    continue;
                }
                let used_version = requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION);
                let sources = source_exchange_peers(transfer_runtime, &requested, peer_addr.ip()).await?;
                if source_exchange_entry_count(used_version, &sources) == 0 {
                    continue;
                }
                let reply = encode_answer_sources2(&requested, used_version, &sources);
                dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
                transport.write_all(&reply).await.with_context(|| {
                    format!("failed to send source exchange reply to {peer_addr}")
                })?;
            }
            OP_AICHFILEHASHREQ => {}
            _ => {
                anyhow::bail!("unsupported OP_MULTIPACKET_EXT2 sub-op 0x{sub_opcode:02X}");
            }
        }
    }

    if include_filename || include_status {
        let status_body = include_status.then(|| shared.encode_part_status_body());
        let reply = encode_multipacket_ext2_answer(
            &shared_identifier,
            &shared.canonical_name,
            include_filename,
            status_body.as_deref(),
        )?;
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "multipacket_ext2_answer", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_MULTIPACKETANSWER_EXT2 to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_multipacket_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    opcode: u8,
    payload: &[u8],
    peer_supports_aich: bool,
    peer_supports_file_identifiers: bool,
) -> Result<Option<Ed2kHash>> {
    if payload.len() < 16 {
        anyhow::bail!("short OP_MULTIPACKET payload {}", payload.len());
    }
    let requested = Ed2kHash::from_bytes(payload[..16].try_into()?);
    let mut remaining = &payload[16..];
    let requested_size = if opcode == OP_MULTIPACKET_EXT {
        if remaining.len() < 8 {
            anyhow::bail!("short OP_MULTIPACKET_EXT size payload {}", payload.len());
        }
        let size = u64::from_le_bytes(remaining[..8].try_into()?);
        remaining = &remaining[8..];
        Some(size).filter(|size| *size != 0)
    } else {
        None
    };
    let Some(shared) = transfer_runtime.local_servable_entry(&requested).await? else {
        send_nofile(transport, peer_addr, &requested, "multipacket_nofil").await?;
        return Ok(Some(requested));
    };
    if requested_size.is_some_and(|size| size != shared.file_size) {
        send_nofile(
            transport,
            peer_addr,
            &requested,
            "multipacket_size_mismatch",
        )
        .await?;
        return Ok(Some(requested));
    }

    let mut include_filename = false;
    let mut include_status = false;
    let mut include_aich_root = None;
    while let Some((&sub_opcode, rest)) = remaining.split_first() {
        remaining = rest;
        match sub_opcode {
            OP_REQUESTFILENAME => {
                remaining = skip_request_filename_ext_info(remaining, shared.file_size)?;
                include_filename = true;
            }
            OP_SETREQFILEID => {
                include_status = true;
            }
            OP_REQUESTSOURCES | OP_REQUESTSOURCES2 => {
                remaining = answer_source_request_subpacket(
                    transfer_runtime,
                    transport,
                    peer_addr,
                    &requested,
                    sub_opcode,
                    remaining,
                )
                .await?;
            }
            OP_AICHFILEHASHREQ => {
                if !peer_supports_file_identifiers && peer_supports_aich {
                    include_aich_root = shared_aich_root(&shared);
                }
            }
            _ => {
                anyhow::bail!("unsupported OP_MULTIPACKET sub-op 0x{sub_opcode:02X}");
            }
        }
    }

    if include_filename || include_status || include_aich_root.is_some() {
        let status_body = include_status.then(|| shared.encode_part_status_body());
        let reply = encode_multipacket_answer(
            &requested,
            &shared.canonical_name,
            include_filename,
            status_body.as_deref(),
            include_aich_root,
        )?;
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "multipacket_answer", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_MULTIPACKETANSWER to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_request_filename(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    let reply = if let Some(shared) = transfer_runtime.local_servable_entry(&requested).await? {
        encode_request_filename_answer(&requested, &shared.canonical_name)?
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "request_filename", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_REQFILENAMEANSWER to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_set_req_file_id(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_exact_file_hash_payload(payload, "OP_SETREQFILEID")?;
    // OP_SETREQFILEID answers the live part-status: a complete file collapses to
    // the master "complete" sentinel, while an in-progress partfile reports its
    // verified parts (master ListenSocket.cpp: IsPartFile() -> WritePartStatus,
    // else WriteUInt16(0)). A partfile is only a valid requested file once it
    // holds at least one complete part.
    let reply = if let Some(shared) = transfer_runtime.local_servable_entry(&requested).await? {
        encode_file_status(&requested, &shared.encode_part_status_body())
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "set_req_file_id", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_SETREQFILEID response to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_hashset_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let requested = decode_exact_file_hash_payload(payload, "OP_HASHSETREQUEST")?;
    let reply = if transfer_runtime.local_entry(&requested).await?.is_some() {
        if let Some(hashset) = transfer_runtime.md4_hashset(&requested).await? {
            encode_hashset_answer(&requested, &hashset)?
        } else {
            encode_file_req_ans_nofil(&requested)
        }
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_HASHSETANSWER to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_hashset_request2(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested_identifier, request_options) = decode_hashset_request2(payload)?;
    let requested = requested_identifier.file_hash;
    if !request_options.has_known_request() {
        return Ok(Some(requested));
    }
    let reply = if let Some(shared) = transfer_runtime.local_entry(&requested).await? {
        let shared_identifier = Ed2kFileIdentifier::from_shared_entry(&shared)?;
        if !shared_identifier.matches_relaxed(&requested_identifier) {
            encode_file_req_ans_nofil(&requested)
        } else {
            let md4_hashset = if request_options.request_md4 {
                transfer_runtime.md4_hashset(&requested).await?
            } else {
                None
            };
            let aich_hashset = if request_options.request_aich {
                transfer_runtime.aich_hashset(&requested).await?
            } else {
                None
            };
            encode_hashset_answer2(
                &shared_identifier,
                md4_hashset.as_deref(),
                aich_hashset.as_ref(),
            )?
        }
    } else {
        encode_file_req_ans_nofil(&requested)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "hashset_request", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_HASHSETANSWER2 to {peer_addr}"))?;
    Ok(Some(requested))
}

pub(in crate::ed2k_tcp) async fn handle_source_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    opcode: u8,
    payload: &[u8],
) -> Result<Option<Ed2kHash>> {
    let (requested, requested_version) = decode_request_sources_payload(opcode, payload)?;
    if opcode == OP_REQUESTSOURCES2 && requested_version == 0 {
        return Ok(Some(requested));
    }
    if transfer_runtime.local_entry(&requested).await?.is_some() {
        let used_version = if opcode == OP_REQUESTSOURCES2 {
            requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION)
        } else {
            1
        };
        let sources = source_exchange_peers(transfer_runtime, &requested, peer_addr.ip()).await?;
        if source_exchange_entry_count(used_version, &sources) == 0 {
            return Ok(Some(requested));
        }
        let reply = if opcode == OP_REQUESTSOURCES2 {
            encode_answer_sources2(&requested, used_version, &sources)
        } else {
            encode_answer_sources(&requested, &sources)
        };
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send source exchange response to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

async fn answer_source_request_subpacket<'a>(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    requested: &Ed2kHash,
    opcode: u8,
    remaining: &'a [u8],
) -> Result<&'a [u8]> {
    let requested_version = if opcode == OP_REQUESTSOURCES2 {
        if remaining.len() < 3 {
            anyhow::bail!("short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET");
        }
        remaining[0]
    } else {
        1
    };
    let remaining = if opcode == OP_REQUESTSOURCES2 {
        &remaining[3..]
    } else {
        remaining
    };
    if requested_version == 0 {
        return Ok(remaining);
    }
    let used_version = if opcode == OP_REQUESTSOURCES2 {
        requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION)
    } else {
        1
    };
    let sources = source_exchange_peers(transfer_runtime, requested, peer_addr.ip()).await?;
    if source_exchange_entry_count(used_version, &sources) == 0 {
        return Ok(remaining);
    }
    let reply = if opcode == OP_REQUESTSOURCES2 {
        encode_answer_sources2(requested, used_version, &sources)
    } else {
        encode_answer_sources(requested, &sources)
    };
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "answer_sources", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send source exchange reply to {peer_addr}"))?;
    Ok(remaining)
}

/// Build the OP_ANSWERSOURCES(2) source list for a shared file, excluding the
/// requesting peer's own IP (master `CKnownFile::CreateSrcInfoPacket` skips
/// `forClient` so a requester is never offered itself as a source).
async fn source_exchange_peers(
    transfer_runtime: &Ed2kTransferRuntime,
    requested: &Ed2kHash,
    exclude_ip: IpAddr,
) -> Result<Vec<SourceExchangePeer>> {
    // The eD2k peer plane is IPv4-only; a non-IPv4 requester (never produced by
    // this stack) excludes nothing.
    let IpAddr::V4(exclude_ipv4) = exclude_ip else {
        return source_exchange_peers_excluding(transfer_runtime, requested, None).await;
    };
    source_exchange_peers_excluding(transfer_runtime, requested, Some(exclude_ipv4)).await
}

async fn source_exchange_peers_excluding(
    transfer_runtime: &Ed2kTransferRuntime,
    requested: &Ed2kHash,
    exclude_ipv4: Option<Ipv4Addr>,
) -> Result<Vec<SourceExchangePeer>> {
    let manifest = transfer_runtime.manifest(&requested.to_string()).await?;
    Ok(manifest
        .sources
        .iter()
        .filter_map(|source| {
            let parsed_ip = source.ip.parse::<Ipv4Addr>().ok()?;
            // Never echo the requester back to itself as a source.
            if exclude_ipv4 == Some(parsed_ip) {
                return None;
            }
            let ip = parsed_ip.octets();
            if source.tcp_port == 0 {
                return None;
            }
            let user_hash = source
                .user_hash
                .as_deref()
                .and_then(|hash| hex::decode(hash).ok())
                .and_then(|bytes| bytes.try_into().ok());
            Some(SourceExchangePeer {
                ip,
                tcp_port: source.tcp_port,
                server_ip: 0,
                server_port: 0,
                user_hash,
                connect_options: 0,
            })
        })
        .collect())
}

pub(in crate::ed2k_tcp) async fn handle_aich_file_hash_request(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
    peer_supports_aich: bool,
) -> Result<Option<Ed2kHash>> {
    let requested = decode_file_hash_payload(payload)?;
    if peer_supports_aich
        && let Some(shared) = transfer_runtime.local_entry(&requested).await?
        && let Some(aich_root) = shared_aich_root(&shared)
    {
        let reply = encode_aich_file_hash_answer(&requested, aich_root);
        dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "aich_file_hash_answer", &reply);
        transport
            .write_all(&reply)
            .await
            .with_context(|| format!("failed to send OP_AICHFILEHASHANS to {peer_addr}"))?;
    }
    Ok(Some(requested))
}

fn shared_aich_root(shared: &Ed2kSharedEntry) -> Option<[u8; 20]> {
    shared
        .aich_root
        .as_deref()
        .and_then(|root| hex::decode(root).ok())
        .and_then(|bytes| bytes.try_into().ok())
}

async fn send_nofile(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    requested: &Ed2kHash,
    phase: &'static str,
) -> Result<()> {
    let reply = encode_file_req_ans_nofil(requested);
    dump_ed2k_tcp_listener_send(peer_addr, transport.mode, phase, &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_FILEREQANSNOFIL to {peer_addr}"))
}
