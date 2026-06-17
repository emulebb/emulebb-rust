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
    encode_answer_sources2, encode_file_req_ans_nofil, encode_file_status,
    encode_hashset_answer, encode_hashset_answer2, encode_multipacket_answer,
    encode_file_desc, encode_multipacket_ext2_answer, encode_request_filename_answer,
    skip_request_filename_ext_info, source_exchange_entry_count,
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
                // SX2-only (REF-002 / sx1-live-source-exchange omission): a legacy
                // SX1 OP_REQUESTSOURCES sub-op carries no extra payload, so it is
                // consumed but never answered with OP_ANSWERSOURCES.
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

/// Whether to send an `OP_FILEDESC` (comment/rating) for a served file. Mirrors
/// the oracle `UploadClient.cpp:SendCommentInfo` gate: only when the peer
/// advertised comment acceptance (`m_byAcceptCommentVer >= 1`) AND the served
/// file has a non-empty rating OR comment. Pure so the gating is unit-testable.
#[must_use]
pub(in crate::ed2k_tcp) fn should_send_file_desc(
    peer_accept_comment_version: u8,
    rating: u8,
    comment: &str,
) -> bool {
    peer_accept_comment_version >= 1 && (rating != 0 || !comment.is_empty())
}

pub(in crate::ed2k_tcp) async fn handle_request_filename(
    transfer_runtime: &Ed2kTransferRuntime,
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
    peer_accept_comment_version: u8,
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
    // Propagate the user-set comment/rating right after the filename answer, like
    // the oracle (ListenSocket.cpp OP_REQUESTFILENAME -> SendCommentInfo). Only
    // for a file we actually serve, when the peer accepts comments and we have a
    // non-empty rating/comment to send.
    if let Ok(manifest) = transfer_runtime.manifest(&requested.to_string()).await {
        if should_send_file_desc(peer_accept_comment_version, manifest.rating, &manifest.comment) {
            let desc = encode_file_desc(manifest.rating, &manifest.comment);
            dump_ed2k_tcp_listener_send(peer_addr, transport.mode, "file_desc", &desc);
            transport
                .write_all(&desc)
                .await
                .with_context(|| format!("failed to send OP_FILEDESC to {peer_addr}"))?;
        }
    }
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
    // Source exchange is SX2-only (REF-002 / the sx1-live-source-exchange
    // omission): we serve OP_REQUESTSOURCES2 -> OP_ANSWERSOURCES2 only. A legacy
    // SX1 OP_REQUESTSOURCES is decoded (for the diagnostic dump) but never
    // answered with OP_ANSWERSOURCES.
    if opcode != OP_REQUESTSOURCES2 {
        return Ok(Some(requested));
    }
    if requested_version == 0 {
        return Ok(Some(requested));
    }
    if transfer_runtime.local_entry(&requested).await?.is_some() {
        let used_version = requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION);
        let sources = source_exchange_peers(transfer_runtime, &requested, peer_addr.ip()).await?;
        if source_exchange_entry_count(used_version, &sources) == 0 {
            return Ok(Some(requested));
        }
        let reply = encode_answer_sources2(&requested, used_version, &sources);
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
    // Source exchange is SX2-only (REF-002 / the sx1-live-source-exchange
    // omission): inside a multipacket we answer the OP_REQUESTSOURCES2 sub-op only.
    // A legacy SX1 OP_REQUESTSOURCES sub-op (which carries no extra payload) is
    // consumed but never answered with OP_ANSWERSOURCES.
    if opcode != OP_REQUESTSOURCES2 {
        return Ok(remaining);
    }
    if remaining.len() < 3 {
        anyhow::bail!("short OP_REQUESTSOURCES2 sub-payload in OP_MULTIPACKET");
    }
    let requested_version = remaining[0];
    let remaining = &remaining[3..];
    if requested_version == 0 {
        return Ok(remaining);
    }
    let used_version = requested_version.min(ED2K_SOURCE_EXCHANGE2_VERSION);
    let sources = source_exchange_peers(transfer_runtime, requested, peer_addr.ip()).await?;
    if source_exchange_entry_count(used_version, &sources) == 0 {
        return Ok(remaining);
    }
    let reply = encode_answer_sources2(requested, used_version, &sources);
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

/// Max sources advertised in one OP_ANSWERSOURCES(2) reply (eMule
/// `CreateSrcInfoPacket` caps at `nCount > 500`, i.e. it emits up to 501).
const MAX_SOURCE_EXCHANGE_ENTRIES: usize = 501;

/// eMule LowID test for a source whose advertised IPv4 we treat as its client-id
/// (`CUpDownClient::HasLowID`: `GetUserIDHybrid() < 16777216`). A LowID source is
/// firewalled and not directly dialable, so it must never be offered as a source
/// in a source-exchange reply (oracle `CreateSrcInfoPacket` skips `HasLowID()`).
fn source_ip_is_low_id(ip: Ipv4Addr) -> bool {
    // eMule encodes the client-id from the IP as little-endian octets, so a LowID
    // (`GetUserIDHybrid() < 16777216`) is equivalently an IP whose final octet is
    // zero. The unspecified address is never a valid direct-dial source.
    let client_id = u32::from_le_bytes(ip.octets());
    client_id < 0x0100_0000 || ip.is_unspecified()
}

/// `true` when a source is eligible to be offered in a source-exchange reply:
/// direct-dialable (non-LowID, non-zero TCP port) and not the requester itself.
fn source_exchange_eligible(
    ip: Ipv4Addr,
    tcp_port: u16,
    exclude_ipv4: Option<Ipv4Addr>,
) -> bool {
    // Never echo the requester back to itself as a source.
    tcp_port != 0 && exclude_ipv4 != Some(ip) && !source_ip_is_low_id(ip)
}

async fn source_exchange_peers_excluding(
    transfer_runtime: &Ed2kTransferRuntime,
    requested: &Ed2kHash,
    exclude_ipv4: Option<Ipv4Addr>,
) -> Result<Vec<SourceExchangePeer>> {
    let requested_hex = requested.to_string();
    let mut peers: Vec<SourceExchangePeer> = Vec::new();
    let mut seen: std::collections::HashSet<(Ipv4Addr, u16)> = std::collections::HashSet::new();

    // Prefer live download sources (currently connected, verified direct-dial
    // peers) over stale persisted manifest hints — these are the sources eMule
    // would actually offer (`IsLiveSource`). They are deduped by (ip, port).
    for live in transfer_runtime.live_download_sources(&requested_hex) {
        let IpAddr::V4(ipv4) = live.endpoint.ip() else {
            continue;
        };
        let tcp_port = live.endpoint.port();
        if !source_exchange_eligible(ipv4, tcp_port, exclude_ipv4) {
            continue;
        }
        if !seen.insert((ipv4, tcp_port)) {
            continue;
        }
        peers.push(SourceExchangePeer {
            ip: ipv4.octets(),
            tcp_port,
            server_ip: 0,
            server_port: 0,
            user_hash: live.user_hash,
            connect_options: 0,
        });
        if peers.len() >= MAX_SOURCE_EXCHANGE_ENTRIES {
            return Ok(peers);
        }
    }

    // Fill the remainder from persisted manifest hints, applying the same
    // non-LowID / non-zero-port eligibility filter and (ip, port) dedup.
    let manifest = transfer_runtime.manifest(&requested_hex).await?;
    for source in &manifest.sources {
        let Ok(parsed_ip) = source.ip.parse::<Ipv4Addr>() else {
            continue;
        };
        if !source_exchange_eligible(parsed_ip, source.tcp_port, exclude_ipv4) {
            continue;
        }
        if !seen.insert((parsed_ip, source.tcp_port)) {
            continue;
        }
        let user_hash = source
            .user_hash
            .as_deref()
            .and_then(|hash| hex::decode(hash).ok())
            .and_then(|bytes| bytes.try_into().ok());
        peers.push(SourceExchangePeer {
            ip: parsed_ip.octets(),
            tcp_port: source.tcp_port,
            server_ip: 0,
            server_port: 0,
            user_hash,
            connect_options: 0,
        });
        if peers.len() >= MAX_SOURCE_EXCHANGE_ENTRIES {
            break;
        }
    }

    Ok(peers)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_id_sources_are_filtered() {
        // LowID: eMule GetUserIDHybrid() < 0x01000000, i.e. final octet zero.
        assert!(source_ip_is_low_id(Ipv4Addr::new(5, 0, 0, 0)));
        assert!(source_ip_is_low_id(Ipv4Addr::new(200, 1, 2, 0)));
        assert!(source_ip_is_low_id(Ipv4Addr::UNSPECIFIED));
        // A normal HighID source (non-zero final octet) is eligible — including
        // LAN sources used by the test harness as stand-ins for real peers.
        assert!(!source_ip_is_low_id(Ipv4Addr::new(45, 82, 80, 155)));
        assert!(!source_ip_is_low_id(Ipv4Addr::new(10, 20, 30, 41)));
    }

    #[test]
    fn eligibility_requires_port_non_self_and_highid() {
        let public = Ipv4Addr::new(45, 82, 80, 155);
        // Eligible: public IP, real port, not the requester.
        assert!(source_exchange_eligible(public, 4662, None));
        assert!(source_exchange_eligible(public, 4662, Some(Ipv4Addr::new(1, 2, 3, 4))));
        // Zero port is never dialable.
        assert!(!source_exchange_eligible(public, 0, None));
        // Never echo the requester back to itself.
        assert!(!source_exchange_eligible(public, 4662, Some(public)));
        // LowID source is excluded even with a non-zero port.
        assert!(!source_exchange_eligible(Ipv4Addr::new(7, 0, 0, 0), 4662, None));
    }

    #[test]
    fn source_exchange_cap_matches_oracle() {
        // eMule caps at nCount > 500, i.e. up to 501 entries per reply.
        assert_eq!(MAX_SOURCE_EXCHANGE_ENTRIES, 501);
    }

    #[test]
    fn file_desc_send_gate_matches_oracle() {
        // Oracle SendCommentInfo gate: only when the peer accepts comments
        // (m_byAcceptCommentVer >= 1) AND there is a non-empty rating OR comment.
        assert!(should_send_file_desc(1, 3, "great file"));
        assert!(should_send_file_desc(1, 0, "comment only"));
        assert!(should_send_file_desc(2, 4, ""));
        // Peer does not accept comments -> never send.
        assert!(!should_send_file_desc(0, 5, "rated"));
        // Nothing to share (no rating, no comment) -> never send.
        assert!(!should_send_file_desc(1, 0, ""));
    }

    #[test]
    fn file_desc_encodes_oracle_layout_and_round_trips() {
        use super::super::super::super::codec::decode_file_description_payload;
        let frame = encode_file_desc(3, "nice");
        // Full eD2k frame: [OP_EMULEPROT][len u32 LE][OP_FILEDESC=0x61][body].
        assert_eq!(frame[0], 0xC5); // OP_EMULEPROT
        assert_eq!(frame[5], 0x61); // OP_FILEDESC
        let declared = u32::from_le_bytes(frame[1..5].try_into().unwrap()) as usize;
        let body = &frame[6..];
        assert_eq!(declared, body.len() + 1, "len counts opcode + body");
        // Body: [rating u8][u32 LE len][UTF-8 comment].
        assert_eq!(body[0], 3);
        assert_eq!(u32::from_le_bytes(body[1..5].try_into().unwrap()), 4);
        assert_eq!(&body[5..9], b"nice");
        let decoded = decode_file_description_payload(body).unwrap();
        assert_eq!(decoded.rating, 3);
        assert_eq!(decoded.comment, "nice");
    }
}
