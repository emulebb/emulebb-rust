//! Short availability sessions share normal codecs, transport and secure ident.
use super::*;
use crate::ed2k_server::Ed2kFoundSource;
use crate::ed2k_tcp::{
    Ed2kPeerConnectionOrigin, Ed2kTransport, EmuleTcpPacket, PeerSourceExchangeRequest,
    encode_hello_request, encode_multipacket_ext2_request, encode_multipacket_request,
    encode_request_filename, encode_set_req_file_id,
};
use crate::ed2k_transfer::{ED2K_PART_SIZE, Ed2kSourceConnectionAdmission};

/// Inputs contain compact verified-part status, without execution/storage state.
pub struct Ed2kPeerProbeOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub egress_route: crate::networking::EgressRoute,
    pub peer: &'a Ed2kFoundSource,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Ed2kSecureIdent,
    pub transfer_runtime: &'a Ed2kTransferRuntime,
    pub file_size: u64,
    /// One bit per data part, or empty when no local part is verified.
    pub verified_parts: &'a [bool],
    /// Deadline covers connection, hello, security and metadata together.
    pub timeout: Duration,
}

/// Status attributed to the peer's actual decoded HELLO identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kPeerAvailability {
    pub peer: SocketAddr,
    pub user_hash: [u8; 16],
    pub file_name: Option<String>,
    /// Data parts only; the protocol EOF slice is excluded.
    pub available_parts: Vec<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kPeerProbeOutcome {
    /// No socket was opened because shared preparation/connection limits refused.
    Deferred,
    FileNotFound,
    Available(Ed2kPeerAvailability),
}

/// Obtain validated availability without entering the upload queue, requesting
/// hashsets/payload, beginning a job generation or opening its temporary store.
/// Cancellation drops the owned socket and both admission permits synchronously.
pub async fn probe_file_from_peer(
    options: Ed2kPeerProbeOptions<'_>,
) -> Result<Ed2kPeerProbeOutcome> {
    let parts = usize::try_from(options.file_size.div_ceil(ED2K_PART_SIZE))?;
    anyhow::ensure!(
        options.file_size > 0 && parts < usize::from(u16::MAX),
        "invalid probe geometry"
    );
    anyhow::ensure!(
        options.verified_parts.is_empty() || options.verified_parts.len() == parts,
        "invalid probe part status"
    );
    anyhow::ensure!(
        options.peer.is_direct_dialable(),
        "probe requires a directly dialable source"
    );
    let Some(_probe) = options.transfer_runtime.try_admit_source_probe() else {
        return Ok(Ed2kPeerProbeOutcome::Deferred);
    };
    let _connection = match options.transfer_runtime.try_admit_source_connection() {
        Ed2kSourceConnectionAdmission::Admitted { permit, .. } => permit,
        Ed2kSourceConnectionAdmission::Denied { .. } => return Ok(Ed2kPeerProbeOutcome::Deferred),
    };
    tokio::time::timeout(options.timeout, run_probe(&options, parts))
        .await
        .context("peer availability probe timed out")?
}

async fn run_probe(
    options: &Ed2kPeerProbeOptions<'_>,
    parts: usize,
) -> Result<Ed2kPeerProbeOutcome> {
    let peer_addr = SocketAddr::from((options.peer.ip, options.peer.tcp_port));
    let runtime = options.transfer_runtime;
    anyhow::ensure!(
        !runtime
            .ban_store()
            .is_banned(Some(options.peer.ip), options.peer.user_hash.as_ref()),
        "banned probe source"
    );
    let transport = Ed2kTransport::connect_outgoing(
        "source_probe",
        crate::networking::EgressBinding::new(options.bind_ip, options.egress_route),
        peer_addr,
        options.hello_identity.connect_options,
        options.peer.user_hash,
        options.peer.obfuscation_options,
        options.timeout,
    )
    .await?;
    let mut transport = Ed2kPeerDispatcher::new(
        transport,
        peer_addr,
        Ed2kPeerConnectionOrigin::OutboundEstablished,
    );
    let _peer = runtime.register_peer_connection(peer_addr.ip());
    runtime.mark_connection_established();
    transport
        .write_all_diagnostic(
            "source_probe",
            peer_addr,
            "hello",
            &encode_hello_request(options.hello_identity),
        )
        .await?;
    let mut state = DownloadSessionState::new(
        false,
        false,
        false,
        options.peer.user_hash,
        options.peer.obfuscation_options,
        None,
    );
    let mut requested = false;
    let mut file_name = None;
    // WHY: metadata probes must retire even when a peer floods unrelated control
    // frames. Packet framing/decompression retain the transport's existing caps.
    for _ in 0..64 {
        let packet = transport
            .read_packet_diagnostic("source_probe", peer_addr, "availability")
            .await?
            .context("peer closed availability probe")?;
        match (packet.protocol, packet.opcode) {
            (OP_EDONKEYPROT, OP_HELLO | OP_HELLOANSWER) => {
                let profile = if packet.opcode == OP_HELLO {
                    decode_hello_profile(&packet.payload)?
                } else {
                    decode_hello_answer_profile(&packet.payload)?
                };
                anyhow::ensure!(
                    !runtime
                        .ban_store()
                        .is_banned(Some(options.peer.ip), Some(&profile.identity.user_hash)),
                    "banned probe identity"
                );
                anyhow::ensure!(
                    !state.hello_complete
                        || state.peer_user_hash == Some(profile.identity.user_hash),
                    "probe peer changed identity"
                );
                if packet.opcode == OP_HELLO {
                    for reply in build_hello_responses(&packet.payload, options.hello_identity)? {
                        transport
                            .write_all_diagnostic("source_probe", peer_addr, "hello_reply", &reply)
                            .await?;
                    }
                }
                state.peer_user_hash = Some(profile.identity.user_hash);
                state.peer_secure_ident.peer_sec_ident = profile.misc_options1.secure_ident;
                state.remote_supports_unicode = profile.misc_options1.unicode_support;
                state.hello_complete = true;
                if profile.supports_secure_ident && !state.peer_secure_ident.requested_peer_key {
                    let challenge = begin_secure_ident_probe(&mut state.peer_secure_ident);
                    transport
                        .write_all_diagnostic(
                            "source_probe",
                            peer_addr,
                            "secure_ident_probe",
                            &challenge,
                        )
                        .await?;
                }
                if !requested {
                    let verified = options.verified_parts.iter().copied();
                    let hash = options.peer.file_hash;
                    let request = if profile.supports_file_identifiers {
                        encode_multipacket_ext2_request(
                            &Ed2kFileIdentifier {
                                file_hash: hash,
                                file_size: Some(options.file_size),
                                aich_root: None,
                            },
                            options.file_size,
                            verified,
                            PeerSourceExchangeRequest::None,
                        )
                    } else if profile.supports_multipacket {
                        encode_multipacket_request(
                            &hash,
                            options.file_size,
                            verified,
                            profile.supports_ext_multipacket,
                            PeerSourceExchangeRequest::None,
                            false,
                        )
                    } else {
                        encode_request_filename(&hash, options.file_size, verified)
                    };
                    transport
                        .write_all_diagnostic("source_probe", peer_addr, "file_request", &request)
                        .await?;
                    if !profile.supports_file_identifiers
                        && !profile.supports_multipacket
                        && options.file_size > ED2K_PART_SIZE
                    {
                        transport
                            .write_all_diagnostic(
                                "source_probe",
                                peer_addr,
                                "file_status_request",
                                &encode_set_req_file_id(&hash),
                            )
                            .await?;
                    }
                    requested = true;
                }
            }
            (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                secure_ident::handle_secident_state(
                    &mut transport,
                    peer_addr,
                    options.secure_ident,
                    &mut state,
                    &packet.payload,
                )
                .await?
            }
            (OP_EMULEPROT, OP_PUBLICKEY) => {
                secure_ident::handle_public_key(
                    &mut transport,
                    peer_addr,
                    options.secure_ident,
                    &mut state,
                    &packet.payload,
                )
                .await?
            }
            (OP_EMULEPROT, OP_SIGNATURE) => secure_ident::handle_signature(
                &transport,
                peer_addr,
                options.secure_ident,
                &mut state,
                runtime,
                &packet.payload,
            ),
            (OP_EMULEPROT, OP_EMULEINFO | OP_EMULEINFOANSWER) => {
                apply_emule_info_profile(&mut state, decode_emule_info_profile(&packet.payload)?);
                if packet.opcode == OP_EMULEINFO {
                    transport
                        .write_all_diagnostic(
                            "source_probe",
                            peer_addr,
                            "emule_info_answer",
                            &encode_emule_info_answer(options.hello_identity.udp_port),
                        )
                        .await?;
                }
            }
            _ if requested => {
                match decode_probe_reply(
                    &packet,
                    options.peer.file_hash,
                    options.file_size,
                    parts,
                    state.remote_supports_unicode,
                    &mut file_name,
                )? {
                    ProbeReply::NotFound => return Ok(Ed2kPeerProbeOutcome::FileNotFound),
                    ProbeReply::Parts(available_parts) => {
                        return Ok(Ed2kPeerProbeOutcome::Available(Ed2kPeerAvailability {
                            peer: peer_addr,
                            user_hash: state.peer_user_hash.context("missing probe identity")?,
                            file_name,
                            available_parts,
                        }));
                    }
                    ProbeReply::Continue => {}
                }
            }
            _ => {}
        }
    }
    anyhow::bail!("peer availability probe packet allowance exhausted")
}

#[derive(Debug, PartialEq, Eq)]
enum ProbeReply {
    Continue,
    NotFound,
    Parts(Vec<bool>),
}

fn decode_probe_reply(
    packet: &EmuleTcpPacket,
    hash: Ed2kHash,
    size: u64,
    parts: usize,
    unicode: bool,
    name: &mut Option<String>,
) -> Result<ProbeReply> {
    let encoding = Ed2kStringEncoding::from_unicode_support(unicode);
    let mut bitmap = None;
    match (packet.protocol, packet.opcode) {
        (OP_EDONKEYPROT, OP_FILEREQANSNOFIL) => {
            anyhow::ensure!(
                decode_exact_file_hash_payload(&packet.payload, "probe file-not-found")? == hash,
                "probe file-not-found hash mismatch"
            );
            return Ok(ProbeReply::NotFound);
        }
        (OP_EDONKEYPROT, OP_REQFILENAMEANSWER) => {
            let (returned, value) = decode_request_filename_answer(&packet.payload, encoding)?;
            anyhow::ensure!(returned == hash, "probe filename hash mismatch");
            *name = Some(value);
        }
        (OP_EDONKEYPROT, OP_FILESTATUS) => {
            let (returned, availability) = decode_file_status_availability(&packet.payload)?;
            anyhow::ensure!(returned == hash, "probe status hash mismatch");
            bitmap = Some(availability);
        }
        (OP_EMULEPROT, OP_MULTIPACKETANSWER | OP_MULTIPACKETANSWER_EXT2) => {
            let mut remaining = packet.payload.as_slice();
            let returned = if packet.opcode == OP_MULTIPACKETANSWER_EXT2 {
                let (identifier, rest) = Ed2kFileIdentifier::decode(remaining)?;
                remaining = rest;
                anyhow::ensure!(
                    identifier.file_size.is_none_or(|value| value == size),
                    "probe size mismatch"
                );
                identifier.file_hash
            } else {
                let value = Ed2kHash::from_bytes(
                    remaining
                        .get(..16)
                        .context("short probe multipacket hash")?
                        .try_into()?,
                );
                remaining = &remaining[16..];
                value
            };
            anyhow::ensure!(returned == hash, "probe multipacket hash mismatch");
            while let Some((&opcode, rest)) = remaining.split_first() {
                remaining = rest;
                match opcode {
                    OP_REQFILENAMEANSWER => {
                        let (value, rest) =
                            decode_request_filename_answer_body(remaining, encoding)?;
                        *name = Some(value);
                        remaining = rest;
                    }
                    OP_FILESTATUS => {
                        let (value, rest) = decode_file_status_body_availability(remaining)?;
                        bitmap = Some(value);
                        remaining = rest;
                    }
                    _ => anyhow::bail!("unexpected probe multipacket sub-opcode"),
                }
            }
        }
        _ => return Ok(ProbeReply::Continue),
    }
    if let Some(mut bitmap) = bitmap {
        validate_file_status_part_count(u16::try_from(bitmap.len())?, size)?;
        if bitmap.is_empty() {
            bitmap.resize(parts, true);
        } else {
            bitmap.truncate(parts);
        }
        return Ok(ProbeReply::Parts(bitmap));
    }
    Ok(if name.is_some() && parts == 1 {
        ProbeReply::Parts(vec![true])
    } else {
        ProbeReply::Continue
    })
}

#[cfg(test)]
mod tests;
