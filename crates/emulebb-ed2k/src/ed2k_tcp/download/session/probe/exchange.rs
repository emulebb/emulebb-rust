//! Metadata-only exchange shared by outbound and accepted callback connections.
use super::*;
use crate::ed2k_tcp::{
    codec::FilenameRequestExtension,
    hello::{DecodedHelloProfile, ExtendedRequestNegotiation},
};

pub(super) struct ProbeExchangeOptions<'a> {
    pub peer_addr: SocketAddr,
    pub file_hash: Ed2kHash,
    pub file_size: u64,
    pub verified_parts: &'a [bool],
    pub job_token: Option<emulebb_metadata::JobToken>,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Ed2kSecureIdent,
    pub runtime: &'a Ed2kTransferRuntime,
    pub parts: usize,
}

pub(super) struct PreparedPeerMetadata {
    pub availability: Ed2kPeerAvailability,
    pub state: DownloadSessionState,
    pub metadata: std::collections::VecDeque<EmuleTcpPacket>,
    pub profile: DecodedHelloProfile,
}

pub(super) enum ProbeExchangeOutcome {
    Closed(Option<anyhow::Error>),
    FileNotFound(Box<DownloadConnectionState>),
    Available(Box<PreparedPeerMetadata>),
}

pub(super) async fn exchange_probe(
    transport: &mut Ed2kPeerDispatcher,
    options: ProbeExchangeOptions<'_>,
    mut state: DownloadSessionState,
    mut observed_profile: Option<DecodedHelloProfile>,
) -> Result<ProbeExchangeOutcome> {
    let peer_addr = options.peer_addr;
    let std::net::IpAddr::V4(peer_ip) = peer_addr.ip() else {
        anyhow::bail!("probe requires IPv4");
    };
    let runtime = options.runtime;
    let parts = options.parts;
    if let Some(profile) = observed_profile.as_ref() {
        anyhow::ensure!(
            state.hello_complete && state.peer_user_hash == Some(profile.identity.user_hash),
            "accepted probe differs from connection identity"
        );
        anyhow::ensure!(
            !runtime
                .ban_store()
                .is_banned(Some(peer_ip), Some(&profile.identity.user_hash)),
            "banned probe identity"
        );
    }
    let mut requested = false;
    let mut file_name = None;
    let mut metadata = std::collections::VecDeque::with_capacity(2);
    // WHY: metadata probes must retire even when a peer floods unrelated control
    // frames. Packet framing/decompression retain the transport's existing caps.
    for _ in 0..64 {
        if !requested && observed_profile.is_some() {
            request_metadata(transport, &options, &state).await?;
            requested = true;
        }
        let packet = match transport
            .read_packet_diagnostic("source_probe", peer_addr, "availability")
            .await
        {
            Ok(Some(packet)) => packet,
            Ok(None) => return Ok(ProbeExchangeOutcome::Closed(None)),
            Err(error) if is_connection_shutdown_error(&error) => {
                return Ok(ProbeExchangeOutcome::Closed(Some(error)));
            }
            Err(error) => return Err(error),
        };
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
                        .is_banned(Some(peer_ip), Some(&profile.identity.user_hash)),
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
                let mut extended_requests = state.extended_requests;
                if packet.opcode == OP_HELLOANSWER {
                    extended_requests.apply_hello_answer(&profile);
                } else {
                    extended_requests = ExtendedRequestNegotiation::from_hello(&profile);
                }
                state.hello_complete = true;
                let connection = DownloadConnectionState::from_inbound_hello(
                    &profile,
                    &state.peer_secure_ident,
                    state.secure_ident_started,
                );
                state = DownloadSessionState::new(
                    true,
                    state.secure_ident_started,
                    false,
                    Some(profile.identity.user_hash),
                    Some(profile.connect_options),
                    Some(&connection),
                );
                state.extended_requests = extended_requests;
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
                    state.secure_ident_started = true;
                }

                observed_profile = Some(profile);
            }
            (OP_EMULEPROT, OP_SECIDENTSTATE) => {
                secure_ident::handle_secident_state(
                    &mut *transport,
                    peer_addr,
                    options.secure_ident,
                    &mut state,
                    &packet.payload,
                )
                .await?
            }
            (OP_EMULEPROT, OP_PUBLICKEY) => {
                secure_ident::handle_public_key(
                    &mut *transport,
                    peer_addr,
                    options.secure_ident,
                    &mut state,
                    &packet.payload,
                )
                .await?
            }
            (OP_EMULEPROT, OP_SIGNATURE) => secure_ident::handle_signature(
                &*transport,
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
                    options.file_hash,
                    options.file_size,
                    parts,
                    state.remote_supports_unicode,
                    &mut file_name,
                )? {
                    ProbeReply::NotFound => {
                        return Ok(ProbeExchangeOutcome::FileNotFound(Box::new(
                            state.connection_state(),
                        )));
                    }
                    ProbeReply::Parts(available_parts) => {
                        metadata.push_back(packet);
                        return Ok(ProbeExchangeOutcome::Available(Box::new(
                            PreparedPeerMetadata {
                                availability: Ed2kPeerAvailability {
                                    peer: peer_addr,
                                    user_hash: state
                                        .peer_user_hash
                                        .context("missing probe identity")?,
                                    file_name,
                                    available_parts,
                                },
                                state,
                                metadata,
                                profile: observed_profile.context("missing probe profile")?,
                            },
                        )));
                    }
                    ProbeReply::Continue => {
                        if matches!(
                            (packet.protocol, packet.opcode),
                            (OP_EDONKEYPROT, OP_REQFILENAMEANSWER)
                                | (
                                    OP_EMULEPROT,
                                    OP_MULTIPACKETANSWER | OP_MULTIPACKETANSWER_EXT2
                                )
                        ) {
                            // Keep at most the last incomplete metadata answer
                            // before final status; never retain unrelated frames.
                            metadata.clear();
                            metadata.push_back(packet);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    anyhow::bail!("peer availability probe packet allowance exhausted")
}

async fn request_metadata(
    transport: &mut Ed2kPeerDispatcher,
    options: &ProbeExchangeOptions<'_>,
    state: &DownloadSessionState,
) -> Result<()> {
    let peer_addr = options.peer_addr;
    let verified = options.verified_parts.iter().copied();
    let hash = options.file_hash;
    let version = state.extended_requests.version;
    let extension = FilenameRequestExtension {
        version,
        complete_source_count: if version >= 2 {
            options.job_token.map_or(0, |token| {
                options
                    .runtime
                    .known_complete_source_count(token, options.parts)
            })
        } else {
            0
        },
    };
    let request = if state.remote_supports_file_identifiers {
        encode_multipacket_ext2_request(
            &Ed2kFileIdentifier {
                file_hash: hash,
                file_size: Some(options.file_size),
                aich_root: None,
            },
            options.file_size,
            extension,
            verified,
            PeerSourceExchangeRequest::None,
        )
    } else if state.remote_supports_multipacket {
        encode_multipacket_request(
            &hash,
            options.file_size,
            extension,
            verified,
            state.remote_supports_ext_multipacket,
            PeerSourceExchangeRequest::None,
            false,
        )
    } else {
        encode_request_filename(&hash, options.file_size, extension, verified)
    };
    transport
        .write_all_diagnostic("source_probe", peer_addr, "file_request", &request)
        .await?;
    if !state.remote_supports_file_identifiers
        && !state.remote_supports_multipacket
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

    Ok(())
}
