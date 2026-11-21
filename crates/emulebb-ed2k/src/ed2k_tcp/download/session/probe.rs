//! Short availability sessions share normal codecs, transport and secure ident.
mod accepted;
mod exchange;
use super::*;
use crate::ed2k_server::Ed2kFoundSource;
use crate::ed2k_tcp::{
    Ed2kPeerConnectionOrigin, Ed2kTransport, EmuleTcpPacket, PeerSourceExchangeRequest,
    encode_hello_request, encode_multipacket_ext2_request, encode_multipacket_request,
    encode_request_filename, encode_set_req_file_id,
};
use crate::ed2k_transfer::{
    ED2K_PART_SIZE, Ed2kPeerConnectionGuard, Ed2kSourceConnectionAdmission,
    Ed2kSourceConnectionPermit,
};
pub(in crate::ed2k_tcp) use accepted::{
    AcceptedFileProbeOptions, AcceptedFileProbeOutcome, probe_accepted_file,
};
use exchange::{ProbeExchangeOptions, ProbeExchangeOutcome, exchange_probe};

/// Inputs contain compact verified-part status, without execution/storage state.
pub struct Ed2kPeerProbeOptions<'request> {
    pub bind_ip: Ipv4Addr,
    pub egress_route: crate::networking::EgressRoute,
    pub peer: &'request Ed2kFoundSource,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: std::sync::Arc<Ed2kSecureIdent>,
    pub transfer_runtime: std::sync::Arc<Ed2kTransferRuntime>,
    pub file_size: u64,
    /// One bit per data part, or empty when no local part is verified.
    pub verified_parts: &'request [bool],
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

#[derive(Debug)]
pub enum Ed2kPeerProbeOutcome {
    /// No socket was opened because shared preparation/connection limits refused.
    Deferred,
    FileNotFound,
    Available(Box<Ed2kPreparedPeer>),
}

/// Linear connection ownership across preparation, admission and execution.
/// Dropping an unselected peer closes its socket before releasing its permits.
pub struct Ed2kPreparedPeer {
    dispatcher: Ed2kPeerDispatcher,
    state: Option<DownloadSessionState>,
    metadata: std::collections::VecDeque<EmuleTcpPacket>,
    availability: Ed2kPeerAvailability,
    profile: crate::ed2k_tcp::hello::DecodedHelloProfile,
    peer: Ed2kFoundSource,
    file_size: u64,
    runtime: std::sync::Arc<Ed2kTransferRuntime>,
    secure_ident: std::sync::Arc<Ed2kSecureIdent>,
    hello_identity: Ed2kHelloIdentity,
    preparation: Option<tokio::sync::OwnedSemaphorePermit>,
    _connection: Ed2kSourceConnectionPermit,
    _peer_connection: Ed2kPeerConnectionGuard,
}

impl std::fmt::Debug for Ed2kPreparedPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ed2kPreparedPeer")
            .field("peer", &self.availability.peer)
            .field("file_hash", &self.peer.file_hash)
            .field("parts", &self.availability.available_parts.len())
            .finish()
    }
}

/// Execution context is supplied only after Core admits and hydrates the job.
pub struct Ed2kPreparedDownloadOptions {
    pub job_token: emulebb_metadata::JobToken,
    pub timeout: Duration,
    pub current_source_count: usize,
    pub upload_context: Option<Ed2kPeerUploadContext>,
    pub established_context: Option<Ed2kEstablishedPeerContext>,
    pub reask_register: Option<crate::ed2k_client_udp::ReaskSourceHandle>,
}

impl Ed2kPreparedPeer {
    pub fn availability(&self) -> &Ed2kPeerAvailability {
        &self.availability
    }

    /// Persist this exact reply under the captured job's current authority.
    /// The immutable content match is checked before the owned delta's SQL fence.
    pub async fn remember_availability(&self, token: emulebb_metadata::JobToken) -> Result<()> {
        self.check_job(token).await?;
        self.runtime
            .remember_source_availability(
                token,
                Ed2kSourceHint {
                    ip: self.peer.ip.to_string(),
                    tcp_port: self.peer.tcp_port,
                    user_hash: Some(hex::encode(self.availability.user_hash)),
                    connect_options: Some(self.profile.connect_options),
                    file_comment: String::new(),
                    file_rating: 0,
                },
                self.file_size,
                self.availability.available_parts.clone(),
            )
            .await
    }

    async fn check_job(&self, token: emulebb_metadata::JobToken) -> Result<()> {
        let job = self
            .runtime
            .download_job(token.job_id)
            .await?
            .context("missing prepared job")?;
        anyhow::ensure!(
            job.token == token
                && job.file_hash == self.peer.file_hash.to_string()
                && job.expected_size_bytes == Some(self.file_size),
            "prepared peer differs from captured job"
        );
        Ok(())
    }

    /// Continue on the prepared socket. File metadata and HELLO are not resent;
    /// the normal session still owns hashsets, part selection, storage and SUI.
    pub async fn download(
        self: Box<Self>,
        options: Ed2kPreparedDownloadOptions,
    ) -> Result<Ed2kPeerDownloadOutcome> {
        let report = self.download_files(options, Vec::new()).await?;
        report
            .file_outcomes
            .first()
            .map(|result| result.outcome)
            .context("prepared peer download returned no file outcome")
    }

    /// Continue selected files on this one connection, retaining HELLO/security
    /// across A4AF transitions and reporting earlier outcomes if a later file fails.
    pub async fn download_files(
        mut self: Box<Self>,
        options: Ed2kPreparedDownloadOptions,
        alternate_files: Vec<super::super::startup::Ed2kPeerDownloadFile>,
    ) -> Result<super::super::startup::Ed2kPeerDownloadReport> {
        use super::super::startup::{
            ConnectedDownloadOptions, Ed2kPeerDownloadFile, drive_connected_download_files,
            prepare_peer_download_files,
        };
        let token = options.job_token;
        self.check_job(token).await?;
        let runtime = self.runtime.as_ref();
        let peer_addr = self.availability.peer;
        let hash = self.peer.file_hash;
        let hash_hex = hash.to_string();
        let manifest = runtime.manifest(token).await?;
        anyhow::ensure!(
            manifest.file_hash == hash_hex && manifest.file_size == self.file_size,
            "prepared connection differs from admitted execution"
        );
        let mut files = Vec::with_capacity(alternate_files.len().saturating_add(1));
        files.push(Ed2kPeerDownloadFile {
            job_token: token,
            file_hash: hash,
            display_name: manifest.display_name.clone(),
            file_size: self.file_size,
            current_source_count: options.current_source_count,
        });
        drop(manifest);
        files.extend(alternate_files);
        prepare_peer_download_files(
            runtime,
            &files,
            Ed2kSourceHint {
                ip: self.peer.ip.to_string(),
                tcp_port: self.peer.tcp_port,
                user_hash: Some(hex::encode(self.availability.user_hash)),
                connect_options: Some(self.profile.connect_options),
                file_comment: String::new(),
                file_rating: 0,
            },
        )
        .await?;
        drop(self.preparation.take());
        let mut state = self.state.take().expect("prepared state has one owner");
        state.startup_file_requests_sent = true;
        state.source_exchange_allowed = runtime
            .should_request_source_exchange(
                token,
                peer_addr,
                Some(self.availability.user_hash),
                options.current_source_count,
                std::time::Instant::now(),
            )
            .await;
        remember_connected_peer_source(
            runtime,
            token,
            peer_addr,
            self.availability.user_hash,
            self.profile.connect_options,
        )
        .await?;
        if let Some(software) = &self.profile.client_software {
            runtime.note_download_source_software(token, peer_addr, software.clone());
        }
        let mut upload_facet =
            PeerUploadFacet::new(peer_addr, self.dispatcher.mode.is_obfuscated());
        anyhow::ensure!(
            upload_facet
                .bind_hello(
                    runtime,
                    peer_addr,
                    self.dispatcher.mode.is_obfuscated(),
                    &self.profile
                )
                .await,
            "rejected prepared peer identity"
        );
        let connection_state = state.connection_state();
        let result = drive_connected_download_files(
            ConnectedDownloadOptions {
                dispatcher: &mut self.dispatcher,
                peer_addr,
                hello_identity: self.hello_identity,
                secure_ident: self.secure_ident.as_ref(),
                transfer_runtime: runtime,
                timeout: options.timeout,
                peer_user_hash: Some(self.availability.user_hash),
                peer_connect_options: Some(self.profile.connect_options),
                connection_state,
                prepared: Some(PreparedDownloadSession {
                    state,
                    metadata: std::mem::take(&mut self.metadata),
                }),
                established_context: options.established_context.as_ref(),
                upload_facet: &mut upload_facet,
                upload_context: options.upload_context.as_ref(),
                reask_register: options.reask_register,
            },
            files,
        )
        .await;
        upload_facet.release(runtime).await;
        result
    }
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
    tokio::time::timeout(
        options.timeout,
        run_probe(options, parts, _probe, _connection),
    )
    .await
    .context("peer availability probe timed out")?
}

async fn run_probe(
    options: Ed2kPeerProbeOptions<'_>,
    parts: usize,
    preparation: tokio::sync::OwnedSemaphorePermit,
    connection: Ed2kSourceConnectionPermit,
) -> Result<Ed2kPeerProbeOutcome> {
    let peer_addr = SocketAddr::from((options.peer.ip, options.peer.tcp_port));
    let runtime = options.transfer_runtime.as_ref();
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
    let state = DownloadSessionState::new(
        false,
        false,
        false,
        options.peer.user_hash,
        options.peer.obfuscation_options,
        None,
    );
    let observed = exchange_probe(
        &mut transport,
        ProbeExchangeOptions {
            peer_addr,
            file_hash: options.peer.file_hash,
            file_size: options.file_size,
            verified_parts: options.verified_parts,
            hello_identity: options.hello_identity,
            secure_ident: options.secure_ident.as_ref(),
            runtime,
            parts,
        },
        state,
        None,
    )
    .await?;
    Ok(match observed {
        ProbeExchangeOutcome::Closed(Some(error)) => return Err(error),
        ProbeExchangeOutcome::Closed(None) => anyhow::bail!("peer closed availability probe"),
        ProbeExchangeOutcome::FileNotFound(_) => Ed2kPeerProbeOutcome::FileNotFound,
        ProbeExchangeOutcome::Available(observed) => {
            Ed2kPeerProbeOutcome::Available(Box::new(Ed2kPreparedPeer {
                availability: observed.availability,
                dispatcher: transport,
                state: Some(observed.state),
                metadata: observed.metadata,
                profile: observed.profile,
                peer: options.peer.clone(),
                file_size: options.file_size,
                runtime: options.transfer_runtime,
                secure_ident: options.secure_ident,
                hello_identity: options.hello_identity,
                preparation: Some(preparation),
                _connection: connection,
                _peer_connection: _peer,
            }))
        }
    })
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
