use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::ed2k_server::Ed2kFoundSource;
use crate::ed2k_transfer::{Ed2kSourceHint, Ed2kTransferRuntime, new_transfer_job};

use super::super::{
    Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport, dump_ed2k_tcp_download_meta,
    dump_ed2k_tcp_download_send, encode_hello_request,
};
use super::session::{
    DownloadConnectionState, DownloadSessionOptions, Ed2kPeerDownloadOutcome,
    drive_download_session,
};
/// Executes a minimal outbound native ED2K download session against one peer.
///
/// A successful public-peer oracle capture showed a startup sequence that
/// public peers accept more readily than our earlier minimal flow:
///
/// `OP_HELLO -> OP_HELLOANSWER -> secure-ident -> OP_REQUESTFILENAME ->
/// OP_SETREQFILEID -> OP_HASHSETREQUEST2/ANSWER2 -> OP_STARTUPLOADREQ ->
/// OP_ACCEPTUPLOADREQ -> OP_REQUESTPARTS`
///
/// Public peers that the oracle downloaded from were closing on our earlier
/// startup sequence, so the downloader now follows the observed file-startup
/// shape instead of the more speculative minimal flow.
///
/// Some real peers still acknowledge upload intent before they return a
/// hashset. The downloader keeps the captured hashset-first path as the
/// default, but falls back to `OP_STARTUPLOADREQ` after a short stall so
/// queue-oriented peers are not discarded prematurely.
/// Inputs for one outbound native ED2K peer download attempt.
pub struct Ed2kPeerDownloadOptions<'a> {
    pub bind_ip: Ipv4Addr,
    pub peer: &'a Ed2kFoundSource,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Arc<Ed2kSecureIdent>,
    pub transfer_runtime: &'a Ed2kTransferRuntime,
    pub display_name: String,
    pub file_size: u64,
    pub current_source_count: usize,
    pub timeout: Duration,
    /// When set (UDP reask enabled), a queued + UDP-eligible source detaches onto
    /// UDP reask via this handle. `None` keeps the legacy TCP-only queued path.
    pub reask_register: Option<crate::ed2k_client_udp::ReaskSourceHandle>,
}

/// One additional wanted file served by the same peer. Full A4AF uses these
/// plans to switch the already-open TCP session after NNP, FNF, or completion,
/// instead of reconnecting merely to ask the same peer for another file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kPeerDownloadFile {
    pub file_hash: Ed2kHash,
    pub display_name: String,
    pub file_size: u64,
    pub current_source_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kPeerFileDownloadOutcome {
    pub file_hash: Ed2kHash,
    pub outcome: Ed2kPeerDownloadOutcome,
}

/// Outcomes produced by one physical peer connection. A full A4AF connection
/// may visit several files before it becomes queued, closes, or times out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kPeerDownloadReport {
    pub file_outcomes: Vec<Ed2kPeerFileDownloadOutcome>,
    /// A later-file error after at least one useful outcome. The earlier
    /// outcomes still need applying (NNP holds/FNF dead-listing), so it is
    /// carried instead of discarding the whole report as `Err`.
    pub terminal_error: Option<String>,
}

impl Ed2kPeerDownloadReport {
    #[must_use]
    pub fn single(file_hash: Ed2kHash, outcome: Ed2kPeerDownloadOutcome) -> Self {
        Self {
            file_outcomes: vec![Ed2kPeerFileDownloadOutcome { file_hash, outcome }],
            terminal_error: None,
        }
    }
}

pub async fn download_file_from_peer(
    options: Ed2kPeerDownloadOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let report = download_files_from_peer(options, Vec::new()).await?;
    report
        .file_outcomes
        .first()
        .map(|result| result.outcome)
        .ok_or_else(|| anyhow::anyhow!("ED2K peer download returned no file outcome"))
}

pub async fn download_files_from_peer(
    options: Ed2kPeerDownloadOptions<'_>,
    alternate_files: Vec<Ed2kPeerDownloadFile>,
) -> Result<Ed2kPeerDownloadReport> {
    let Ed2kPeerDownloadOptions {
        bind_ip,
        peer,
        hello_identity,
        secure_ident,
        transfer_runtime,
        display_name,
        file_size,
        current_source_count,
        timeout,
        reask_register,
    } = options;
    let first_file_hash = peer.file_hash;
    let first_file_hash_hex = first_file_hash.to_string();
    let mut files = Vec::with_capacity(alternate_files.len().saturating_add(1));
    files.push(Ed2kPeerDownloadFile {
        file_hash: first_file_hash,
        display_name,
        file_size,
        current_source_count,
    });
    files.extend(alternate_files);
    for file in &files {
        let file_hash_hex = file.file_hash.to_string();
        let job = new_transfer_job(file.file_hash, file.display_name.clone(), file.file_size);
        transfer_runtime.ensure_job(&job).await?;
        transfer_runtime
            .remember_source(
                &file_hash_hex,
                Ed2kSourceHint {
                    ip: peer.ip.to_string(),
                    tcp_port: peer.tcp_port,
                    user_hash: peer.user_hash.map(hex::encode),
                    connect_options: peer.obfuscation_options,
                    file_comment: String::new(),
                    file_rating: 0,
                },
            )
            .await?;
    }

    let peer_addr = SocketAddr::new(IpAddr::V4(peer.ip), peer.tcp_port);
    let crypt_options = peer
        .obfuscation_options
        .map(|options| format!("0x{options:02x}"))
        .unwrap_or_else(|| "none".to_string());
    dump_ed2k_tcp_download_meta(peer_addr, None, "connect_start", || {
        format!(
            "file_hash={first_file_hash_hex} file_size={file_size} client_id={} obfuscated={} crypt_options={} has_user_hash={}",
            peer.client_id,
            peer.obfuscated,
            crypt_options,
            peer.user_hash.is_some()
        )
    });
    async {
        let mut transport = Ed2kTransport::connect_outgoing(
            bind_ip,
            peer_addr,
            hello_identity.connect_options,
            peer.user_hash,
            peer.obfuscation_options,
            timeout,
        )
        .await?;
        dump_ed2k_tcp_download_meta(peer_addr, Some(transport.mode), "connect_ready", || {
            format!("file_hash={first_file_hash_hex}")
        });
        // The outbound TCP connect + hello handshake has completed, so the global
        // connection-budget slot acquired for this source transitions from
        // half-open to established (eMule `m_nHalfOpen` decrement on OnConnect),
        // freeing the half-open budget for the next pending source connect.
        transfer_runtime.mark_connection_established();
        let hello = encode_hello_request(hello_identity);
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello", &hello);
        transport
            .write_all(&hello)
            .await
            .with_context(|| format!("failed to send OP_HELLO to {peer_addr}"))?;
        let mut report = Ed2kPeerDownloadReport {
            file_outcomes: Vec::with_capacity(files.len()),
            terminal_error: None,
        };
        let mut connection_state = DownloadConnectionState::default();
        for (file_index, file) in files.into_iter().enumerate() {
            let file_hash_hex = file.file_hash.to_string();
            let source_exchange_allowed = transfer_runtime
                .should_request_source_exchange(
                    &file_hash_hex,
                    peer_addr,
                    peer.user_hash,
                    file.current_source_count,
                    std::time::Instant::now(),
                )
                .await;
            if file_index != 0 {
                dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport.mode),
                    "a4af_connection_swap",
                    || format!("file_hash={file_hash_hex}"),
                );
            }
            let session_result = drive_download_session(DownloadSessionOptions {
                transport: &mut transport,
                peer_addr,
                hello_identity,
                secure_ident: secure_ident.as_ref(),
                transfer_runtime,
                file_hash: file.file_hash,
                file_hash_hex: &file_hash_hex,
                timeout,
                send_initial_requests: true,
                source_exchange_allowed,
                initial_hello_complete: file_index != 0,
                initial_secure_ident_started: file_index != 0,
                peer_user_hash: peer.user_hash,
                peer_connect_options: peer.obfuscation_options,
                connection_state: Some(&mut connection_state),
                reask_register: reask_register.clone(),
            })
            .await;
            match &session_result {
                Ok(Ed2kPeerDownloadOutcome::Completed) => {
                    dump_ed2k_tcp_download_meta(peer_addr, Some(transport.mode), "complete", || {
                        format!("file_hash={file_hash_hex}")
                    })
                }
                Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport.mode),
                    "accepted_incomplete",
                    || format!("file_hash={file_hash_hex}"),
                ),
                Ok(Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask) => {
                    dump_ed2k_tcp_download_meta(
                        peer_addr,
                        Some(transport.mode),
                        "queued_detached_udp_reask",
                        || format!("file_hash={file_hash_hex}"),
                    )
                }
                Ok(Ed2kPeerDownloadOutcome::NoNeededParts) => dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport.mode),
                    "no_needed_parts",
                    || format!("file_hash={file_hash_hex}"),
                ),
                Ok(Ed2kPeerDownloadOutcome::FileNotFound) => dump_ed2k_tcp_download_meta(
                    peer_addr,
                    Some(transport.mode),
                    "file_not_found",
                    || format!("file_hash={file_hash_hex}"),
                ),
                Err(error) => {
                    dump_ed2k_tcp_download_meta(peer_addr, Some(transport.mode), "error", || {
                        format!("file_hash={file_hash_hex} error={error}")
                    })
                }
            }
            match session_result {
                Ok(outcome) => {
                    report.file_outcomes.push(Ed2kPeerFileDownloadOutcome {
                        file_hash: file.file_hash,
                        outcome,
                    });
                    if matches!(
                        outcome,
                        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
                            | Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask
                    ) {
                        break;
                    }
                }
                Err(error) if report.file_outcomes.is_empty() => return Err(error),
                Err(error) => {
                    report.terminal_error = Some(error.to_string());
                    break;
                }
            }
        }
        Ok(report)
    }
    .await
}
