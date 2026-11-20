//! One file-switch loop for ordinary and prepared physical connections.
use super::super::session::PreparedDownloadSession;
use super::*;

pub(in crate::ed2k_tcp) struct ConnectedDownloadOptions<'a> {
    pub dispatcher: &'a mut Ed2kPeerDispatcher,
    pub peer_addr: SocketAddr,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Ed2kSecureIdent,
    pub transfer_runtime: &'a Ed2kTransferRuntime,
    pub timeout: Duration,
    pub peer_user_hash: Option<[u8; 16]>,
    pub peer_connect_options: Option<u8>,
    pub connection_state: DownloadConnectionState,
    pub prepared: Option<PreparedDownloadSession>,
    pub upload_facet: &'a mut PeerUploadFacet,
    pub upload_context: Option<&'a Ed2kPeerUploadContext>,
    pub established_context: Option<&'a Ed2kEstablishedPeerContext>,
    pub reask_register: Option<crate::ed2k_client_udp::ReaskSourceHandle>,
}

pub(in crate::ed2k_tcp) async fn prepare_peer_download_files(
    runtime: &Ed2kTransferRuntime,
    files: &[Ed2kPeerDownloadFile],
    source: Ed2kSourceHint,
) -> Result<()> {
    for file in files {
        let job = new_transfer_job(
            file.job_token,
            file.file_hash,
            file.display_name.clone(),
            file.file_size,
        );
        runtime.ensure_job(&job).await?;
        runtime
            .remember_source(file.job_token, source.clone())
            .await?;
    }
    Ok(())
}

pub(in crate::ed2k_tcp) async fn drive_connected_download_files(
    options: ConnectedDownloadOptions<'_>,
    files: Vec<Ed2kPeerDownloadFile>,
) -> Result<Ed2kPeerDownloadReport> {
    let ConnectedDownloadOptions {
        dispatcher: transport,
        peer_addr,
        hello_identity,
        secure_ident,
        transfer_runtime,
        timeout,
        peer_user_hash,
        peer_connect_options,
        mut connection_state,
        mut prepared,
        upload_facet,
        upload_context,
        established_context,
        reask_register,
    } = options;
    let initially_prepared = prepared.is_some();
    let mut report = Ed2kPeerDownloadReport {
        file_outcomes: Vec::with_capacity(files.len()),
        terminal_error: None,
    };
    for (file_index, file) in files.into_iter().enumerate() {
        let file_hash_hex = file.file_hash.to_string();
        let source_exchange_allowed = if let Some(prepared) = prepared.as_ref() {
            prepared.source_exchange_allowed()
        } else {
            transfer_runtime
                .should_request_source_exchange(
                    file.job_token,
                    peer_addr,
                    peer_user_hash,
                    file.current_source_count,
                    std::time::Instant::now(),
                )
                .await
        };
        if file_index != 0 {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "a4af_connection_swap",
                || format!("file_hash={file_hash_hex}"),
            );
        }
        let session_result = drive_download_session(DownloadSessionOptions {
            job_token: file.job_token,
            dispatcher: &mut *transport,
            peer_addr,
            hello_identity,
            secure_ident,
            transfer_runtime,
            file_hash: file.file_hash,
            file_hash_hex: &file_hash_hex,
            timeout,
            send_initial_requests: true,
            source_exchange_allowed,
            initial_hello_complete: initially_prepared || file_index != 0,
            initial_secure_ident_started: initially_prepared || file_index != 0,
            peer_user_hash,
            peer_connect_options,
            connection_state: Some(&mut connection_state),
            prepared_state: prepared.take(),
            established_context,
            upload_facet: Some(&mut *upload_facet),
            upload_context,
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
            Ok(Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "queued_detached_udp_reask",
                || format!("file_hash={file_hash_hex}"),
            ),
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
                    observed_peer: connection_state
                        .observed_peer_hash()
                        .map(|hash| (peer_addr, hash)),
                    job_token: file.job_token,
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
            Err(error) if report.file_outcomes.is_empty() => {
                return Err(error);
            }
            Err(error) => {
                report.terminal_error = Some(error.to_string());
                break;
            }
        }
    }
    Ok(report)
}
