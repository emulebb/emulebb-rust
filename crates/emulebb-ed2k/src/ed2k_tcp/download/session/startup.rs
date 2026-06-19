use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use emulebb_kad_proto::Ed2kHash;

use crate::{
    ed2k_tcp::{
        Ed2kFileIdentifier, Ed2kHashsetRequestOptions, Ed2kSecureIdent, Ed2kTransport,
        PeerSourceExchangeRequest, begin_secure_ident_probe, dump_ed2k_tcp_download_meta,
        dump_ed2k_tcp_download_send, encode_aich_file_hash_request, encode_hashset_request,
        encode_hashset_request2, encode_multipacket_ext2_request, encode_multipacket_request,
        encode_request_filename, encode_request_sources2, encode_set_req_file_id,
        encode_start_upload_req,
    },
    ed2k_transfer::{ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime},
};

use super::state::DownloadSessionState;

pub(super) const HASHSET_STALL_UPLOAD_FALLBACK: Duration = Duration::from_millis(500);

pub(super) struct DownloadStartupStep<'a> {
    pub(super) transport: &'a mut Ed2kTransport,
    pub(super) peer_addr: SocketAddr,
    pub(super) secure_ident: &'a Ed2kSecureIdent,
    pub(super) transfer_runtime: &'a Ed2kTransferRuntime,
    pub(super) file_hash: &'a Ed2kHash,
    pub(super) file_hash_hex: &'a str,
    pub(super) send_initial_requests: bool,
    pub(super) manifest: &'a mut Ed2kResumeManifest,
    pub(super) request_file_identifier: &'a Ed2kFileIdentifier,
    pub(super) session_state: &'a mut DownloadSessionState,
}

pub(super) async fn advance_download_startup(step: DownloadStartupStep<'_>) -> Result<()> {
    let DownloadStartupStep {
        transport,
        peer_addr,
        secure_ident: _secure_ident,
        transfer_runtime,
        file_hash,
        file_hash_hex,
        send_initial_requests,
        manifest,
        request_file_identifier,
        session_state,
    } = step;
    if send_initial_requests
        && session_state.hello_complete
        && !session_state.secure_ident_started
        && session_state.remote_supports_secure_ident
    {
        let secure_ident_probe = begin_secure_ident_probe(&mut session_state.peer_secure_ident);
        dump_ed2k_tcp_download_send(
            peer_addr,
            transport.mode,
            "secure_ident_probe",
            &secure_ident_probe,
        );
        transport
            .write_all(&secure_ident_probe)
            .await
            .with_context(|| format!("failed to send OP_SECIDENTSTATE to {peer_addr}"))?;
        session_state.secure_ident_started = true;
    }

    if send_initial_requests
        && session_state.hello_complete
        && !session_state.startup_file_requests_sent
    {
        if session_state.remote_supports_file_identifiers {
            let source_exchange_request = source_exchange_request_for_peer(session_state);
            let multipacket_ext2 = encode_multipacket_ext2_request(
                request_file_identifier,
                manifest,
                source_exchange_request,
            );
            dump_ed2k_tcp_download_send(
                peer_addr,
                transport.mode,
                "multipacket_ext2_request",
                &multipacket_ext2,
            );
            transport
                .write_all(&multipacket_ext2)
                .await
                .with_context(|| format!("failed to send OP_MULTIPACKET_EXT2 to {peer_addr}"))?;
            session_state.source_request_sent =
                source_exchange_request != PeerSourceExchangeRequest::None;
            session_state.aich_file_hash_requested = true;
        } else if session_state.remote_supports_multipacket {
            let source_exchange_request = source_exchange_request_for_peer(session_state);
            let request_aich = session_state.remote_supports_aich;
            let multipacket = encode_multipacket_request(
                file_hash,
                manifest,
                session_state.remote_supports_ext_multipacket,
                source_exchange_request,
                request_aich,
            );
            let label = if session_state.remote_supports_ext_multipacket {
                "multipacket_ext_request"
            } else {
                "multipacket_request"
            };
            dump_ed2k_tcp_download_send(peer_addr, transport.mode, label, &multipacket);
            transport
                .write_all(&multipacket)
                .await
                .with_context(|| format!("failed to send legacy multipacket to {peer_addr}"))?;
            session_state.source_request_sent =
                source_exchange_request != PeerSourceExchangeRequest::None;
            session_state.aich_file_hash_requested = request_aich;
        } else {
            let request_filename = encode_request_filename(file_hash, manifest);
            dump_ed2k_tcp_download_send(
                peer_addr,
                transport.mode,
                "request_filename",
                &request_filename,
            );
            transport
                .write_all(&request_filename)
                .await
                .with_context(|| format!("failed to send OP_REQUESTFILENAME to {peer_addr}"))?;

            if manifest.file_size > ED2K_PART_SIZE {
                let set_req_file_id = encode_set_req_file_id(file_hash);
                dump_ed2k_tcp_download_send(
                    peer_addr,
                    transport.mode,
                    "set_req_file_id",
                    &set_req_file_id,
                );
                transport
                    .write_all(&set_req_file_id)
                    .await
                    .with_context(|| format!("failed to send OP_SETREQFILEID to {peer_addr}"))?;
            }
        }
        session_state.startup_file_requests_sent = true;
    }

    // Source exchange is SX2-only (REF-002 / the sx1-live-source-exchange
    // omission): only request sources from an SX2-capable peer via
    // OP_REQUESTSOURCES2. We never send the legacy SX1 OP_REQUESTSOURCES, so a
    // peer that advertised only SX1 is not asked for sources.
    if send_initial_requests
        && session_state.hello_complete
        && !session_state.source_request_sent
        && !session_state.remote_supports_file_identifiers
        && session_state.source_exchange_allowed
        && session_state.remote_supports_source_exchange2
    {
        let source_request = encode_request_sources2(file_hash);
        dump_ed2k_tcp_download_send(
            peer_addr,
            transport.mode,
            "request_sources2",
            &source_request,
        );
        transport
            .write_all(&source_request)
            .await
            .with_context(|| format!("failed to send OP_REQUESTSOURCES2 to {peer_addr}"))?;
        session_state.source_request_sent = true;
    }

    if send_initial_requests
        && session_state.hello_complete
        && !session_state.aich_file_hash_requested
        && !session_state.remote_supports_file_identifiers
        && session_state.remote_supports_aich
    {
        let aich_file_hash_request = encode_aich_file_hash_request(file_hash);
        dump_ed2k_tcp_download_send(
            peer_addr,
            transport.mode,
            "aich_file_hash_request",
            &aich_file_hash_request,
        );
        transport
            .write_all(&aich_file_hash_request)
            .await
            .with_context(|| format!("failed to send OP_AICHFILEHASHREQ to {peer_addr}"))?;
        session_state.aich_file_hash_requested = true;
    }

    if send_initial_requests
        && session_state.hello_complete
        && manifest.file_size != 0
        && !manifest.md4_hashset_acquired
        && !session_state.hashset_requested
        && session_state.startup_file_response_received
    {
        if manifest.file_size <= ED2K_PART_SIZE {
            *manifest = transfer_runtime
                .store_md4_hashset(file_hash_hex, Vec::new())
                .await?;
        } else {
            let hashset_request = if session_state.remote_supports_file_identifiers {
                encode_hashset_request2(
                    request_file_identifier,
                    Ed2kHashsetRequestOptions {
                        request_md4: true,
                        // Request the AICH hashset only when a peer has advertised
                        // an AICH root for this file. We can no longer key this off
                        // a trusted `manifest.aich_root` (network-learned roots are
                        // no longer promoted on first sight -- they need IP
                        // corroboration), so track the peer-advertised signal
                        // separately. This preserves the prior behaviour without
                        // making the request depend on a trust decision.
                        request_aich: manifest.file_size > ED2K_PART_SIZE
                            && session_state.peer_advertised_aich_root,
                    },
                )?
            } else {
                encode_hashset_request(file_hash)
            };
            dump_ed2k_tcp_download_send(
                peer_addr,
                transport.mode,
                "hashset_request",
                &hashset_request,
            );
            transport
                .write_all(&hashset_request)
                .await
                .with_context(|| {
                    if session_state.remote_supports_file_identifiers {
                        format!("failed to send OP_HASHSETREQUEST2 to {peer_addr}")
                    } else {
                        format!("failed to send OP_HASHSETREQUEST to {peer_addr}")
                    }
                })?;
            session_state.hashset_requested = true;
            session_state.hashset_requested_at = Some(tokio::time::Instant::now());
        }
    }

    let hashset_request_stalled = hashset_request_stalled(session_state);
    if send_initial_requests
        && session_state.hello_complete
        && manifest.file_size != 0
        && (manifest.md4_hashset_acquired || hashset_request_stalled)
        && !session_state.upload_requested
        && session_state.startup_file_response_received
    {
        if hashset_request_stalled && !manifest.md4_hashset_acquired {
            dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "upload_request_hashset_fallback",
                format!("file_hash={file_hash_hex}"),
            );
        }
        let start_upload = encode_start_upload_req(file_hash);
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "start_upload", &start_upload);
        transport
            .write_all(&start_upload)
            .await
            .with_context(|| format!("failed to send OP_STARTUPLOADREQ to {peer_addr}"))?;
        session_state.upload_requested = true;
    }

    Ok(())
}

pub(super) fn hashset_request_stalled(session_state: &DownloadSessionState) -> bool {
    session_state
        .hashset_requested_at
        .is_some_and(|requested_at| requested_at.elapsed() >= HASHSET_STALL_UPLOAD_FALLBACK)
}

fn source_exchange_request_for_peer(
    session_state: &DownloadSessionState,
) -> PeerSourceExchangeRequest {
    // Source exchange is SX2-only (REF-002 / the sx1-live-source-exchange
    // omission): request sources only from an SX2-capable peer. A peer that
    // advertised only the legacy SX1 is never asked (no V1 fallback).
    if session_state.source_exchange_allowed && session_state.remote_supports_source_exchange2 {
        PeerSourceExchangeRequest::V2
    } else {
        PeerSourceExchangeRequest::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(sx1: bool, sx2: bool, allowed: bool) -> DownloadSessionState {
        let mut s = DownloadSessionState::new(true, false, allowed, None, None);
        s.remote_supports_source_exchange = sx1;
        s.remote_supports_source_exchange2 = sx2;
        s
    }

    #[test]
    fn source_exchange_request_is_sx2_only() {
        // SX2-capable peer -> request V2 (REF-002: SX2-only).
        assert_eq!(
            source_exchange_request_for_peer(&state(true, true, true)),
            PeerSourceExchangeRequest::V2
        );
        // SX1-only peer -> never asked (no V1 fallback).
        assert_eq!(
            source_exchange_request_for_peer(&state(true, false, true)),
            PeerSourceExchangeRequest::None
        );
        // No source exchange at all -> None.
        assert_eq!(
            source_exchange_request_for_peer(&state(false, false, true)),
            PeerSourceExchangeRequest::None
        );
        // Source exchange not allowed (already requested) -> None even for SX2.
        assert_eq!(
            source_exchange_request_for_peer(&state(true, true, false)),
            PeerSourceExchangeRequest::None
        );
    }
}
