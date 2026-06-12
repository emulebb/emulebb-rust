use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::ed2k_server::Ed2kFoundSource;
use crate::ed2k_transfer::{Ed2kSourceHint, Ed2kTransferRuntime, new_transfer_job};

use super::super::{
    Ed2kHelloIdentity, Ed2kSecureIdent, Ed2kTransport, dump_ed2k_tcp_download_meta,
    dump_ed2k_tcp_download_send, encode_hello_request,
};
use super::session::{DownloadSessionOptions, Ed2kPeerDownloadOutcome, drive_download_session};
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
    pub canonical_name: String,
    pub file_size: u64,
    pub timeout: Duration,
}

pub async fn download_file_from_peer(
    options: Ed2kPeerDownloadOptions<'_>,
) -> Result<Ed2kPeerDownloadOutcome> {
    let Ed2kPeerDownloadOptions {
        bind_ip,
        peer,
        hello_identity,
        secure_ident,
        transfer_runtime,
        canonical_name,
        file_size,
        timeout,
    } = options;
    let file_hash = peer.file_hash;
    let file_hash_hex = file_hash.to_string();
    let job = new_transfer_job(file_hash, canonical_name, file_size);
    transfer_runtime.ensure_job(&job).await?;
    transfer_runtime
        .remember_source(
            &file_hash_hex,
            Ed2kSourceHint {
                ip: peer.ip.to_string(),
                tcp_port: peer.tcp_port,
                user_hash: peer.user_hash.map(hex::encode),
            },
        )
        .await?;

    let peer_addr = SocketAddr::new(IpAddr::V4(peer.ip), peer.tcp_port);
    dump_ed2k_tcp_download_meta(
        peer_addr,
        None,
        "connect_start",
        format!(
            "file_hash={file_hash_hex} file_size={file_size} client_id={} obfuscated={} has_user_hash={}",
            peer.client_id,
            peer.obfuscated,
            peer.user_hash.is_some()
        ),
    );
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
        dump_ed2k_tcp_download_meta(
            peer_addr,
            Some(transport.mode),
            "connect_ready",
            format!("file_hash={file_hash_hex}"),
        );
        let source_exchange_allowed = transfer_runtime
            .should_request_source_exchange(
                &file_hash_hex,
                peer_addr,
                peer.user_hash,
                std::time::Instant::now(),
            )
            .await;
        let hello = encode_hello_request(hello_identity);
        dump_ed2k_tcp_download_send(peer_addr, transport.mode, "hello", &hello);
        transport
            .write_all(&hello)
            .await
            .with_context(|| format!("failed to send OP_HELLO to {peer_addr}"))?;
        let session_result = drive_download_session(DownloadSessionOptions {
            transport: &mut transport,
            peer_addr,
            hello_identity,
            secure_ident: secure_ident.as_ref(),
            transfer_runtime,
            file_hash,
            file_hash_hex: &file_hash_hex,
            timeout,
            send_initial_requests: true,
            source_exchange_allowed,
            initial_hello_complete: false,
            initial_secure_ident_started: false,
            peer_user_hash: peer.user_hash,
        })
        .await;
        match &session_result {
            Ok(Ed2kPeerDownloadOutcome::Completed) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "complete",
                format!("file_hash={file_hash_hex}"),
            ),
            Ok(Ed2kPeerDownloadOutcome::AcceptedButIncomplete) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "accepted_incomplete",
                format!("file_hash={file_hash_hex}"),
            ),
            Err(error) => dump_ed2k_tcp_download_meta(
                peer_addr,
                Some(transport.mode),
                "error",
                format!("file_hash={file_hash_hex} error={error}"),
            ),
        }
        session_result
    }
    .await
}
