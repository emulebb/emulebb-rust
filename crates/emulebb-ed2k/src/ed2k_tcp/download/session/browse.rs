//! Download-session handlers for the inbound browse / shared-files family
//! (OP_ASKSHAREDFILES, OP_ASKSHAREDDIRS, OP_ASKSHAREDFILESDIR and their
//! answer/denied opcodes). A downloader never shares, so requests are answered
//! with the empty/denied stubs and answers are decoded for diagnostics only.

use std::net::SocketAddr;

use anyhow::{Context, Result};

use crate::ed2k_tcp::{
    Ed2kTransport, decode_shared_dirs_answer_payload, decode_shared_files_answer_payload,
    decode_shared_files_dir_answer_payload, decode_shared_files_dir_request_payload,
    dump_ed2k_tcp_download_meta, dump_ed2k_tcp_download_send, encode_empty_shared_files_answer,
    encode_shared_browse_denied_answer,
};

/// OP_ASKSHAREDFILES: a downloader does not share, so reply with the empty
/// shared-files answer.
pub(super) async fn handle_ask_shared_files(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload_len: usize,
) -> Result<()> {
    dump_ed2k_tcp_download_meta(peer_addr, Some(transport.mode), "ask_shared_files", || {
        (format!("payload_len={payload_len}")).into()
    });
    let reply = encode_empty_shared_files_answer();
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "shared_files_answer", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_ASKSHAREDFILESANSWER to {peer_addr}"))
}

/// OP_ASKSHAREDDIRS: deny the browse (we share nothing).
pub(super) async fn handle_ask_shared_dirs(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload_len: usize,
) -> Result<()> {
    dump_ed2k_tcp_download_meta(peer_addr, Some(transport.mode), "ask_shared_dirs", || {
        (format!("payload_len={payload_len}")).into()
    });
    let reply = encode_shared_browse_denied_answer();
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "shared_browse_denied", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_ASKSHAREDDENIEDANS to {peer_addr}"))
}

/// OP_ASKSHAREDFILESDIR: deny the per-directory browse.
pub(super) async fn handle_ask_shared_files_dir(
    transport: &mut Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let dir = decode_shared_files_dir_request_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "ask_shared_files_dir",
        || (format!("dir={dir}")).into(),
    );
    let reply = encode_shared_browse_denied_answer();
    dump_ed2k_tcp_download_send(peer_addr, transport.mode, "shared_browse_denied", &reply);
    transport
        .write_all(&reply)
        .await
        .with_context(|| format!("failed to send OP_ASKSHAREDDENIEDANS to {peer_addr}"))
}

/// OP_ASKSHAREDFILESANSWER: decode for diagnostics only.
pub(super) fn handle_ask_shared_files_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let answer = decode_shared_files_answer_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "shared_files_answer",
        || {
            (format!(
                "file_count={} entry_bytes={}",
                answer.file_count, answer.entry_bytes
            ))
            .into()
        },
    );
    Ok(())
}

/// OP_ASKSHAREDDIRSANS: decode for diagnostics only.
pub(super) fn handle_ask_shared_dirs_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let answer = decode_shared_dirs_answer_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "shared_dirs_answer",
        || (format!("dir_count={} dirs={}", answer.dir_count, answer.dirs.len())).into(),
    );
    Ok(())
}

/// OP_ASKSHAREDFILESDIRANS: decode for diagnostics only.
pub(super) fn handle_ask_shared_files_dir_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let answer = decode_shared_files_dir_answer_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "shared_files_dir_answer",
        || {
            (format!(
                "dir={} file_count={} entry_bytes={}",
                answer.dir, answer.file_count, answer.entry_bytes
            ))
            .into()
        },
    );
    Ok(())
}

/// OP_ASKSHAREDDENIEDANS: the peer denied our (never-sent) browse; log only.
pub(super) fn handle_ask_shared_denied_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload_len: usize,
) {
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "shared_browse_denied",
        || (format!("payload_len={payload_len}")).into(),
    );
}
