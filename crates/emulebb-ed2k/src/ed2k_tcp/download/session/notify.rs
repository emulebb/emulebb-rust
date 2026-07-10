//! Download-session decode-and-log handlers for inbound eMule notification
//! opcodes that carry no download-state effect (public-IP answer, Kad
//! callback/reask-callback, chat captcha req/res, Kad firewall TCP ack, buddy
//! ping/pong, file description, preview request/answer). Each decodes its
//! payload for the diagnostic packet dump only.

use std::net::SocketAddr;

use anyhow::Result;

use crate::ed2k_tcp::{
    Ed2kTransport, decode_chat_captcha_request_payload, decode_chat_captcha_result_payload,
    decode_file_description_payload, decode_kad_callback_payload, decode_preview_answer_payload,
    decode_preview_request_payload, decode_public_ip_answer_payload,
    decode_reask_callback_tcp_payload, dump_ed2k_tcp_download_meta,
};

/// OP_PUBLICIP_ANSWER: the peer reported the external IP it sees for us.
pub(super) fn handle_public_ip_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let public_ip = decode_public_ip_answer_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "public_ip_answer",
        || (format!("public_ip={public_ip}")).into(),
    );
    Ok(())
}

/// OP_CALLBACK: a Kad firewalled-callback request relayed to us.
pub(super) fn handle_kad_callback(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let callback = decode_kad_callback_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "kad_callback",
        || (format!(
            "file_hash={} callback_peer={}:{} buddy_check={} trailing_len={}",
            callback.file_hash,
            callback.peer_ip,
            callback.peer_tcp_port,
            hex::encode(callback.buddy_check),
            callback.trailing_len
        )).into(),
    );
    Ok(())
}

/// OP_REASKCALLBACKTCP: a TCP-relayed reask callback.
pub(super) fn handle_reask_callback_tcp(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let reask = decode_reask_callback_tcp_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "reask_callback_tcp",
        || (format!(
            "file_hash={} dest={}:{} extended_info_len={}",
            reask.file_hash, reask.dest_ip, reask.dest_port, reask.extended_info_len
        )).into(),
    );
    Ok(())
}

/// OP_CHATCAPTCHAREQ: an inbound chat captcha challenge.
pub(super) fn handle_chat_captcha_request(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let request = decode_chat_captcha_request_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "chat_captcha_request",
        || (format!(
            "tag_count={} data_len={}",
            request.tag_count, request.data_len
        )).into(),
    );
    Ok(())
}

/// OP_CHATCAPTCHARES: a chat captcha verification result.
pub(super) fn handle_chat_captcha_result(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let status = decode_chat_captcha_result_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "chat_captcha_result",
        || (format!("status={status}")).into(),
    );
    Ok(())
}

/// OP_KAD_FWTCPCHECK_ACK: a Kad TCP firewall-check acknowledgement.
pub(super) fn handle_kad_firewall_tcp_ack(transport: &Ed2kTransport, peer_addr: SocketAddr) {
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "kad_firewall_tcp_ack",
        || ("received=true").into(),
    );
}

/// OP_BUDDYPING / OP_BUDDYPONG: a Kad buddy keep-alive.
pub(super) fn handle_buddy_ping_pong(transport: &Ed2kTransport, peer_addr: SocketAddr, opcode: u8) {
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "kad_buddy_ping_pong",
        || (format!("opcode=0x{opcode:02X}")).into(),
    );
}

/// OP_FILEDESC: the peer's file rating/comment description.
pub(super) fn handle_file_desc(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    file_hash_hex: &str,
    payload: &[u8],
) -> Result<()> {
    let file_desc = decode_file_description_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "file_desc",
        || (format!(
            "file_hash={file_hash_hex} rating={} comment_len={}",
            file_desc.rating,
            file_desc.comment.len()
        )).into(),
    );
    Ok(())
}

/// OP_REQUESTPREVIEW: a preview request from the peer.
pub(super) fn handle_preview_request(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let preview_request = decode_preview_request_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "preview_request",
        || (format!(
            "file_hash={} trailing_len={}",
            preview_request.file_hash, preview_request.trailing_len
        )).into(),
    );
    Ok(())
}

/// OP_PREVIEWANSWER: a preview answer from the peer.
pub(super) fn handle_preview_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let preview_answer = decode_preview_answer_payload(payload)?;
    dump_ed2k_tcp_download_meta(
        peer_addr,
        Some(transport.mode),
        "preview_answer",
        || (format!(
            "file_hash={} frame_count={} frame_payload_bytes={} trailing_len={}",
            preview_answer.file_hash,
            preview_answer.frame_count,
            preview_answer.frame_payload_bytes,
            preview_answer.trailing_len
        )).into(),
    );
    Ok(())
}
