//! Listener-session decode-and-log handlers for inbound opcodes that carry no
//! upload/session-state effect (out-of-part-reqs, client-id change, slot
//! change, chat message, queue rank, public-IP answer, reask-callback, chat
//! captcha req/res, file description, preview request/answer, buddy pong). Each
//! decodes its payload for the diagnostic packet dump only.

use std::net::SocketAddr;

use anyhow::Result;

use super::super::super::Ed2kTransport;
use super::super::super::codec::{
    decode_chat_captcha_request_payload, decode_chat_captcha_result_payload,
    decode_client_id_change_payload, decode_client_message_payload,
    decode_edonkey_queue_rank_payload, decode_emule_queue_ranking_payload,
    decode_file_description_payload, decode_optional_file_hash_payload,
    decode_preview_answer_payload, decode_preview_request_payload, decode_public_ip_answer_payload,
    decode_reask_callback_tcp_payload,
};
use super::super::super::dump::dump_ed2k_tcp_listener_meta;

/// OP_OUTOFPARTREQS: the peer ran out of part requests for us; log only.
pub(super) fn handle_out_of_part_requests(transport: &Ed2kTransport, peer_addr: SocketAddr) {
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "out_of_part_requests",
        || ("received=true").into(),
    );
}

/// OP_CHANGE_CLIENT_ID: the peer's server reassigned its client id.
pub(super) fn handle_change_client_id(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let change = decode_client_id_change_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "change_client_id", || {
        format!(
            "new_user_id={} new_server_ip={} trailing_len={}",
            change.new_user_id, change.new_server_ip, change.trailing_len
        )
    });
    Ok(())
}

/// OP_CHANGE_SLOT: the peer changed the active transfer slot.
pub(super) fn handle_change_slot(transport: &Ed2kTransport, peer_addr: SocketAddr, payload: &[u8]) {
    let changed_file = decode_optional_file_hash_payload(payload);
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "change_slot", || {
        format!(
            "file_hash={} payload_len={}",
            changed_file.map_or_else(|| "none".to_string(), |hash| hash.to_string()),
            payload.len()
        )
    });
}

/// OP_MESSAGE: an inbound chat message.
pub(super) fn handle_client_message(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let message = decode_client_message_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "client_message", || {
        format!(
            "message_len={} accepted_len={}",
            message.message_len, message.accepted_len
        )
    });
    Ok(())
}

/// OP_QUEUERANK (edonkey): the peer reported our queue rank on it.
pub(super) fn handle_edonkey_queue_rank(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let rank = decode_edonkey_queue_rank_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "queue_ranking", || {
        format!("rank={rank} protocol=edonkey")
    });
    Ok(())
}

/// OP_QUEUERANKING (emule): the peer reported our queue rank on it.
pub(super) fn handle_emule_queue_ranking(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let rank = decode_emule_queue_ranking_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "queue_ranking", || {
        format!("rank={rank} protocol=emule")
    });
    Ok(())
}

/// OP_PUBLICIP_ANSWER: the peer reported the external IP it sees for us.
pub(super) fn handle_public_ip_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let public_ip = decode_public_ip_answer_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "public_ip_answer", || {
        format!("public_ip={public_ip}")
    });
    Ok(())
}

/// OP_REASKCALLBACKTCP: a TCP-relayed reask callback.
pub(super) fn handle_reask_callback_tcp(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let reask = decode_reask_callback_tcp_payload(payload)?;
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "reask_callback_tcp",
        || {
            format!(
                "file_hash={} dest={}:{} extended_info_len={}",
                reask.file_hash, reask.dest_ip, reask.dest_port, reask.extended_info_len
            )
        },
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
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "chat_captcha_request",
        || {
            format!(
                "tag_count={} data_len={}",
                request.tag_count, request.data_len
            )
        },
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
    dump_ed2k_tcp_listener_meta(
        peer_addr,
        Some(transport.mode),
        "chat_captcha_result",
        || format!("status={status}"),
    );
    Ok(())
}

/// OP_FILEDESC: the peer's file rating/comment description.
pub(super) fn handle_file_desc(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let file_desc = decode_file_description_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "file_desc", || {
        format!(
            "rating={} comment_len={}",
            file_desc.rating,
            file_desc.comment.len()
        )
    });
    Ok(())
}

/// OP_REQUESTPREVIEW: a preview request from the peer.
pub(super) fn handle_preview_request(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let preview_request = decode_preview_request_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "preview_request", || {
        format!(
            "file_hash={} trailing_len={}",
            preview_request.file_hash, preview_request.trailing_len
        )
    });
    Ok(())
}

/// OP_PREVIEWANSWER: a preview answer from the peer.
pub(super) fn handle_preview_answer(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let preview_answer = decode_preview_answer_payload(payload)?;
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "preview_answer", || {
        format!(
            "file_hash={} frame_count={} frame_payload_bytes={} trailing_len={}",
            preview_answer.file_hash,
            preview_answer.frame_count,
            preview_answer.frame_payload_bytes,
            preview_answer.trailing_len
        )
    });
    Ok(())
}

/// OP_BUDDYPONG: a Kad buddy pong; log only.
pub(super) fn handle_buddy_pong(
    transport: &Ed2kTransport,
    peer_addr: SocketAddr,
    held_buddy: bool,
) {
    dump_ed2k_tcp_listener_meta(peer_addr, Some(transport.mode), "kad_buddy_pong", || {
        format!("held_buddy={held_buddy}")
    });
}
