use std::net::SocketAddr;

use emulebb_kad_proto::Ed2kHash;

use super::{DownloadSessionState, Ed2kPeerDownloadOutcome};

/// Return the incomplete outcome for a queued peer, detaching it to UDP reask
/// only after the live TCP queue session is gone or timed out.
pub(super) fn incomplete_or_detached_queued_source(
    reask_register: &Option<crate::ed2k_client_udp::ReaskSourceHandle>,
    peer_addr: SocketAddr,
    file_hash: Ed2kHash,
    session_state: &DownloadSessionState,
    should_crypt: bool,
) -> Ed2kPeerDownloadOutcome {
    // WHY: MFC keeps the TCP queue session usable while it is connected; UDP
    // reask is only used when the socket is gone. Detach queued sources only on
    // incomplete exits, not on the queue-rank packet itself, so late accepts can
    // still start a transfer.
    if session_state.queued_until.is_some()
        && try_detach_queued_source_for_reask(
            reask_register,
            peer_addr,
            file_hash,
            session_state,
            should_crypt,
        )
    {
        Ed2kPeerDownloadOutcome::QueuedDetachedForUdpReask
    } else {
        Ed2kPeerDownloadOutcome::AcceptedButIncomplete
    }
}

/// Detach a queued source onto UDP reask when reask is enabled and the peer is
/// UDP-eligible (eMuleBB `QueuedDetached`).
fn try_detach_queued_source_for_reask(
    reask_register: &Option<crate::ed2k_client_udp::ReaskSourceHandle>,
    peer_addr: SocketAddr,
    file_hash: Ed2kHash,
    session_state: &DownloadSessionState,
    should_crypt: bool,
) -> bool {
    let Some(handle) = reask_register else {
        return false;
    };
    let SocketAddr::V4(v4) = peer_addr else {
        return false;
    };
    const DEFAULT_PEER_UDP_VERSION: u8 = 4;
    let effective_udp_version = if session_state.peer_udp_version != 0 {
        session_state.peer_udp_version
    } else {
        DEFAULT_PEER_UDP_VERSION
    };
    let eligible = crate::ed2k_client_udp::udp_reask_eligible(
        session_state.peer_udp_port,
        effective_udp_version,
        true,
        false,
        false,
        false,
    );
    tracing::debug!(
        "reask detach check for {peer_addr}: peer_udp_port={} peer_udp_version={} (effective={effective_udp_version}) low_id={} eligible={eligible}",
        session_state.peer_udp_port,
        session_state.peer_udp_version,
        session_state.peer_low_id,
    );
    if !eligible {
        return false;
    }
    handle.detach(crate::ed2k_client_udp::ReaskDetachArgs {
        file_hash,
        endpoint: (*v4.ip(), session_state.peer_udp_port),
        udp_version: effective_udp_version,
        // WHY: MFC stamps SetLastAskedTime() when the TCP file request is sent,
        // so a queued source is not immediately reasked over UDP after the TCP
        // queue-rank response detaches the socket.
        initial_reask_delay: crate::ed2k_client_udp::FILE_REASK_TIME,
        user_hash: session_state.peer_user_hash,
        should_crypt,
        low_id: session_state.peer_low_id,
        buddy_endpoint: session_state.peer_buddy_endpoint,
        buddy_id: None,
    });
    true
}
