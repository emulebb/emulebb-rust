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
    if session_state.peer_low_id {
        // WHY: A TCP hello can advertise a LowID peer's buddy endpoint but not
        // its buddy id. MFC only emits LowID UDP reasks when the buddy id is
        // known from Kad source discovery, so TCP-discovered LowID queue sources
        // must stay on the normal reconnect/callback path instead of being
        // stranded in the UDP reask loop.
        tracing::debug!(
            "not detaching LowID queued source {peer_addr} for UDP reask: missing buddy id"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::{ReaskCommand, reask_command_channel};
    use crate::ed2k_tcp::download::session::DownloadSessionState;
    use std::net::Ipv4Addr;
    use tokio::time::Instant;

    fn session_state(low_id: bool) -> DownloadSessionState {
        let mut state = DownloadSessionState::new(false, false, false, Some([0x42; 16]), None);
        state.queued_until = Some(Instant::now());
        state.peer_udp_port = 4672;
        state.peer_udp_version = 4;
        state.peer_low_id = low_id;
        state.peer_buddy_endpoint = Some((Ipv4Addr::new(198, 51, 100, 10), 5000));
        state
    }

    #[test]
    fn high_id_queued_source_detaches_for_udp_reask() {
        let file_hash = Ed2kHash::from_bytes([0x5a; 16]);
        let peer_addr = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 4662);
        let state = session_state(false);
        let (handle, mut rx) = reask_command_channel();

        assert!(try_detach_queued_source_for_reask(
            &Some(handle),
            peer_addr,
            file_hash,
            &state,
            true,
        ));

        match rx.try_recv().expect("register command") {
            ReaskCommand::Register(args) => {
                assert_eq!(args.file_hash, file_hash);
                assert_eq!(args.endpoint, (Ipv4Addr::new(192, 0, 2, 10), 4672));
                assert_eq!(args.udp_version, 4);
                assert_eq!(args.user_hash, Some([0x42; 16]));
                assert!(args.should_crypt);
                assert!(!args.low_id);
                assert_eq!(
                    args.buddy_endpoint,
                    Some((Ipv4Addr::new(198, 51, 100, 10), 5000))
                );
                assert_eq!(args.buddy_id, None);
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    #[test]
    fn low_id_tcp_queued_source_without_buddy_id_stays_on_tcp_path() {
        let file_hash = Ed2kHash::from_bytes([0x6b; 16]);
        let peer_addr = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 20).into(), 4662);
        let state = session_state(true);
        let (handle, mut rx) = reask_command_channel();

        assert!(!try_detach_queued_source_for_reask(
            &Some(handle),
            peer_addr,
            file_hash,
            &state,
            false,
        ));
        assert!(rx.try_recv().is_err());
    }
}
