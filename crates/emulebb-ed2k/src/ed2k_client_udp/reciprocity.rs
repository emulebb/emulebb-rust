//! Uploader-side reciprocity: how to answer an inbound `OP_REASKFILEPING` when a
//! peer queued on us refreshes its slot over UDP. Pure port of eMule's
//! `CClientUDPSocket::ProcessPacket` `OP_REASKFILEPING` handler
//! (`ClientUDPSocket.cpp`); `docs/design/udp-source-reask.md` §4.5.
//!
//! This is the receiver-side analog of [`super::apply_reask_reply`]: given the
//! upload-queue facts, it decides the response. The transport/obfuscation/queue
//! lookups that produce these facts (and that encode the chosen answer via
//! [`super::encode_reask_ack`]) are the gated next slice.

/// Queue-full safety margin eMule keeps before answering `OP_QUEUEFULL` to an
/// otherwise-unknown sender (`GetWaitingUserCount() + 50 > GetQueueSize()`).
pub(crate) const QUEUE_FULL_MARGIN: u32 = 50;

/// The upload-queue facts needed to decide how to answer an inbound reask.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InboundReaskRequest {
    /// Whether we currently share the requested file (`reqfile != NULL`).
    pub file_shared: bool,
    /// Whether the sender is a known waiting client located by `(ip, udp_port)`.
    pub sender_located: bool,
    /// Whether the located sender's upload file matches the requested hash
    /// (`md4equ`); only meaningful when `sender_located`.
    pub file_matches: bool,
    /// The sender's position in our queue (`GetWaitingPosition`); only used for
    /// an `Ack`.
    pub waiting_position: u16,
    /// Set when multiple clients share the sender IP on different UDP ports — a
    /// port-mapping ambiguity that eMule resolves by forcing a TCP connect.
    pub sender_multiple_ip_unknown: bool,
    /// Current number of waiting users (`GetWaitingUserCount`).
    pub waiting_user_count: u32,
    /// Configured queue size (`GetQueueSize`).
    pub queue_size: u32,
}

/// How to answer an inbound `OP_REASKFILEPING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundReaskAnswer {
    /// Reply `OP_REASKACK` carrying our queue rank (and, when the peer's
    /// udp_version > 3, a leading partstatus — handled by `encode_reask_ack`).
    Ack { queue_position: u16 },
    /// Reply `OP_FILENOTFOUND`: we do not share the requested file.
    FileNotFound,
    /// Reply `OP_QUEUEFULL`: the sender is unknown and our queue is near full.
    QueueFull,
    /// Send nothing — deliberately force the peer onto a TCP connection
    /// (sender unknown, or a file/port-mapping mismatch).
    Silent,
}

/// Decide the uploader-side answer to an inbound reask (the §4.5 reaction table).
///
/// Mirrors the master exactly:
/// - file not shared -> `FileNotFound` (sent regardless of whether the sender is
///   located; the crypt choice for it is a transport detail);
/// - sender located + file matches -> `Ack { waiting_position }`;
/// - sender located + file mismatch -> `Silent` (eMule logs and sends nothing);
/// - sender unknown + multiple-IP ambiguity -> `Silent` (force TCP);
/// - sender unknown + queue near full -> `QueueFull`;
/// - sender unknown otherwise -> `Silent` (force TCP).
pub(crate) fn answer_inbound_reask(req: &InboundReaskRequest) -> InboundReaskAnswer {
    if !req.file_shared {
        return InboundReaskAnswer::FileNotFound;
    }
    if req.sender_located {
        if req.file_matches {
            InboundReaskAnswer::Ack {
                queue_position: req.waiting_position,
            }
        } else {
            // Reask for a file the sender isn't actually queued on with us.
            InboundReaskAnswer::Silent
        }
    } else if req.sender_multiple_ip_unknown {
        InboundReaskAnswer::Silent
    } else if req.waiting_user_count + QUEUE_FULL_MARGIN > req.queue_size {
        InboundReaskAnswer::QueueFull
    } else {
        InboundReaskAnswer::Silent
    }
}

/// Framing facts for an inbound reask answer, gathered by the caller from the
/// located waiting client + the requested file: how to address/obfuscate the
/// reply and (for an `Ack`) the partstatus + the peer's udp_version gating it.
#[derive(Debug, Clone)]
pub(crate) struct ReciprocityReplyFraming {
    /// The peer's advertised eD2k UDP version (gates the leading partstatus in
    /// the `OP_REASKACK`, mirroring eMule `GetUDPVersion() > 3`).
    pub peer_udp_version: u8,
    /// The peer's user hash — obfuscation key when `should_crypt`.
    pub dest_user_hash: [u8; 16],
    /// Whether to obfuscate the reply (`ShouldReceiveCryptUDPPackets`).
    pub should_crypt: bool,
    /// Our part availability for the requested file (partfile bitmap, or `None`
    /// for a complete/unshared file).
    pub our_part_status: Option<Vec<bool>>,
}

/// Build the ready-to-send uploader reply datagram for an inbound reask (or
/// `None` for the deliberate-silence cases). Composes the §4.5 decision
/// ([`answer_inbound_reask`]) with the outbound framing/obfuscation builders so
/// the transport just sends the bytes. Pure; the caller gathers `req` + `framing`
/// from the upload queue + shared catalog.
pub(crate) fn build_reciprocity_reply(
    req: &InboundReaskRequest,
    framing: &ReciprocityReplyFraming,
    our_public_ip: [u8; 4],
) -> Option<Vec<u8>> {
    build_reciprocity_reply_packet(req, framing, our_public_ip).map(|packet| packet.bytes)
}

/// Build the ready-to-send uploader reply datagram with packet-diagnostic
/// metadata preserved for the async transport layer.
pub(crate) fn build_reciprocity_reply_packet(
    req: &InboundReaskRequest,
    framing: &ReciprocityReplyFraming,
    our_public_ip: [u8; 4],
) -> Option<super::outbound::ClientUdpDatagram> {
    let target = super::outbound::OutboundReaskTarget {
        dest_user_hash: framing.dest_user_hash,
        our_public_ip,
        obfuscate: framing.should_crypt,
    };
    match answer_inbound_reask(req) {
        InboundReaskAnswer::Ack { queue_position } => {
            Some(super::outbound::build_reask_ack_packet(
                framing.our_part_status.as_deref(),
                queue_position,
                framing.peer_udp_version,
                &target,
            ))
        }
        InboundReaskAnswer::QueueFull => Some(super::outbound::build_queue_full_packet(&target)),
        InboundReaskAnswer::FileNotFound => {
            Some(super::outbound::build_file_not_found_packet(&target))
        }
        InboundReaskAnswer::Silent => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> InboundReaskRequest {
        InboundReaskRequest {
            file_shared: true,
            sender_located: true,
            file_matches: true,
            waiting_position: 0,
            sender_multiple_ip_unknown: false,
            waiting_user_count: 10,
            queue_size: 1000,
        }
    }

    #[test]
    fn unshared_file_is_file_not_found() {
        let req = InboundReaskRequest {
            file_shared: false,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&req), InboundReaskAnswer::FileNotFound);
    }

    #[test]
    fn reciprocity_reply_acks_a_located_match_and_round_trips() {
        use crate::ed2k_client_udp::dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};

        let peer_hash = [0x55u8; 16];
        let our_ip = [203, 0, 113, 9];
        let req = InboundReaskRequest {
            waiting_position: 7,
            ..base()
        };
        let framing = ReciprocityReplyFraming {
            peer_udp_version: 4,
            dest_user_hash: peer_hash,
            should_crypt: true,
            our_part_status: None,
        };
        let datagram = build_reciprocity_reply(&req, &framing, our_ip).expect("ack reply");
        // The peer parses the obfuscated ack: it keys on its own hash (== peer_hash)
        // and the sender IP it sees (our public IP).
        match parse_inbound_reask_datagram(&datagram, our_ip, &peer_hash, 4) {
            Some(InboundReaskMessage::Ack(ack)) => assert_eq!(ack.queue_position, 7),
            other => panic!("expected obfuscated Ack, got {other:?}"),
        }
    }

    #[test]
    fn reciprocity_reply_is_none_for_silent_decisions() {
        // Unknown sender with room => Silent => no datagram.
        let req = InboundReaskRequest {
            sender_located: false,
            waiting_user_count: 1,
            queue_size: 1000,
            ..base()
        };
        let framing = ReciprocityReplyFraming {
            peer_udp_version: 4,
            dest_user_hash: [0u8; 16],
            should_crypt: false,
            our_part_status: None,
        };
        assert!(build_reciprocity_reply(&req, &framing, [203, 0, 113, 9]).is_none());
    }

    #[test]
    fn located_sender_with_matching_file_gets_ack_with_rank() {
        let req = InboundReaskRequest {
            waiting_position: 17,
            ..base()
        };
        assert_eq!(
            answer_inbound_reask(&req),
            InboundReaskAnswer::Ack { queue_position: 17 }
        );
    }

    #[test]
    fn located_sender_with_mismatched_file_stays_silent() {
        let req = InboundReaskRequest {
            file_matches: false,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&req), InboundReaskAnswer::Silent);
    }

    #[test]
    fn unknown_sender_multiple_ip_forces_tcp_silence() {
        let req = InboundReaskRequest {
            sender_located: false,
            sender_multiple_ip_unknown: true,
            // Even with a near-full queue, the ambiguity forces silence.
            waiting_user_count: 1000,
            queue_size: 1000,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&req), InboundReaskAnswer::Silent);
    }

    #[test]
    fn unknown_sender_with_near_full_queue_gets_queue_full() {
        // 960 + 50 > 1000 -> near full.
        let req = InboundReaskRequest {
            sender_located: false,
            waiting_user_count: 960,
            queue_size: 1000,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&req), InboundReaskAnswer::QueueFull);
    }

    #[test]
    fn unknown_sender_with_room_stays_silent_to_force_tcp() {
        // 100 + 50 < 1000 -> room; don't answer, force TCP.
        let req = InboundReaskRequest {
            sender_located: false,
            waiting_user_count: 100,
            queue_size: 1000,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&req), InboundReaskAnswer::Silent);
    }

    #[test]
    fn queue_full_margin_is_exclusive_threshold() {
        // Exactly at the margin (950 + 50 == 1000, not > 1000) -> still silent.
        let at_margin = InboundReaskRequest {
            sender_located: false,
            waiting_user_count: 950,
            queue_size: 1000,
            ..base()
        };
        assert_eq!(answer_inbound_reask(&at_margin), InboundReaskAnswer::Silent);
        // One over -> queue full.
        let over = InboundReaskRequest {
            waiting_user_count: 951,
            ..at_margin
        };
        assert_eq!(answer_inbound_reask(&over), InboundReaskAnswer::QueueFull);
    }
}
