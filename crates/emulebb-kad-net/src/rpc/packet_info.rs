use crate::obfuscation::{OutboundKadEncryptionInfo, OutboundKadEncryptionMode};
use crate::tracker::{OutboundRequestTracker, PacketTrackerBucket};
use emulebb_kad_proto::{KadPacket, NodeId, constants::opcode};
use parking_lot::Mutex;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub(super) struct InboundKadPacketInfo {
    pub(super) tracker_bucket: Option<PacketTrackerBucket>,
    pub(super) peer_id: Option<NodeId>,
    pub(super) kad_version: Option<u8>,
}

pub(super) fn inspect_inbound_packet(packet: &KadPacket) -> InboundKadPacketInfo {
    match packet {
        KadPacket::BootstrapRes(res) => InboundKadPacketInfo {
            tracker_bucket: None,
            peer_id: Some(res.sender_id),
            kad_version: Some(res.sender_version),
        },
        KadPacket::HelloReq(req) => InboundKadPacketInfo {
            tracker_bucket: Some(PacketTrackerBucket::HelloReq),
            peer_id: Some(req.node_id),
            kad_version: Some(req.version),
        },
        KadPacket::HelloRes(res) => InboundKadPacketInfo {
            tracker_bucket: None,
            peer_id: Some(res.node_id),
            kad_version: Some(res.version),
        },
        KadPacket::HelloResAck(ack) => InboundKadPacketInfo {
            tracker_bucket: None,
            peer_id: Some(ack.node_id),
            kad_version: None,
        },
        KadPacket::SearchRes(res) => InboundKadPacketInfo {
            tracker_bucket: Some(PacketTrackerBucket::SearchRes),
            peer_id: Some(res.sender_id),
            kad_version: None,
        },
        _ => InboundKadPacketInfo {
            tracker_bucket: tracker_bucket_for_opcode(packet.opcode()),
            peer_id: None,
            kad_version: None,
        },
    }
}

fn tracker_bucket_for_opcode(opcode_value: u8) -> Option<PacketTrackerBucket> {
    match opcode_value {
        opcode::BOOTSTRAP_REQ => Some(PacketTrackerBucket::BootstrapReq),
        opcode::HELLO_REQ => Some(PacketTrackerBucket::HelloReq),
        opcode::REQ => Some(PacketTrackerBucket::FindNodeReq),
        opcode::SEARCH_KEY_REQ | opcode::SEARCH_SOURCE_REQ | opcode::SEARCH_NOTES_REQ => {
            Some(PacketTrackerBucket::SearchReq)
        }
        opcode::PUBLISH_KEY_REQ => Some(PacketTrackerBucket::PublishKeyReq),
        opcode::PUBLISH_SOURCE_REQ => Some(PacketTrackerBucket::PublishSourceReq),
        opcode::PUBLISH_NOTES_REQ => Some(PacketTrackerBucket::PublishNotesReq),
        opcode::FIREWALLED_REQ | opcode::FIREWALLED2_REQ => {
            Some(PacketTrackerBucket::FirewalledReq)
        }
        opcode::FINDBUDDY_REQ => Some(PacketTrackerBucket::FindBuddyReq),
        opcode::CALLBACK_REQ => Some(PacketTrackerBucket::CallbackReq),
        opcode::PING => Some(PacketTrackerBucket::PingReq),
        opcode::SEARCH_RES => Some(PacketTrackerBucket::SearchRes),
        _ => None,
    }
}

pub(super) fn is_publish_opcode(opcode_value: u8) -> bool {
    matches!(
        opcode_value,
        opcode::PUBLISH_KEY_REQ
            | opcode::PUBLISH_SOURCE_REQ
            | opcode::PUBLISH_NOTES_REQ
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
    )
}

pub(super) fn should_learn_sender_verify_key(opcode_value: u8) -> bool {
    matches!(
        opcode_value,
        opcode::BOOTSTRAP_REQ
            | opcode::BOOTSTRAP_RES
            | opcode::HELLO_REQ
            | opcode::HELLO_RES
            | opcode::HELLO_RES_ACK
            | opcode::REQ
            | opcode::SEARCH_KEY_REQ
            | opcode::SEARCH_SOURCE_REQ
            | opcode::SEARCH_NOTES_REQ
            | opcode::PUBLISH_KEY_REQ
            | opcode::PUBLISH_SOURCE_REQ
            | opcode::PUBLISH_NOTES_REQ
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
            | opcode::FIREWALLED_REQ
            | opcode::FIREWALLED2_REQ
            | opcode::FINDBUDDY_REQ
            | opcode::FINDBUDDY_RES
            | opcode::CALLBACK_REQ
            | opcode::PING
    )
}

pub(super) fn should_log_unsolicited_opcode(opcode_value: u8) -> bool {
    matches!(
        opcode_value,
        opcode::BOOTSTRAP_REQ
            | opcode::BOOTSTRAP_RES
            | opcode::HELLO_REQ
            | opcode::HELLO_RES
            | opcode::HELLO_RES_ACK
            | opcode::REQ
            | opcode::RES
            | opcode::SEARCH_KEY_REQ
            | opcode::SEARCH_SOURCE_REQ
            | opcode::SEARCH_NOTES_REQ
            | opcode::SEARCH_RES
            | opcode::PUBLISH_KEY_REQ
            | opcode::PUBLISH_SOURCE_REQ
            | opcode::PUBLISH_NOTES_REQ
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
            | opcode::FIREWALLED_REQ
            | opcode::FIREWALLED2_REQ
            | opcode::FIREWALLED_RES
            | opcode::FIREWALLED_ACK_RES
            | opcode::FIREWALLUDP
            | opcode::FINDBUDDY_REQ
            | opcode::FINDBUDDY_RES
            | opcode::CALLBACK_REQ
            | opcode::PING
            | opcode::PONG
    )
}

pub(super) fn is_tracked_response_opcode(opcode_value: u8) -> bool {
    // NOTE: FIREWALLED_RES / FIREWALLED_ACK_RES are intentionally excluded.
    // The oracle deliberately does NOT out-track firewall-check requests
    // (PacketTracking.cpp IsTrackedOutListRequestPacket omits FIREWALLED_REQ /
    // FIREWALLED2_REQ); instead Process_KADEMLIA_FIREWALLED_RES validates the
    // response against the firewall-check-IP list (IsKadFirewallCheckIP). If we
    // treated them as out-tracked responses here, they would be dropped as
    // unrequested before the handler ran, leaving the TCP firewall recheck inert.
    // Letting them fall through to the unsolicited path delivers them to the
    // handler, which performs the IP-list validation itself.
    matches!(
        opcode_value,
        opcode::BOOTSTRAP_RES
            | opcode::HELLO_RES
            | opcode::HELLO_RES_ACK
            | opcode::RES
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
            | opcode::FINDBUDDY_RES
            | opcode::PONG
    )
}

pub(super) fn opcode_name(opcode_value: u8) -> &'static str {
    match opcode_value {
        opcode::BOOTSTRAP_REQ => "KADEMLIA2_BOOTSTRAP_REQ",
        opcode::BOOTSTRAP_RES => "KADEMLIA2_BOOTSTRAP_RES",
        opcode::HELLO_REQ_DEPRECATED => "KADEMLIA_HELLO_REQ_DEPRECATED",
        opcode::HELLO_REQ => "KADEMLIA2_HELLO_REQ",
        opcode::HELLO_RES_DEPRECATED => "KADEMLIA_HELLO_RES_DEPRECATED",
        opcode::HELLO_RES => "KADEMLIA2_HELLO_RES",
        opcode::HELLO_RES_ACK => "KADEMLIA2_HELLO_RES_ACK",
        opcode::REQ => "KADEMLIA2_REQ",
        opcode::RES => "KADEMLIA2_RES",
        opcode::SEARCH_KEY_REQ => "KADEMLIA2_SEARCH_KEY_REQ",
        opcode::SEARCH_SOURCE_REQ => "KADEMLIA2_SEARCH_SOURCE_REQ",
        opcode::SEARCH_NOTES_REQ => "KADEMLIA2_SEARCH_NOTES_REQ",
        opcode::SEARCH_RES => "KADEMLIA2_SEARCH_RES",
        opcode::PUBLISH_KEY_REQ => "KADEMLIA2_PUBLISH_KEY_REQ",
        opcode::PUBLISH_SOURCE_REQ => "KADEMLIA2_PUBLISH_SOURCE_REQ",
        opcode::PUBLISH_NOTES_REQ => "KADEMLIA2_PUBLISH_NOTES_REQ",
        opcode::PUBLISH_RES => "KADEMLIA2_PUBLISH_RES",
        opcode::PUBLISH_RES_ACK => "KADEMLIA2_PUBLISH_RES_ACK",
        opcode::FIREWALLED_REQ => "KADEMLIA_FIREWALLED_REQ",
        opcode::FIREWALLED2_REQ => "KADEMLIA2_FIREWALLED2_REQ",
        opcode::FIREWALLED_RES => "KADEMLIA2_FIREWALLED_RES",
        opcode::FIREWALLED_ACK_RES => "KADEMLIA2_FIREWALLED_ACK_RES",
        opcode::FIREWALLUDP => "KADEMLIA2_FIREWALLUDP",
        opcode::FINDBUDDY_REQ => "KADEMLIA_FINDBUDDY_REQ",
        opcode::FINDBUDDY_RES => "KADEMLIA_FINDBUDDY_RES",
        opcode::CALLBACK_REQ => "KADEMLIA_CALLBACK_REQ",
        opcode::PING => "KADEMLIA2_PING",
        opcode::PONG => "KADEMLIA2_PONG",
        _ => "UNKNOWN",
    }
}

pub(super) fn hex_prefix(bytes: &[u8], max_bytes: usize) -> String {
    let prefix_len = bytes.len().min(max_bytes);
    let mut out = String::with_capacity(prefix_len.saturating_mul(2));
    for byte in &bytes[..prefix_len] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub(super) fn outbound_transport_reason(
    opcode_value: u8,
    outbound: OutboundKadEncryptionInfo,
) -> &'static str {
    match outbound.mode {
        OutboundKadEncryptionMode::NodeId => "node_id_fallback_without_receiver_verify_key",
        OutboundKadEncryptionMode::ReceiverVerifyKey => {
            if is_response_opcode(opcode_value) {
                "reply_falls_back_to_receiver_verify_key_without_node_id"
            } else {
                "request_falls_back_to_receiver_verify_key_without_node_id"
            }
        }
        OutboundKadEncryptionMode::Plaintext => {
            if outbound.peer_node_id.is_none() && outbound.receiver_verify_key.is_none() {
                "missing_peer_identity_and_receiver_key"
            } else if outbound.peer_node_id.is_none() {
                "missing_peer_identity_for_node_id_mode"
            } else if outbound
                .peer_kad_version
                .is_some_and(|kad_version| kad_version < 6)
            {
                "peer_version_below_v6_without_receiver_key"
            } else {
                "missing_receiver_verify_key"
            }
        }
    }
}

fn is_response_opcode(opcode_value: u8) -> bool {
    matches!(
        opcode_value,
        opcode::BOOTSTRAP_RES
            | opcode::HELLO_RES
            | opcode::HELLO_RES_ACK
            | opcode::RES
            | opcode::SEARCH_RES
            | opcode::PUBLISH_RES
            | opcode::PUBLISH_RES_ACK
            | opcode::FIREWALLED_RES
            | opcode::FIREWALLED_ACK_RES
            | opcode::FINDBUDDY_RES
            | opcode::PONG
    )
}

pub(super) fn inbound_transport_mode(
    was_obfuscated: bool,
    receiver_verify_key_valid: bool,
) -> &'static str {
    if !was_obfuscated {
        "plaintext"
    } else if receiver_verify_key_valid {
        "receiver_verify_key"
    } else {
        "node_id"
    }
}

pub(super) fn tracked_request_opcode_for_response(
    outbound_tracker: &Mutex<OutboundRequestTracker>,
    ip: IpAddr,
    response_opcode: u8,
) -> Option<u8> {
    let mut tracker = outbound_tracker.lock();
    match response_opcode {
        opcode::BOOTSTRAP_RES => tracker.find_any(ip, &[opcode::BOOTSTRAP_REQ], true),
        opcode::HELLO_RES => tracker.find_any(ip, &[opcode::HELLO_REQ], true),
        opcode::HELLO_RES_ACK => tracker.find_any(ip, &[opcode::HELLO_RES], true),
        opcode::RES => tracker.find_any(ip, &[opcode::REQ], true),
        opcode::PUBLISH_RES => {
            let matched = tracker.find_any(
                ip,
                &[
                    opcode::PUBLISH_KEY_REQ,
                    opcode::PUBLISH_SOURCE_REQ,
                    opcode::PUBLISH_NOTES_REQ,
                ],
                false,
            )?;
            let _ = tracker.contains(ip, matched, true);
            Some(matched)
        }
        // FIREWALLED_RES / FIREWALLED_ACK_RES are deliberately not out-tracked
        // (the oracle validates them against the firewall-check-IP list instead),
        // so there is never a matching tracked request here.
        opcode::FINDBUDDY_RES => tracker.find_any(ip, &[opcode::FINDBUDDY_REQ], true),
        opcode::PONG => tracker.find_any(ip, &[opcode::PING], true),
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::opcode_name;
    use emulebb_kad_proto::constants::opcode;

    // Regression (2026-07-06 parity audit): an unknown/legacy inbound Kad opcode
    // (e.g. Kad1 KADEMLIA_REQ 0x20) must keep its RAW NUMERIC opcode through the
    // decode + diag pipeline, with "UNKNOWN" as the name marker. If either ever
    // becomes None/absent, the offline coverage tooling can no longer credit rust
    // with receiving those opcodes from the diag stream alone.
    #[test]
    fn unknown_legacy_inbound_opcode_keeps_raw_numeric_opcode_for_diagnostics() {
        let datagram = [0xE4u8, 0x20, 0x01, 0x02, 0x03];
        let packet = emulebb_kad_proto::KadPacket::decode(&datagram).expect("decodes as Unknown");
        assert!(matches!(
            packet,
            emulebb_kad_proto::KadPacket::Unknown { opcode: 0x20, .. }
        ));
        assert_eq!(packet.opcode(), 0x20);
        assert_eq!(opcode_name(0x20), "UNKNOWN");
    }

    #[test]
    fn deprecated_kad_hello_opcodes_are_named_for_diagnostics() {
        assert_eq!(
            opcode_name(opcode::HELLO_REQ_DEPRECATED),
            "KADEMLIA_HELLO_REQ_DEPRECATED"
        );
        assert_eq!(
            opcode_name(opcode::HELLO_RES_DEPRECATED),
            "KADEMLIA_HELLO_RES_DEPRECATED"
        );
    }
}
