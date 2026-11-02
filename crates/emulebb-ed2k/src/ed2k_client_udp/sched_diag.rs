//! Converged `sched.*` evidence for the client-UDP reask state machine.

use std::net::Ipv4Addr;

use emulebb_kad_proto::Ed2kHash;
use serde_json::{Map, Value, json};

use super::codec::{OP_FILENOTFOUND, OP_QUEUEFULL, OP_REASKACK, OP_REASKCALLBACKUDP};
use super::outbound::ReaskSend;
use super::state::{ReaskAction, ReaskDiagnosticIdentity};

const FAMILY: &str = "sched";

fn endpoint(endpoint: (Ipv4Addr, u16)) -> String {
    format!("{}:{}", endpoint.0, endpoint.1)
}

fn source_keys(file_hash: Ed2kHash, identity: ReaskDiagnosticIdentity) -> Value {
    json!({
        "fileHash": file_hash.to_string(),
        "peer": endpoint(identity.peer_endpoint),
        "peerHash": identity.peer_hash.map(hex::encode).unwrap_or_default(),
    })
}

pub(super) fn udp_reask_source_registered(file_hash: Ed2kHash, identity: ReaskDiagnosticIdentity) {
    let (keys, body) = udp_reask_source_registered_parts(file_hash, identity);
    crate::diag_event::emit(FAMILY, "udp_reask_source_registered", "info", keys, body);
}

fn udp_reask_source_registered_parts(
    file_hash: Ed2kHash,
    identity: ReaskDiagnosticIdentity,
) -> (Value, Value) {
    let body = json!({
        "outcome": "accepted",
        "sourceUdpEndpoint": endpoint(identity.source_udp_endpoint),
        "sourceUdpVersion": identity.source_udp_version,
        "lowId": identity.low_id,
        "buddyEndpoint": identity.buddy_endpoint.map(endpoint),
        "buddyId": identity.buddy_id.map(hex::encode),
    });
    (source_keys(file_hash, identity), body)
}

pub(super) fn udp_reask_schedule_decision(send: &ReaskSend) {
    let (keys, body) = udp_reask_schedule_decision_parts(send);
    crate::diag_event::emit(FAMILY, "udp_reask_schedule_decision", "info", keys, body);
}

fn udp_reask_schedule_decision_parts(send: &ReaskSend) -> (Value, Value) {
    let file_hash = send
        .datagram
        .file_hash
        .expect("scheduled reask datagrams are file-owned");
    (
        source_keys(file_hash, send.diagnostic_identity),
        json!({
            "outcome": "eligible",
            "reason": "eligible",
        }),
    )
}

/// Record the production decision to issue this already-built reask. This event
/// deliberately precedes the packet attempt; packet + send_outcome remain the
/// authoritative transport evidence.
pub(super) fn udp_reask_decision(send: &ReaskSend) {
    let (keys, body) = udp_reask_decision_parts(send);
    crate::diag_event::emit(FAMILY, "udp_reask_decision", "info", keys, body);
}

fn udp_reask_decision_parts(send: &ReaskSend) -> (Value, Value) {
    let file_hash = send
        .datagram
        .file_hash
        .expect("scheduled reask datagrams are file-owned");
    let callback = send.datagram.opcode == OP_REASKCALLBACKUDP;
    (
        source_keys(file_hash, send.diagnostic_identity),
        json!({
            "outcome": "sent",
            "transportEligible": true,
            "reason": if callback { "callback_reask_sent" } else { "udp_reask_sent" },
            "path": if callback { "callback" } else { "direct" },
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct UdpReaskFirewallDiagnostic {
    pub authority: &'static str,
    pub server_connected: bool,
    pub server_firewalled: Option<bool>,
    pub kad_connected: bool,
    pub kad_firewalled: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UdpReaskReplyApplicationDiagnostic {
    pub queue_rank_applied: bool,
    pub part_status_included: bool,
    pub wire_part_count: Option<usize>,
    pub part_status_after: Option<Vec<bool>>,
    pub no_needed_parts_after: Option<bool>,
}

fn part_status_bits(parts: &[bool]) -> String {
    parts
        .iter()
        .map(|available| if *available { '1' } else { '0' })
        .collect()
}

pub(super) fn udp_reask_decision_local_firewalled(
    send: &ReaskSend,
    firewall: UdpReaskFirewallDiagnostic,
) {
    let (keys, body) = udp_reask_decision_local_firewalled_parts(send, firewall);
    crate::diag_event::emit(FAMILY, "udp_reask_decision", "info", keys, body);
}

fn udp_reask_decision_local_firewalled_parts(
    send: &ReaskSend,
    firewall: UdpReaskFirewallDiagnostic,
) -> (Value, Value) {
    let file_hash = send
        .datagram
        .file_hash
        .expect("scheduled reask datagrams are file-owned");
    let callback = send.datagram.opcode == OP_REASKCALLBACKUDP;
    (
        source_keys(file_hash, send.diagnostic_identity),
        json!({
            "outcome": "skipped",
            "transportEligible": false,
            "reason": "local_firewalled",
            "path": if callback { "callback" } else { "direct" },
            "localFirewalled": true,
            "firewallAuthority": firewall.authority,
            "serverConnected": firewall.server_connected,
            "serverFirewalled": firewall.server_firewalled,
            "kadConnected": firewall.kad_connected,
            "kadTcpFirewalled": firewall.kad_firewalled,
        }),
    )
}

pub(super) fn udp_reask_reply_applied(
    file_hash: Ed2kHash,
    identity: ReaskDiagnosticIdentity,
    action: ReaskAction,
    request_pending_after: bool,
    remote_queue_full_after: bool,
    application: Option<UdpReaskReplyApplicationDiagnostic>,
) {
    let (keys, body) = udp_reask_reply_applied_parts(
        file_hash,
        identity,
        action,
        request_pending_after,
        remote_queue_full_after,
        application,
    );
    crate::diag_event::emit(FAMILY, "udp_reask_reply_applied", "info", keys, body);
}

fn udp_reask_reply_applied_parts(
    file_hash: Ed2kHash,
    identity: ReaskDiagnosticIdentity,
    action: ReaskAction,
    request_pending_after: bool,
    remote_queue_full_after: bool,
    application: Option<UdpReaskReplyApplicationDiagnostic>,
) -> (Value, Value) {
    let (reply_opcode, queue_rank) = match action {
        ReaskAction::UpdatedRank(rank) => (OP_REASKACK, Some(rank)),
        ReaskAction::QueueFull => (OP_QUEUEFULL, None),
        ReaskAction::DropSource => (OP_FILENOTFOUND, None),
        ReaskAction::RetryTcp | ReaskAction::RetryUdp => {
            unreachable!("timeouts are not parsed replies")
        }
    };
    let mut body = Map::new();
    body.insert("outcome".to_string(), json!("applied"));
    body.insert("replyOpcode".to_string(), json!(reply_opcode));
    if let Some(queue_rank) = queue_rank {
        body.insert("queueRank".to_string(), json!(queue_rank));
    }
    body.insert(
        "requestPendingAfter".to_string(),
        json!(request_pending_after),
    );
    body.insert(
        "remoteQueueFullAfter".to_string(),
        json!(remote_queue_full_after),
    );
    body.insert(
        "sourceUdpEndpoint".to_string(),
        json!(endpoint(identity.source_udp_endpoint)),
    );
    body.insert(
        "sourceUdpVersion".to_string(),
        json!(identity.source_udp_version),
    );
    body.insert(
        "queueRankApplied".to_string(),
        json!(
            application
                .as_ref()
                .is_some_and(|status| status.queue_rank_applied)
        ),
    );
    body.insert(
        "partStatusIncluded".to_string(),
        json!(
            application
                .as_ref()
                .is_some_and(|status| status.part_status_included)
        ),
    );
    body.insert(
        "wirePartCount".to_string(),
        json!(
            application
                .as_ref()
                .and_then(|status| status.wire_part_count)
        ),
    );
    body.insert(
        "partStatusApplied".to_string(),
        json!(
            application
                .as_ref()
                .is_some_and(|status| status.part_status_after.is_some())
        ),
    );
    body.insert(
        "partCountAfter".to_string(),
        json!(
            application
                .as_ref()
                .and_then(|status| status.part_status_after.as_ref().map(Vec::len))
        ),
    );
    body.insert(
        "availablePartsAfter".to_string(),
        json!(application.as_ref().and_then(|status| {
            status
                .part_status_after
                .as_ref()
                .map(|parts| parts.iter().filter(|available| **available).count())
        })),
    );
    body.insert(
        "partStatusBitsAfter".to_string(),
        json!(
            application
                .as_ref()
                .and_then(|status| status.part_status_after.as_deref().map(part_status_bits))
        ),
    );
    body.insert(
        "noNeededPartsAfter".to_string(),
        json!(
            application
                .as_ref()
                .and_then(|status| status.no_needed_parts_after)
        ),
    );
    (source_keys(file_hash, identity), Value::Object(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::outbound::build_reask_callback_udp_packet;

    fn file_hash() -> Ed2kHash {
        Ed2kHash::from_bytes([0x11; 16])
    }

    fn identity() -> ReaskDiagnosticIdentity {
        ReaskDiagnosticIdentity {
            peer_endpoint: (Ipv4Addr::new(192, 0, 2, 20), 4662),
            peer_hash: Some([0x33; 16]),
            source_udp_endpoint: (Ipv4Addr::new(192, 0, 2, 20), 4672),
            source_udp_version: 4,
            low_id: true,
            buddy_endpoint: Some((Ipv4Addr::new(198, 51, 100, 30), 5000)),
            buddy_id: Some([0x22; 16]),
        }
    }

    fn callback_send() -> ReaskSend {
        ReaskSend {
            source_endpoint: identity().source_udp_endpoint,
            destination: "198.51.100.30:5000".parse().unwrap(),
            datagram: build_reask_callback_udp_packet(
                &Ed2kHash::from_bytes([0x22; 16]),
                &file_hash(),
                None,
                0,
                4,
            ),
            request_part_status: None,
            diagnostic_identity: identity(),
        }
    }

    #[test]
    fn registered_buddy_source_matches_the_converged_contract() {
        let (keys, body) = udp_reask_source_registered_parts(file_hash(), identity());

        assert_eq!(
            keys,
            json!({
                "fileHash": "11".repeat(16),
                "peer": "192.0.2.20:4662",
                "peerHash": "33".repeat(16),
            })
        );
        assert_eq!(
            body,
            json!({
                "outcome": "accepted",
                "sourceUdpEndpoint": "192.0.2.20:4672",
                "sourceUdpVersion": 4,
                "lowId": true,
                "buddyEndpoint": "198.51.100.30:5000",
                "buddyId": "22".repeat(16),
            })
        );
    }

    #[test]
    fn callback_schedule_and_decision_match_the_converged_contract() {
        let send = callback_send();
        let (schedule_keys, schedule_body) = udp_reask_schedule_decision_parts(&send);
        let (decision_keys, decision_body) = udp_reask_decision_parts(&send);

        assert_eq!(schedule_keys, decision_keys);
        assert_eq!(
            schedule_body,
            json!({ "outcome": "eligible", "reason": "eligible" })
        );
        assert_eq!(
            decision_body,
            json!({
                "outcome": "sent",
                "transportEligible": true,
                "reason": "callback_reask_sent",
                "path": "callback",
            })
        );
    }

    #[test]
    fn local_firewall_skip_matches_the_oracle_decision_contract() {
        let send = callback_send();
        let (keys, body) = udp_reask_decision_local_firewalled_parts(
            &send,
            UdpReaskFirewallDiagnostic {
                authority: "server_low_id",
                server_connected: true,
                server_firewalled: Some(true),
                kad_connected: false,
                kad_firewalled: None,
            },
        );

        assert_eq!(keys["peer"], "192.0.2.20:4662");
        assert_eq!(keys["peerHash"], "33".repeat(16));
        assert_eq!(
            body,
            json!({
                "outcome": "skipped",
                "transportEligible": false,
                "reason": "local_firewalled",
                "path": "callback",
                "localFirewalled": true,
                "firewallAuthority": "server_low_id",
                "serverConnected": true,
                "serverFirewalled": true,
                "kadConnected": false,
                "kadTcpFirewalled": null,
            })
        );
    }

    #[test]
    fn ack_application_matches_the_converged_contract() {
        let (keys, body) = udp_reask_reply_applied_parts(
            file_hash(),
            identity(),
            ReaskAction::UpdatedRank(47),
            false,
            false,
            Some(UdpReaskReplyApplicationDiagnostic {
                queue_rank_applied: true,
                part_status_included: true,
                wire_part_count: Some(3),
                part_status_after: Some(vec![true, false, true]),
                no_needed_parts_after: Some(false),
            }),
        );

        assert_eq!(keys["peer"], "192.0.2.20:4662");
        assert_eq!(keys["peerHash"], "33".repeat(16));
        assert_eq!(
            body,
            json!({
                "outcome": "applied",
                "replyOpcode": 145,
                "queueRank": 47,
                "requestPendingAfter": false,
                "remoteQueueFullAfter": false,
                "sourceUdpEndpoint": "192.0.2.20:4672",
                "sourceUdpVersion": 4,
                "queueRankApplied": true,
                "partStatusIncluded": true,
                "wirePartCount": 3,
                "partStatusApplied": true,
                "partCountAfter": 3,
                "availablePartsAfter": 2,
                "partStatusBitsAfter": "101",
                "noNeededPartsAfter": false,
            })
        );
    }
}
