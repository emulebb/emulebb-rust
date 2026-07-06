use std::sync::Arc;

use emulebb_kad_proto::KadPacket;
use tracing::{debug, error, info, warn};

use super::packet_info::{
    hex_prefix, inbound_transport_mode, inspect_inbound_packet, is_publish_opcode,
    is_tracked_response_opcode, opcode_name, should_learn_sender_verify_key,
    should_log_unsolicited_opcode, tracked_request_opcode_for_response,
};
use super::{ReceivedKadPacket, RpcManager};
use crate::error::NetError;
use crate::obfuscation::DecryptResult;
use crate::tracker::{PacketTrackerAction, PacketTrackerBucket, PacketTrackerKey};
use crate::wire_dump::{KadUdpDumpSummary, dump_kad_udp_packet};

impl RpcManager {
    /// Start the background receive loop. Returns the JoinHandle.
    /// The handle will run until the transport is closed or an unrecoverable error occurs.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            loop {
                match inner.transport.recv_raw().await {
                    Ok((data, from)) => {
                        let DecryptResult {
                            data: plain,
                            was_obfuscated,
                            sender_verify_key,
                            receiver_verify_key_valid,
                        } = inner.obfuscation.decrypt(from, &data);
                        debug!("packet from {} was_obfuscated={}", from, was_obfuscated);

                        // DNS-confusion hardening (oracle KademliaUDPListener.cpp:250):
                        // drop an unencrypted Kad datagram whose SOURCE UDP port is 53
                        // and that carries no sender key. Such a packet is a
                        // reflected/forged DNS response, never a real Kad message; an
                        // obfuscated packet (or one proving a key) is exempt.
                        if from.port() == 53 && !was_obfuscated && sender_verify_key.is_none() {
                            debug!("kad recv drop reason=sender_port_53 from={from}");
                            continue;
                        }

                        let packet = match KadPacket::decode(&plain) {
                            Ok(p) => p,
                            Err(e) => {
                                // Before treating this as a Kad decode failure,
                                // offer the raw datagram to a registered foreign
                                // handler (e.g. eD2k client UDP reask sharing the
                                // Kad port). If it consumes the datagram, this was
                                // never a Kad packet — skip the decode-failure path.
                                if let Some(handler) = inner.foreign_datagram_handler.get()
                                    && handler(&data, from)
                                {
                                    continue;
                                }
                                inner.observability.lock().unwrap().record_decode_failure();
                                dump_kad_udp_packet(
                                    "recv",
                                    from,
                                    &data,
                                    &plain,
                                    KadUdpDumpSummary {
                                        protocol: plain.first().copied().unwrap_or_default(),
                                        opcode: plain.get(1).copied(),
                                        // Name the heuristic opcode byte too (known name
                                        // or the "UNKNOWN" marker) so decode-failed diag
                                        // records stay self-sufficient for opcode-coverage
                                        // crediting, matching the decoded-packet records.
                                        opcode_name: plain.get(1).map(|&op| opcode_name(op)),
                                        raw_obfuscated: was_obfuscated,
                                        transport_mode: Some(inbound_transport_mode(
                                            was_obfuscated,
                                            receiver_verify_key_valid,
                                        )),
                                        requested_obfuscation: None,
                                        receiver_verify_key: None,
                                        sender_verify_key,
                                        receiver_verify_key_valid: Some(receiver_verify_key_valid),
                                        tracked_request_opcode: None,
                                        drop_reason: Some("decode_failed"),
                                        tracker_bucket: None,
                                        tracker_action: None,
                                        tracker_observed_packets: None,
                                        tracker_max_packets: None,
                                    },
                                );
                                info!(
                                    "kad recv decode-failed from={} obfuscated={} raw_len={} plain_len={} raw_prefix={} plain_prefix={} error={}",
                                    from,
                                    was_obfuscated,
                                    data.len(),
                                    plain.len(),
                                    hex_prefix(&data, 16),
                                    hex_prefix(&plain, 16),
                                    e,
                                );
                                debug!("failed to decode packet from {}: {}", from, e);
                                continue;
                            }
                        };

                        let response_opcode = packet.opcode();
                        let inbound = inspect_inbound_packet(&packet);

                        if let Some(peer_id) = inbound.peer_id {
                            inner.obfuscation.register_peer_identity(from, peer_id);
                        }
                        if let Some(kad_version) = inbound.kad_version {
                            inner.obfuscation.register_peer_version(from, kad_version);
                        }
                        if should_learn_sender_verify_key(response_opcode)
                            && let Some(sender_verify_key) = sender_verify_key
                        {
                            inner.obfuscation.register_peer_key(from, sender_verify_key);
                        }

                        debug!(
                            "kad recv opcode={} from={} obfuscated={} receiver_key_valid={} sender_verify_key={} bucket={} peer_id={} peer_version={}",
                            opcode_name(response_opcode),
                            from,
                            was_obfuscated,
                            receiver_verify_key_valid,
                            sender_verify_key.unwrap_or_default(),
                            inbound
                                .tracker_bucket
                                .map(PacketTrackerBucket::label)
                                .unwrap_or("-"),
                            inbound
                                .peer_id
                                .map(|peer_id| peer_id.to_string())
                                .unwrap_or_else(|| "-".to_string()),
                            inbound
                                .kad_version
                                .map_or_else(|| "-".to_string(), |version| version.to_string()),
                        );

                        // LAN/loopback peers are exempt from the inbound flood
                        // guard: the anti-flood + per-IP ban is a public-network
                        // DoS protection (oracle treats LAN as trusted), and on a
                        // single host every local node shares one loopback IP, so
                        // throttling/banning by IP there would collapse all of
                        // them together. Public peers are still fully throttled.
                        let flood_exempt = is_lan_ip(from.ip());

                        // Drop everything from an IP previously flood-banned
                        // (oracle banned-client check), before any per-bucket
                        // accounting or handler dispatch.
                        if !flood_exempt && inner.tracker.lock().unwrap().is_banned(from.ip()) {
                            inner.observability.lock().unwrap().record_tracker_action(
                                inbound
                                    .tracker_bucket
                                    .unwrap_or(PacketTrackerBucket::Default),
                                PacketTrackerAction::MassiveDrop,
                            );
                            debug!(
                                "dropping Kad packet from flood-banned IP {} opcode={}",
                                from.ip(),
                                opcode_name(response_opcode),
                            );
                            // WHY: the ban verdict is already emitted once as a
                            // high-severity anti_flood_ban when the limiter trips
                            // (the MassiveDrop branch below). A flood-banned IP keeps
                            // sending, so re-emitting a high-severity event for every
                            // dropped packet spammed the diagnostics (hundreds/min for
                            // a single IP) and inflated the high-severity count.
                            // Subsequent drops are still counted via
                            // record_tracker_action above and debug-logged; stock
                            // eMule likewise drops silently once an IP is banned, so
                            // suppressing the per-packet event keeps diagnostics at
                            // parity (uniform-diagnostics-v2 §3.4).
                            continue;
                        }

                        if let Some(bucket) = inbound.tracker_bucket.filter(|_| !flood_exempt) {
                            let decision =
                                inner
                                    .tracker
                                    .lock()
                                    .unwrap()
                                    .record_and_check(PacketTrackerKey {
                                        ip: from.ip(),
                                        bucket,
                                    });
                            inner
                                .observability
                                .lock()
                                .unwrap()
                                .record_tracker_action(bucket, decision.action);
                            if !decision.allowed {
                                let drop_reason = match decision.action {
                                    PacketTrackerAction::Allow => None,
                                    PacketTrackerAction::Drop => Some("tracker_drop"),
                                    PacketTrackerAction::MassiveDrop => {
                                        Some("tracker_massive_drop")
                                    }
                                };
                                dump_kad_udp_packet(
                                    "recv",
                                    from,
                                    &data,
                                    &plain,
                                    KadUdpDumpSummary {
                                        protocol: plain.first().copied().unwrap_or_default(),
                                        opcode: Some(response_opcode),
                                        opcode_name: Some(opcode_name(response_opcode)),
                                        raw_obfuscated: was_obfuscated,
                                        transport_mode: Some(inbound_transport_mode(
                                            was_obfuscated,
                                            receiver_verify_key_valid,
                                        )),
                                        requested_obfuscation: None,
                                        receiver_verify_key: None,
                                        sender_verify_key,
                                        receiver_verify_key_valid: Some(receiver_verify_key_valid),
                                        tracked_request_opcode: None,
                                        drop_reason,
                                        tracker_bucket: Some(bucket.label()),
                                        tracker_action: Some(decision.action.label()),
                                        tracker_observed_packets: Some(decision.observed_packets),
                                        tracker_max_packets: Some(decision.max_packets),
                                    },
                                );
                                warn!(
                                    "tracker-dropping {} opcode={} bucket={} action={} observed_packets={} max_packets={} window_ms={}",
                                    from.ip(),
                                    opcode_name(response_opcode),
                                    bucket.label(),
                                    decision.action.label(),
                                    decision.observed_packets,
                                    decision.max_packets,
                                    decision.window.as_millis(),
                                );
                                // bad_peer: the per-bucket anti-flood token limiter
                                // dropped this packet (uniform-diagnostics-v2 §3.4).
                                // repeatCount = packets observed in the window;
                                // windowSeconds = the limiter window.
                                let (bad_event, bad_behavior, bad_severity) = if matches!(
                                    decision.action,
                                    PacketTrackerAction::MassiveDrop
                                ) {
                                    ("anti_flood_ban", "anti_flood_ban", "high")
                                } else {
                                    ("anti_flood_drop", "anti_flood_drop", "medium")
                                };
                                crate::diag_event::bad_peer_kad_drop(
                                    bad_event,
                                    bad_severity,
                                    bad_behavior,
                                    decision.action.label(),
                                    from,
                                    decision.observed_packets,
                                    decision.window.as_secs(),
                                );
                                if matches!(decision.action, PacketTrackerAction::MassiveDrop)
                                    && let Some(handler) = &inner.massive_flood_handler
                                {
                                    handler(from);
                                }
                                continue;
                            }
                        }

                        let matched = {
                            let mut pending = inner.pending.lock().unwrap();
                            let exact_match_id = pending
                                .iter()
                                .filter(|(_, e)| {
                                    e.remote_addr == from && e.expected_opcode == response_opcode
                                })
                                .min_by_key(|(_, e)| e.created_at)
                                .map(|(id, _)| *id);

                            let ip_only_match_id = exact_match_id.or_else(|| {
                                pending
                                    .iter()
                                    .filter(|(_, e)| {
                                        e.remote_addr.ip() == from.ip()
                                            && e.expected_opcode == response_opcode
                                    })
                                    .min_by_key(|(_, e)| e.created_at)
                                    .map(|(id, _)| *id)
                            });

                            if let Some(id) = ip_only_match_id {
                                let entry = pending.remove(&id).unwrap();
                                let age_ms = entry.created_at.elapsed().as_millis();
                                let matched_by_ip_only = entry.remote_addr != from;
                                debug!(
                                    "matched pending response: opcode=0x{:02X} from={}",
                                    response_opcode, from
                                );
                                if is_publish_opcode(entry.request_opcode)
                                    || is_publish_opcode(response_opcode)
                                {
                                    debug!(
                                        "kad publish pending match pending_id={} request_opcode={} response_opcode={} from={} age_ms={}",
                                        id,
                                        opcode_name(entry.request_opcode),
                                        opcode_name(response_opcode),
                                        from,
                                        age_ms,
                                    );
                                }
                                let _ = entry.tx.send(packet.clone());
                                Some((id, age_ms, entry.request_opcode, matched_by_ip_only))
                            } else {
                                None
                            }
                        };

                        let tracked_request_opcode = tracked_request_opcode_for_response(
                            &inner.outbound_tracker,
                            from.ip(),
                            response_opcode,
                        );
                        let dump_request_opcode = matched
                            .map(|(_, _, request_opcode, _)| request_opcode)
                            .or(tracked_request_opcode);

                        let mut dump_summary = KadUdpDumpSummary {
                            protocol: plain.first().copied().unwrap_or_default(),
                            opcode: Some(response_opcode),
                            opcode_name: Some(opcode_name(response_opcode)),
                            raw_obfuscated: was_obfuscated,
                            transport_mode: Some(inbound_transport_mode(
                                was_obfuscated,
                                receiver_verify_key_valid,
                            )),
                            requested_obfuscation: None,
                            receiver_verify_key: None,
                            sender_verify_key,
                            receiver_verify_key_valid: Some(receiver_verify_key_valid),
                            tracked_request_opcode: dump_request_opcode.map(opcode_name),
                            drop_reason: None,
                            tracker_bucket: inbound.tracker_bucket.map(PacketTrackerBucket::label),
                            tracker_action: inbound.tracker_bucket.map(|_| "allow"),
                            tracker_observed_packets: None,
                            tracker_max_packets: None,
                        };

                        if is_publish_opcode(response_opcode) {
                            debug!(
                                "kad publish recv opcode={} from={} matched_pending={} matched_pending_id={} matched_age_ms={} matched_request_opcode={} matched_by_ip_only={} tracked_by_ip={} tracked_request_opcode={} obfuscated={} sender_verify_key={}",
                                opcode_name(response_opcode),
                                from,
                                matched.is_some(),
                                matched.map(|(id, _, _, _)| id).unwrap_or_default(),
                                matched.map(|(_, age_ms, _, _)| age_ms).unwrap_or_default(),
                                matched
                                    .map(|(_, _, request_opcode, _)| opcode_name(request_opcode))
                                    .unwrap_or("-"),
                                matched
                                    .map(|(_, _, _, matched_by_ip_only)| matched_by_ip_only)
                                    .unwrap_or(false),
                                tracked_request_opcode.is_some(),
                                tracked_request_opcode.map(opcode_name).unwrap_or("-"),
                                was_obfuscated,
                                sender_verify_key.unwrap_or_default(),
                            );
                        }

                        if matched.is_none() {
                            if is_tracked_response_opcode(response_opcode)
                                && tracked_request_opcode.is_none()
                            {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_dropped_unrequested(response_opcode);
                                dump_summary.drop_reason = Some("unrequested_response");
                                dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
                                debug!(
                                    "kad recv dropping-unrequested-response opcode={} from={} obfuscated={} sender_verify_key={}",
                                    opcode_name(response_opcode),
                                    from,
                                    was_obfuscated,
                                    sender_verify_key.unwrap_or_default(),
                                );
                                continue;
                            }
                            if is_tracked_response_opcode(response_opcode) {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_matched_tracked(response_opcode);
                            } else {
                                inner
                                    .observability
                                    .lock()
                                    .unwrap()
                                    .record_response_accepted_unsolicited(response_opcode);
                            }
                            dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
                            if should_log_unsolicited_opcode(response_opcode) {
                                debug!(
                                    "kad recv unsolicited opcode={} from={} obfuscated={} sender_verify_key={} tracked_request_opcode={}",
                                    opcode_name(response_opcode),
                                    from,
                                    was_obfuscated,
                                    sender_verify_key.unwrap_or_default(),
                                    tracked_request_opcode.map(opcode_name).unwrap_or("-"),
                                );
                            }
                            debug!(
                                "unsolicited packet: opcode=0x{:02X} from={}",
                                response_opcode, from
                            );
                            let _ = inner.unsolicited_tx.send(ReceivedKadPacket {
                                packet,
                                from,
                                was_obfuscated,
                                sender_verify_key,
                                receiver_verify_key_valid,
                            });
                        } else {
                            inner
                                .observability
                                .lock()
                                .unwrap()
                                .record_response_matched_pending(response_opcode);
                            dump_kad_udp_packet("recv", from, &data, &plain, dump_summary);
                        }
                    }
                    Err(e) => {
                        if matches!(&e, NetError::Io(io_err) if io_err.raw_os_error() == Some(10054))
                        {
                            debug!(
                                "ignoring transient Windows UDP reset while receiving: {}",
                                e
                            );
                        } else {
                            error!("transport recv error: {}", e);
                        }
                        if matches!(e, NetError::ChannelClosed) {
                            break;
                        }
                    }
                }
            }
        })
    }
}

/// Whether `ip` is a LAN/local address exempt from the public-network anti-flood
/// guard (loopback, RFC1918 private, link-local, or unspecified). On a single
/// host all local Kad nodes share one loopback IP, so per-IP throttling/banning
/// must not apply to them; only public peers are flood-tracked.
fn is_lan_ip(ip: std::net::IpAddr) -> bool {
    // IPv4-only client: a non-IPv4 source (never expected) is treated as public
    // and stays flood-tracked.
    if let std::net::IpAddr::V4(v4) = ip {
        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
    } else {
        false
    }
}

#[cfg(test)]
mod lan_exempt_tests {
    use super::is_lan_ip;
    use std::net::IpAddr;

    #[test]
    fn loopback_and_private_are_lan_public_is_not() {
        assert!(is_lan_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_lan_ip("192.168.1.10".parse::<IpAddr>().unwrap()));
        assert!(is_lan_ip("10.0.0.5".parse::<IpAddr>().unwrap()));
        assert!(is_lan_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
        assert!(!is_lan_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_lan_ip("45.82.80.155".parse::<IpAddr>().unwrap()));
    }
}
