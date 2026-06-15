//! Reask service — the integration-logic layer that ties the per-file
//! [`ReaskSourceSet`]s together with a global `(ip,udp_port)` routing index
//! (mirroring eMule's `GetDownloadClientByIP_UDP`: inbound replies correlate by
//! endpoint only, since `OP_REASKACK`/`OP_QUEUEFULL`/`OP_FILENOTFOUND` carry no
//! file hash). `docs/design/udp-source-reask.md` §4.2-§4.5.
//!
//! Deliberately **sync and I/O-free**: it parses inbound datagrams and emits the
//! datagrams to send, but the core download runtime performs all socket I/O (via
//! `RpcManager::send_raw_datagram`) and answers inbound reasks (where the
//! upload-queue state lives). This keeps the whole reask decision surface
//! unit-testable without a runtime; the gated core wiring stays thin.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use emulebb_kad_proto::Ed2kHash;

use super::dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};
use super::source_set::ReaskSourceSet;
use super::state::{ReaskAction, ReaskReply, ReaskSource};
use crate::reachability::ExternalReachability;

/// What the caller must do after [`ReaskService::handle_inbound`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReaskInboundOutcome {
    /// A downloader-side reply was routed into our source state. The action tells
    /// the caller whether to also reask over TCP / drop the source / re-engage on a
    /// low rank; `file_hash`/`endpoint` identify the source so the caller can emit a
    /// loop->core event. No datagram reply is owed.
    RoutedReply {
        file_hash: Ed2kHash,
        endpoint: (Ipv4Addr, u16),
        action: ReaskAction,
    },
    /// An inbound `OP_REASKFILEPING` from a peer queued on us — the caller answers
    /// it via `answer_inbound_reask` + an outbound builder (it holds the
    /// upload-queue state this service intentionally does not).
    AnswerNeeded {
        ping: super::codec::ReaskFilePing,
        from: SocketAddr,
    },
    /// Not a reask addressed to us (junk, a Kad packet, an unsolicited reply, an
    /// unknown source, or a Phase-2 buddy relay) — the caller ignores it.
    Ignored,
}

/// Per-tick work the caller must perform: datagrams to send, and sources whose
/// reask timed out (for TCP-fallback reasks the caller drives separately).
#[derive(Debug, Default)]
pub(crate) struct ReaskTickOutput {
    /// `(destination, datagram)` reask pings to send via the shared socket.
    pub send: Vec<(SocketAddr, Vec<u8>)>,
    /// Endpoints whose UDP reask timed out and the resulting action
    /// (`RetryUdp`/`RetryTcp`).
    pub timed_out: Vec<(SocketAddr, ReaskAction)>,
}

/// Transfer-level inputs the tick needs for one file's reask pings.
#[derive(Debug, Clone)]
pub(crate) struct TransferReaskInfo {
    /// Our part availability for the file (`None` = no partfile / complete).
    pub part_status: Option<Vec<bool>>,
    /// Our reported complete-source count for the file.
    pub complete_source_count: u16,
}

/// Owns the downloader-side reask state across all transfers.
#[derive(Debug, Default)]
pub(crate) struct ReaskService {
    our_user_hash: [u8; 16],
    our_udp_version: u8,
    /// Our learned public IP, read dynamically (it is set after connect, at the
    /// server `OP_IDCHANGE`) for the outbound obfuscation key.
    public_ip: ExternalReachability,
    /// Global `(ip,udp_port)` -> file hash routing for inbound replies.
    endpoint_index: HashMap<(Ipv4Addr, u16), Ed2kHash>,
    /// Per-file detached reask sources.
    per_file: HashMap<Ed2kHash, ReaskSourceSet>,
}

impl ReaskService {
    pub(crate) fn new(
        our_user_hash: [u8; 16],
        our_udp_version: u8,
        public_ip: ExternalReachability,
    ) -> Self {
        Self {
            our_user_hash,
            our_udp_version,
            public_ip,
            endpoint_index: HashMap::new(),
            per_file: HashMap::new(),
        }
    }

    /// Register a queued source in detached reask state for `file_hash` (the
    /// §4.1 transition; caller has already checked UDP-eligibility).
    pub(crate) fn register_source(&mut self, file_hash: Ed2kHash, source: ReaskSource) {
        self.endpoint_index.insert(source.endpoint, file_hash);
        self.per_file
            .entry(file_hash)
            .or_default()
            .insert(source);
    }

    /// Drop a source (e.g. the transfer completed or no longer needs it).
    /// Returns `true` if a source was actually present and removed, so the caller
    /// can release the held UDP lease only for endpoints the loop really owned.
    pub(crate) fn remove_source(&mut self, ip: Ipv4Addr, udp_port: u16) -> bool {
        if let Some(file_hash) = self.endpoint_index.remove(&(ip, udp_port)) {
            if let Some(set) = self.per_file.get_mut(&file_hash) {
                set.remove(ip, udp_port);
            }
            true
        } else {
            false
        }
    }

    /// Route an inbound datagram. Downloader replies are applied to the matching
    /// source (correlated by endpoint); an inbound reask ping is handed back for
    /// the caller to answer.
    pub(crate) fn handle_inbound(
        &mut self,
        datagram: &[u8],
        from: SocketAddr,
        now: Instant,
    ) -> ReaskInboundOutcome {
        let SocketAddr::V4(v4) = from else {
            return ReaskInboundOutcome::Ignored; // IPv4-only client
        };
        let ip = *v4.ip();
        let port = v4.port();
        let msg = match parse_inbound_reask_datagram(
            datagram,
            ip.octets(),
            &self.our_user_hash,
            self.our_udp_version,
        ) {
            Some(msg) => msg,
            None => return ReaskInboundOutcome::Ignored,
        };

        let reply = match msg {
            InboundReaskMessage::FilePing(ping) => {
                return ReaskInboundOutcome::AnswerNeeded { ping, from };
            }
            InboundReaskMessage::Ack(ack) => ReaskReply::Ack {
                rank: ack.queue_position,
            },
            InboundReaskMessage::QueueFull => ReaskReply::QueueFull,
            InboundReaskMessage::FileNotFound => ReaskReply::FileNotFound,
            // Phase-2 buddy relay (we are the buddy) is not handled yet.
            InboundReaskMessage::CallbackUdp(_) => return ReaskInboundOutcome::Ignored,
        };

        // Correlate the reply to a source by endpoint, then by its file.
        let Some(file_hash) = self.endpoint_index.get(&(ip, port)).copied() else {
            return ReaskInboundOutcome::Ignored;
        };
        let Some(set) = self.per_file.get_mut(&file_hash) else {
            return ReaskInboundOutcome::Ignored;
        };
        match set.apply_reply(ip, port, reply, now) {
            Some(action) => {
                if matches!(action, ReaskAction::DropSource) {
                    self.endpoint_index.remove(&(ip, port));
                }
                ReaskInboundOutcome::RoutedReply {
                    file_hash,
                    endpoint: (ip, port),
                    action,
                }
            }
            None => ReaskInboundOutcome::Ignored, // unsolicited (failed the pending gate)
        }
    }

    /// Produce the per-tick work: due reask pings (using each file's transfer
    /// info from `info_for`) and timed-out reasks.
    pub(crate) fn tick(
        &mut self,
        now: Instant,
        reply_timeout: Duration,
        mut info_for: impl FnMut(&Ed2kHash) -> TransferReaskInfo,
    ) -> ReaskTickOutput {
        let mut out = ReaskTickOutput::default();
        for (file_hash, set) in &mut self.per_file {
            // Timed-out reasks first (so a due+timed-out source reschedules cleanly).
            for ((ip, port), action) in set.drain_timeouts(now, reply_timeout) {
                out.timed_out
                    .push((SocketAddr::new(ip.into(), port), action));
            }
            let info = info_for(file_hash);
            for ((ip, port), datagram) in set.due_datagrams(
                now,
                info.part_status.as_deref(),
                info.complete_source_count,
                self.our_udp_version,
                self.public_ip.octets(),
            ) {
                out.send.push((SocketAddr::new(ip.into(), port), datagram));
            }
        }
        out
    }

    pub(crate) fn source_count(&self) -> usize {
        self.per_file.values().map(ReaskSourceSet::len).sum()
    }

    /// File hashes that currently have at least one detached reask source, so the
    /// tick caller can pre-fetch each file's [`TransferReaskInfo`].
    pub(crate) fn registered_file_hashes(&self) -> Vec<Ed2kHash> {
        self.per_file
            .iter()
            .filter(|(_, set)| !set.is_empty())
            .map(|(hash, _)| *hash)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed2k_client_udp::outbound::{OutboundReaskTarget, build_reask_ack_datagram};

    const OUR_HASH: [u8; 16] = [0x10; 16];
    const PEER_HASH: [u8; 16] = [0x55; 16];

    fn file_hash() -> Ed2kHash {
        Ed2kHash::from_bytes([0xAB; 16])
    }

    fn peer_addr() -> SocketAddr {
        "198.51.100.7:4672".parse().unwrap()
    }

    fn peer_v4() -> (Ipv4Addr, u16) {
        (Ipv4Addr::new(198, 51, 100, 7), 4672)
    }

    fn service() -> ReaskService {
        let public_ip = ExternalReachability::new();
        public_ip.set(Ipv4Addr::new(203, 0, 113, 9));
        ReaskService::new(OUR_HASH, 4, public_ip)
    }

    fn register(svc: &mut ReaskService, now: Instant) {
        let src = ReaskSource::new(peer_v4(), file_hash(), 4, now)
            .with_obfuscation(PEER_HASH, true);
        svc.register_source(file_hash(), src);
    }

    #[test]
    fn tick_emits_due_ping_then_routes_the_ack() {
        let now = Instant::now();
        let mut svc = service();
        register(&mut svc, now);

        // Tick produces one due reask ping to the peer.
        let out = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
            part_status: Some(vec![true, false]),
            complete_source_count: 1,
        });
        assert_eq!(out.send.len(), 1);
        assert_eq!(out.send[0].0, peer_addr());

        // The peer answers OP_REASKACK with our rank; the service routes it.
        let ack = build_reask_ack_datagram(
            None,
            12,
            4,
            &OutboundReaskTarget {
                // The peer keys on our hash + its own IP (the sender IP we see).
                dest_user_hash: OUR_HASH,
                our_public_ip: peer_v4().0.octets(),
                obfuscate: true,
            },
        );
        let outcome = svc.handle_inbound(&ack, peer_addr(), now);
        assert_eq!(
            outcome,
            ReaskInboundOutcome::RoutedReply {
                file_hash: file_hash(),
                endpoint: peer_v4(),
                action: ReaskAction::UpdatedRank(12),
            }
        );
    }

    #[test]
    fn unsolicited_reply_without_pending_is_ignored() {
        let now = Instant::now();
        let mut svc = service();
        register(&mut svc, now);
        // No tick (no outstanding reask) -> an ack fails the pending gate.
        let ack = build_reask_ack_datagram(
            None,
            1,
            4,
            &OutboundReaskTarget {
                dest_user_hash: OUR_HASH,
                our_public_ip: peer_v4().0.octets(),
                obfuscate: true,
            },
        );
        assert_eq!(
            svc.handle_inbound(&ack, peer_addr(), now),
            ReaskInboundOutcome::Ignored
        );
    }

    #[test]
    fn inbound_file_ping_is_handed_back_for_the_caller_to_answer() {
        use crate::ed2k_client_udp::outbound::build_reask_file_ping_datagram;
        let now = Instant::now();
        let mut svc = service();
        // A peer reasks us (we are the uploader). It keys on OUR hash + its IP.
        let ping = build_reask_file_ping_datagram(
            &file_hash(),
            None,
            0,
            4,
            &OutboundReaskTarget {
                dest_user_hash: OUR_HASH,
                our_public_ip: peer_v4().0.octets(),
                obfuscate: true,
            },
        );
        match svc.handle_inbound(&ping, peer_addr(), now) {
            ReaskInboundOutcome::AnswerNeeded { ping, from } => {
                assert_eq!(ping.file_hash, file_hash());
                assert_eq!(from, peer_addr());
            }
            other => panic!("expected AnswerNeeded, got {other:?}"),
        }
    }

    #[test]
    fn file_not_found_drops_source_and_clears_routing() {
        let now = Instant::now();
        let mut svc = service();
        register(&mut svc, now);
        // Open the pending gate.
        let _ = svc.tick(now, Duration::from_secs(20), |_| TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        });
        // FNF (plaintext OP_EMULEPROT + opcode, empty body).
        let fnf = vec![0xC5u8, 0x92];
        let outcome = svc.handle_inbound(&fnf, peer_addr(), now);
        assert_eq!(
            outcome,
            ReaskInboundOutcome::RoutedReply {
                file_hash: file_hash(),
                endpoint: peer_v4(),
                action: ReaskAction::DropSource,
            }
        );
        assert_eq!(svc.source_count(), 0);
        // Routing for the endpoint is gone.
        let again = svc.handle_inbound(&fnf, peer_addr(), now);
        assert_eq!(again, ReaskInboundOutcome::Ignored);
    }

    #[test]
    fn junk_and_non_ipv4_are_ignored() {
        let now = Instant::now();
        let mut svc = service();
        register(&mut svc, now);
        assert_eq!(
            svc.handle_inbound(&[0x42; 30], peer_addr(), now),
            ReaskInboundOutcome::Ignored
        );
        let v6: SocketAddr = "[2001:db8::1]:4672".parse().unwrap();
        assert_eq!(
            svc.handle_inbound(&[0xC5, 0x93], v6, now),
            ReaskInboundOutcome::Ignored
        );
    }

    #[test]
    fn timed_out_reask_surfaces_in_tick_output() {
        let now = Instant::now();
        let timeout = Duration::from_secs(20);
        let mut svc = service();
        register(&mut svc, now);
        // First tick sends the ping (opens pending).
        let _ = svc.tick(now, timeout, |_| TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        });
        // Later tick past the timeout drains it as a failure.
        let later = now + timeout + Duration::from_secs(1);
        let out = svc.tick(later, timeout, |_| TransferReaskInfo {
            part_status: None,
            complete_source_count: 0,
        });
        assert_eq!(out.timed_out.len(), 1);
        assert_eq!(out.timed_out[0].0, peer_addr());
    }
}
