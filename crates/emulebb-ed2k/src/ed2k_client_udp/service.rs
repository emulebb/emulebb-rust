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

use super::ClientUdpDatagram;
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
    /// An inbound `OP_REASKCALLBACKUDP` — a downloader that cannot reach a
    /// firewalled source over client UDP asked us (as the source's Kad buddy) to
    /// relay its reask. The caller verifies the leading buddy-id against the
    /// inbound buddy it serves and relays an `OP_REASKCALLBACKTCP` down the held
    /// buddy socket (mirrors `ClientUDPSocket.cpp` `OP_REASKCALLBACKUDP`). `from`
    /// is the requester's UDP endpoint, written into the relayed frame so the
    /// firewalled source answers it over UDP.
    BuddyRelay {
        callback: super::codec::ReaskCallbackUdp,
        from: SocketAddr,
    },
    /// An inbound `OP_DIRECTCALLBACKREQ` — a peer that cannot reach us over TCP
    /// (we are the firewalled LowID side that advertised direct UDP callback) asks
    /// us to connect out to it. The caller verifies it is actually the firewalled
    /// side it advertised and TCP-connects out to `(from.ip, req.tcp_port)`,
    /// mirroring `ClientUDPSocket.cpp` `OP_DIRECTCALLBACKREQ` ->
    /// `TryToConnectOrDelete`. `from` is the requester's UDP source IP (the TCP
    /// port to connect to is in `req`).
    DirectCallbackReq {
        req: super::codec::DirectCallbackReq,
        from: SocketAddr,
    },
    /// Not a reask addressed to us (junk, a Kad packet, an unsolicited reply, or
    /// an unknown source) — the caller ignores it.
    Ignored,
}

/// Per-tick work the caller must perform: datagrams to send, and sources whose
/// reask timed out (for TCP-fallback reasks the caller drives separately).
#[derive(Debug, Default)]
pub(crate) struct ReaskTickOutput {
    /// `(destination, datagram)` reask pings to send via the shared socket.
    pub send: Vec<(SocketAddr, ClientUdpDatagram)>,
    /// Endpoints whose UDP reask timed out and the resulting action
    /// (`RetryUdp`/`RetryTcp`).
    pub timed_out: Vec<(SocketAddr, ReaskAction)>,
}

type ReaskAdmitFn<'a> = dyn Fn(&Ed2kHash, usize) -> bool + 'a;

/// Global pacing/round-robin control for a reask tick, supplied by the caller
/// (which wraps the shared download coordinator). Keeps the service I/O-free and
/// the coordinator the single decision-maker: the service only rotates the file
/// visit order and asks `admit` whether a file may emit reask pings this tick.
pub(crate) struct ReaskTickPacing<'a> {
    /// Round-robin start offset into the (sorted) file list for fairness
    /// (eMule `CDownloadQueue::Process` `m_udcounter` rotation).
    pub rotate_offset: usize,
    /// Whether `file_hash` (currently holding `source_count` reask sources) may
    /// emit reask pings this tick: the per-file UDP source cap
    /// (`GetMaxSourcePerFileUDP > GetSourceCount`) AND the global reask pacing
    /// floor. `None` = admit every file (the unbounded default tick).
    pub admit: Option<&'a ReaskAdmitFn<'a>>,
}

impl ReaskTickPacing<'_> {
    /// The unbounded pacing used by the plain [`ReaskService::tick`]: no
    /// rotation, every file admitted (preserves the prior behavior exactly).
    pub(crate) fn unbounded() -> Self {
        Self {
            rotate_offset: 0,
            admit: None,
        }
    }

    fn admit(&self, file_hash: &Ed2kHash, source_count: usize) -> bool {
        self.admit
            .is_none_or(|admit| admit(file_hash, source_count))
    }
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
        self.per_file.entry(file_hash).or_default().insert(source);
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

    /// Flag a registered source as No Needed Parts, routed by endpoint (a TCP
    /// session just learned the peer serves no part we still need): its reask
    /// cadence doubles to `FILEREASKTIME * 2` (oracle `DS_NONEEDEDPARTS` +
    /// `GetTimeUntilReask`, DownloadClient.cpp:2425-2431). Returns whether a
    /// source was present at that endpoint.
    pub(crate) fn mark_no_needed_parts(&mut self, ip: Ipv4Addr, udp_port: u16, now: Instant) -> bool {
        let Some(file_hash) = self.endpoint_index.get(&(ip, udp_port)) else {
            return false;
        };
        self.per_file
            .get_mut(file_hash)
            .is_some_and(|set| set.mark_no_needed_parts(ip, udp_port, now))
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
            // Buddy relay (we are the source's buddy): hand the decoded request +
            // requester endpoint back so the caller can match the buddy-id against
            // its served inbound buddy and relay it over the held buddy socket.
            InboundReaskMessage::CallbackUdp(callback) => {
                return ReaskInboundOutcome::BuddyRelay { callback, from };
            }
            // Direct UDP callback request (we are the firewalled LowID source the
            // requester cannot reach over TCP): hand it back so the caller can
            // verify the firewalled gate and connect out to the requester.
            InboundReaskMessage::DirectCallbackReq(req) => {
                return ReaskInboundOutcome::DirectCallbackReq { req, from };
            }
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
        info_for: impl FnMut(&Ed2kHash) -> TransferReaskInfo,
    ) -> ReaskTickOutput {
        self.tick_paced(now, reply_timeout, info_for, &ReaskTickPacing::unbounded())
    }

    /// Like [`tick`], but globally paces + round-robins reask sends across files
    /// (eMule `CDownloadQueue::Process` `m_udcounter` rotation +
    /// `SendNextUDPPacket`): files are visited in a rotated order seeded by
    /// `pacing.rotate_offset` for fairness, and a file emits reask pings only
    /// when `pacing.admit(file_hash, source_count)` allows it (the per-file UDP
    /// source cap + global pacing floor live in the coordinator the caller
    /// wraps). Timed-out reask accounting is never paced (it is bookkeeping, not
    /// new outbound load).
    pub(crate) fn tick_paced(
        &mut self,
        now: Instant,
        reply_timeout: Duration,
        mut info_for: impl FnMut(&Ed2kHash) -> TransferReaskInfo,
        pacing: &ReaskTickPacing<'_>,
    ) -> ReaskTickOutput {
        let mut out = ReaskTickOutput::default();
        // Deterministic, rotated file order so no file is starved when the global
        // pacing floor admits only a subset per tick.
        let mut file_hashes: Vec<Ed2kHash> = self.per_file.keys().copied().collect();
        file_hashes.sort_unstable_by_key(|hash| hash.0);
        let len = file_hashes.len();
        for step in 0..len {
            let index = (pacing.rotate_offset.wrapping_add(step)) % len;
            let file_hash = file_hashes[index];
            let Some(set) = self.per_file.get_mut(&file_hash) else {
                continue;
            };
            // Timed-out reasks first (so a due+timed-out source reschedules cleanly).
            for ((ip, port), action) in set.drain_timeouts(now, reply_timeout) {
                out.timed_out
                    .push((SocketAddr::new(ip.into(), port), action));
            }
            // Global pacing / per-file UDP cap gate.
            if !pacing.admit(&file_hash, set.len()) {
                continue;
            }
            let info = info_for(&file_hash);
            for (dest, datagram) in set.due_datagrams(
                now,
                info.part_status.as_deref(),
                info.complete_source_count,
                self.public_ip.octets(),
            ) {
                out.send.push((dest, datagram));
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
mod tests;
