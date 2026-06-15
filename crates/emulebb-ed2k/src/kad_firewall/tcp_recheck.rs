//! TCP firewall recheck verdict layer for [`KadFirewallState`].
//!
//! eMule rechecks whether its eD2k/Kad TCP port is reachable by asking open Kad
//! v6+ helpers to TCP-connect back to it (`KADEMLIA2_FIREWALLED2_REQ`). A helper
//! that connects back signals `OP_KAD_FWTCPCHECK_ACK` (oracle
//! `CPrefs::IncFirewalled`); two such open acks settle the verdict as open
//! (oracle `GetFirewalled`: `m_uFirewalled >= 2`). Otherwise, once the round
//! ends, the verdict is firewalled. A short TTL list of probed helper IPs
//! authenticates inbound acks / `FIREWALLED_RES` (oracle
//! `CClientList::AddKadFirewallRequest` / `IsKadFirewallCheckIP`).
//!
//! This lives in a child module so it can extend the parent `KadFirewallState`
//! (accessing its private fields) while keeping each file within budget.

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{DateTime, Duration as ChronoDuration, Utc};

use super::{KadFirewallState, TcpFirewallCheckRound};

/// Open-result threshold for the TCP firewall verdict (oracle `GetFirewalled`:
/// `m_uFirewalled >= 2` means open). Two independent helper TCP connect-backs
/// (signalled by `OP_KAD_FWTCPCHECK_ACK`) must succeed before we declare the
/// eD2k/Kad TCP port open.
const TCP_FIREWALL_OPEN_THRESHOLD: u8 = 2;
/// How long a probed helper IP stays an accepted firewall-check responder
/// (oracle `CClientList::AddKadFirewallRequest` / `IsKadFirewallCheckIP`,
/// `SEC2MS(180)`): inbound `OP_KAD_FWTCPCHECK_ACK` / `KADEMLIA_FIREWALLED_RES`
/// from an IP we did not probe within this window are rejected.
const TCP_FIREWALL_CHECK_IP_TTL_SECS: i64 = 180;

impl KadFirewallState {
    /// Start a fresh TCP firewall recheck round (oracle `SetFirewalled` +
    /// `SetRecheckIP`): snapshot the previous verdict, reset the open-ack count,
    /// and open a new 4-helper budget round. Idempotent while a round is active.
    pub fn begin_tcp_recheck(&mut self, started_at: DateTime<Utc>) {
        if self.active_tcp_round.is_some() {
            return;
        }
        // Oracle SetFirewalled(): m_bLastFirewallState = (m_uFirewalled < 2).
        self.tcp_firewall_last_state = self.tcp_open_acks < TCP_FIREWALL_OPEN_THRESHOLD;
        self.tcp_open_acks = 0;
        self.tcp_recheck_active = true;
        self.last_tcp_check_started_at = Some(started_at);
        self.active_tcp_round = Some(TcpFirewallCheckRound {
            active_helpers: HashSet::new(),
            completed_checks: 0,
        });
    }

    /// Whether a TCP firewall recheck round is currently in flight.
    #[must_use]
    pub fn tcp_recheck_in_progress(&self) -> bool {
        self.active_tcp_round.is_some()
    }

    /// Remember an IP we just sent a `KADEMLIA2_FIREWALLED2_REQ` to, so its
    /// later TCP connect-back ack / `FIREWALLED_RES` is accepted (oracle
    /// `AddKadFirewallRequest`). Also prunes entries older than the 180s TTL.
    pub fn add_tcp_firewall_check_ip(&mut self, ip: IpAddr, now: DateTime<Utc>) {
        self.prune_tcp_firewall_check_ips(now);
        self.tcp_firewall_check_ips.insert(ip, now);
    }

    /// Whether `ip` was probed for a firewall check within the TTL window
    /// (oracle `IsKadFirewallCheckIP`).
    #[must_use]
    pub fn is_tcp_firewall_check_ip(&self, ip: IpAddr, now: DateTime<Utc>) -> bool {
        self.tcp_firewall_check_ips.get(&ip).is_some_and(|probed_at| {
            now.signed_duration_since(*probed_at)
                < ChronoDuration::seconds(TCP_FIREWALL_CHECK_IP_TTL_SECS)
        })
    }

    fn prune_tcp_firewall_check_ips(&mut self, now: DateTime<Utc>) {
        let ttl = ChronoDuration::seconds(TCP_FIREWALL_CHECK_IP_TTL_SECS);
        self.tcp_firewall_check_ips
            .retain(|_, probed_at| now.signed_duration_since(*probed_at) < ttl);
    }

    /// Record an inbound `OP_KAD_FWTCPCHECK_ACK` from a helper that completed a
    /// TCP connect-back to our listener (oracle ListenSocket.cpp ->
    /// `IncFirewalled`). Only counts when the source IP was actually probed.
    /// Returns `true` when the ack was accepted.
    pub fn record_tcp_open_ack(&mut self, ip: IpAddr, now: DateTime<Utc>) -> bool {
        if !self.is_tcp_firewall_check_ip(ip, now) {
            return false;
        }
        self.tcp_open_acks = self.tcp_open_acks.saturating_add(1);
        self.last_helper_ip = Some(ip.to_string());
        self.last_tcp_check_completed_at = Some(now);
        // Reaching the open threshold settles the verdict immediately (oracle
        // GetFirewalled returns open as soon as m_uFirewalled >= 2).
        if self.tcp_open_acks >= TCP_FIREWALL_OPEN_THRESHOLD {
            self.tcp_firewalled_verdict = Some(false);
            self.tcp_recheck_active = false;
            self.active_tcp_round = None;
            self.last_error = None;
        }
        true
    }

    /// The current TCP-firewalled verdict (oracle `CPrefs::GetFirewalled`),
    /// or `None` when no recheck has ever produced one (so callers fall back to
    /// the eD2k server / listener signal).
    ///
    /// Open as soon as the open-ack threshold is reached; otherwise, while a
    /// recheck is in flight, report the snapshot taken when it started; once a
    /// recheck has completed it reports the finalized verdict.
    #[must_use]
    pub fn tcp_firewalled(&self) -> Option<bool> {
        if self.tcp_open_acks >= TCP_FIREWALL_OPEN_THRESHOLD {
            return Some(false);
        }
        if self.active_tcp_round.is_some() {
            // Recheck in progress: report the snapshot only if we already had a
            // verdict; otherwise stay unknown so other signals can decide.
            return self
                .tcp_firewalled_verdict
                .map(|_| self.tcp_firewall_last_state);
        }
        self.tcp_firewalled_verdict
    }

    /// Finalize the verdict for a recheck round that ended without reaching the
    /// open threshold: the node is TCP-firewalled. No-op if the threshold was
    /// already reached or no round is in flight.
    pub fn finish_tcp_recheck(&mut self, completed_at: DateTime<Utc>) {
        if self.tcp_open_acks >= TCP_FIREWALL_OPEN_THRESHOLD {
            return;
        }
        if self.active_tcp_round.is_none() && self.last_tcp_check_started_at.is_none() {
            return;
        }
        self.tcp_firewalled_verdict = Some(true);
        self.tcp_recheck_active = false;
        self.active_tcp_round = None;
        self.last_tcp_check_completed_at = Some(completed_at);
    }
}
