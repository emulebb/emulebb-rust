//! Minimal Kad UDP firewall-check state tracking.
//!
//! The oracle verifies UDP reachability by asking a small set of helper peers
//! to send `KADEMLIA2_FIREWALLUDP` packets back to us. This module keeps just
//! enough state to correlate those helper packets with an active verification
//! round and derive an "open", "firewalled", or "unverified" result.
//!
//! The same state object also tracks the oracle's separate TCP-oriented Kad
//! firewall recheck loop. That loop emits `KADEMLIA_FIREWALLED2_REQ` after
//! HELLO exchanges while the local runtime still believes it is TCP
//! firewalled, and it accepts up to four `KADEMLIA_FIREWALLED_RES` replies to
//! converge on the externally observed IP address.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Utc};

/// Snapshot of one completed UDP firewall-check round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFirewallCheckSummary {
    /// Whether at least one helper successfully reached our UDP port.
    pub open: bool,
    /// Number of helper peers that were selected for the round.
    pub helpers_selected: usize,
    /// Number of helper peers whose TCP request could be sent successfully.
    pub helpers_requested: usize,
    /// Number of helper peers that replied with a positive UDP check.
    pub helpers_succeeded: usize,
    /// Number of helper peers whose completed UDP probe produced a negative result.
    pub helpers_failed: usize,
    /// Timestamp when the round started.
    pub started_at: DateTime<Utc>,
    /// Timestamp when the round finished.
    pub completed_at: DateTime<Utc>,
    /// External UDP port the helpers actually observed, when it differs from the
    /// internal port. `None` when the open result came in on the internal port
    /// (or the round did not open). Mirrors the oracle's `SetUseExternKadPort`.
    pub external_udp_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HelperOutcome {
    Pending,
    /// The TCP request could not be sent, so the helper did not actually run the test.
    RequestFailed,
    /// The helper ran the test and explicitly completed it with a negative result.
    TestFailed,
    /// The helper reported a remote-side error; MFC treats this as cancelled.
    RemoteError,
    /// The helper reported an unexpected port; MFC treats this as cancelled.
    WrongPort,
    Succeeded,
}

const TCP_FIREWALL_RECHECK_LIMIT: usize = 4;
const UDP_FIREWALL_CHECK_CLIENTS_TO_ASK: usize = 2;
const EXTERNAL_PORT_DISCOVERY_REPORTERS: usize = 3;
/// Unique helpers that must report the same off-list incoming UDP port before we
/// trust it as our real external port (one report could be a NAT fluke).
const FIREWALL_UDP_PORT_DISCOVERY_REPORTERS: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpFirewallCheckRound {
    started_at: DateTime<Utc>,
    expected_ports: HashSet<u16>,
    helper_outcomes: HashMap<IpAddr, HelperOutcome>,
    /// Off-list incoming ports reported with a positive result, keyed by port to
    /// the unique helper IPs that reported them. A NAT remaps our source UDP port
    /// so the helper observes (and echoes) a port we did not predict; once enough
    /// distinct helpers agree, that port is our real external UDP port.
    discovered_port_reporters: HashMap<u16, HashSet<IpAddr>>,
    /// The off-list port that reached the corroboration threshold, if any.
    discovered_external_udp_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpFirewallCheckRound {
    active_helpers: HashSet<IpAddr>,
    completed_checks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalPortDiscoveryRound {
    reporter_ips: HashSet<IpAddr>,
    reported_ports: Vec<u16>,
}

/// Process-local Kad firewall verification state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KadFirewallState {
    /// Whether we currently have a verified UDP-open result.
    pub udp_open: bool,
    /// Whether the current UDP-open/firewalled status has been verified.
    pub udp_verified: bool,
    /// Timestamp of the most recent UDP firewall-check start.
    pub last_udp_check_started_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent successful UDP firewall-check.
    pub last_udp_check_succeeded_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent failed UDP firewall-check.
    pub last_udp_check_failed_at: Option<DateTime<Utc>>,
    /// Helper IP that last reported a UDP firewall-check result.
    pub last_helper_ip: Option<String>,
    /// UDP port most recently reported by a helper peer.
    pub last_reported_port: Option<u16>,
    /// Last firewall-check error captured by the runtime.
    pub last_error: Option<String>,
    /// Whether the oracle-style TCP firewall/IP recheck loop is currently active.
    pub tcp_recheck_active: bool,
    /// Timestamp of the most recent TCP firewall/IP recheck start.
    pub last_tcp_check_started_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent completed TCP firewall/IP recheck response.
    pub last_tcp_check_completed_at: Option<DateTime<Utc>>,
    /// External IP most recently reported by a `KADEMLIA_FIREWALLED_RES` helper.
    pub last_reported_external_ip: Option<String>,
    /// Timestamp of the most recent external Kad UDP port discovery start.
    pub last_external_port_probe_started_at: Option<DateTime<Utc>>,
    /// Timestamp of the most recent completed external Kad UDP port discovery round.
    pub last_external_port_probe_completed_at: Option<DateTime<Utc>>,
    /// Most recent external Kad UDP port candidate reported by a PONG responder.
    pub last_reported_external_udp_port: Option<u16>,
    /// Whether the most recent completed TCP firewall verdict is "firewalled".
    /// `None` until a verdict has ever been established (no eD2k server and no
    /// Kad recheck completed yet), so callers can fall back to other signals.
    pub tcp_firewalled_verdict: Option<bool>,
    active_round: Option<UdpFirewallCheckRound>,
    active_tcp_round: Option<TcpFirewallCheckRound>,
    active_external_port_discovery: Option<ExternalPortDiscoveryRound>,
    discovered_external_udp_port: Option<u16>,
    /// Recently probed firewall-check helper IPs with their probe time (oracle
    /// `listFirewallCheckRequests`). Used to authenticate inbound TCP-check acks
    /// and `FIREWALLED_RES` replies within `TCP_FIREWALL_CHECK_IP_TTL_SECS`.
    tcp_firewall_check_ips: HashMap<IpAddr, DateTime<Utc>>,
    /// Count of helper TCP connect-backs that succeeded this round (oracle
    /// `m_uFirewalled`); reset when a new recheck starts.
    tcp_open_acks: u8,
    /// Snapshot of the previous firewalled verdict taken when a recheck starts
    /// (oracle `m_bLastFirewallState`), reported while the recheck is in flight.
    tcp_firewall_last_state: bool,
}

/// Result of processing a `KADEMLIA2_FIREWALLUDP` packet for the active round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallUdpPacketOutcome {
    /// The packet completed the round with an "open" result.
    Open(UdpFirewallCheckSummary),
    /// The packet was associated with the active round but did not finish it.
    Recorded,
    /// The packet does not belong to the active round.
    Ignored,
}

/// Result of processing a `KADEMLIA_FIREWALLED_RES` packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewalledResponseOutcome {
    /// The reply was accepted and the TCP recheck loop is still active.
    Recorded,
    /// The reply completed the oracle's four-response recheck window.
    Completed,
    /// The reply did not match any active oracle-style TCP recheck.
    Ignored,
}

/// Result of processing one external Kad UDP port candidate from a PONG reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalPortDiscoveryOutcome {
    /// The candidate was recorded, but more reporter IPs are still needed.
    Recorded,
    /// Two unique reporters agreed on the same external UDP port.
    Resolved(u16),
    /// Three unique reporters disagreed, so the external port is treated as unreliable.
    Unreliable,
    /// The candidate did not apply to an active discovery round.
    Ignored,
}

impl KadFirewallState {
    /// Start one oracle-style external Kad UDP port discovery round.
    ///
    /// The oracle samples up to three unique `KADEMLIA2_PONG` reporters and
    /// accepts the external port once two reporters agree. Otherwise the
    /// external port is treated as unreliable for the current firewall-check
    /// round and helpers should only probe the internal UDP port.
    pub fn begin_external_port_discovery(&mut self, started_at: DateTime<Utc>) {
        self.last_external_port_probe_started_at = Some(started_at);
        self.last_external_port_probe_completed_at = None;
        self.last_reported_external_udp_port = None;
        self.discovered_external_udp_port = None;
        self.active_external_port_discovery = Some(ExternalPortDiscoveryRound {
            reporter_ips: HashSet::new(),
            reported_ports: Vec::new(),
        });
    }

    /// Return whether the current firewall-check round is still waiting for
    /// enough unique PONG reporters to settle the external UDP port.
    #[must_use]
    pub fn needs_external_port_discovery(&self) -> bool {
        self.active_external_port_discovery.is_some()
    }

    /// Record one external UDP port candidate reported by a unique PONG responder.
    pub fn record_external_port_candidate(
        &mut self,
        reporter_ip: IpAddr,
        reported_port: u16,
        observed_at: DateTime<Utc>,
    ) -> ExternalPortDiscoveryOutcome {
        if reported_port == 0 {
            return ExternalPortDiscoveryOutcome::Ignored;
        }
        let Some(round) = &mut self.active_external_port_discovery else {
            return ExternalPortDiscoveryOutcome::Ignored;
        };
        if !round.reporter_ips.insert(reporter_ip) {
            return ExternalPortDiscoveryOutcome::Ignored;
        }

        self.last_helper_ip = Some(reporter_ip.to_string());
        self.last_reported_external_udp_port = Some(reported_port);

        if round.reported_ports.contains(&reported_port) {
            self.discovered_external_udp_port = Some(reported_port);
            self.last_external_port_probe_completed_at = Some(observed_at);
            self.last_error = None;
            self.active_external_port_discovery = None;
            return ExternalPortDiscoveryOutcome::Resolved(reported_port);
        }

        round.reported_ports.push(reported_port);
        if round.reporter_ips.len() >= EXTERNAL_PORT_DISCOVERY_REPORTERS {
            self.discovered_external_udp_port = None;
            self.last_external_port_probe_completed_at = Some(observed_at);
            self.last_error =
                Some("external Kad UDP port discovery returned inconsistent ports".to_string());
            self.active_external_port_discovery = None;
            return ExternalPortDiscoveryOutcome::Unreliable;
        }

        ExternalPortDiscoveryOutcome::Recorded
    }

    /// Finalize one external Kad UDP port discovery round after the caller
    /// stops waiting for more PONG replies.
    pub fn finish_external_port_discovery(&mut self, completed_at: DateTime<Utc>) {
        if self.active_external_port_discovery.is_none() {
            return;
        }
        self.last_external_port_probe_completed_at = Some(completed_at);
        if self.discovered_external_udp_port.is_none() {
            self.last_error = Some("external Kad UDP port discovery timed out".to_string());
        }
        self.active_external_port_discovery = None;
    }

    /// Return the external UDP port that should be written into
    /// `OP_FWCHECKUDPREQ`.
    ///
    /// Returns `0` when the current firewall-check round could not establish a
    /// reliable external UDP port, which matches the oracle's fallback.
    #[must_use]
    pub fn external_udp_port_for_request(&self) -> u16 {
        self.discovered_external_udp_port.unwrap_or_default()
    }

    /// Ensure the oracle-style TCP firewall/IP recheck loop matches the current
    /// local TCP-firewalled verdict.
    pub fn refresh_tcp_recheck(&mut self, tcp_firewalled: bool, started_at: DateTime<Utc>) {
        if tcp_firewalled {
            if self.active_tcp_round.is_none() {
                self.tcp_recheck_active = true;
                self.last_tcp_check_started_at = Some(started_at);
                self.active_tcp_round = Some(TcpFirewallCheckRound {
                    active_helpers: HashSet::new(),
                    completed_checks: 0,
                });
            }
            return;
        }

        self.tcp_recheck_active = false;
        self.active_tcp_round = None;
    }

    /// Reserve one helper IP for an outbound Kad TCP firewall recheck.
    ///
    /// Mirrors the oracle's `GetRecheckIP()` budget: at most four helpers may
    /// contribute to one active TCP/IP recheck round.
    pub fn try_begin_tcp_firewall_probe(
        &mut self,
        helper_ip: IpAddr,
        started_at: DateTime<Utc>,
    ) -> bool {
        let Some(round) = &mut self.active_tcp_round else {
            return false;
        };
        if round.completed_checks >= TCP_FIREWALL_RECHECK_LIMIT
            || round.active_helpers.len() >= TCP_FIREWALL_RECHECK_LIMIT
            || round.active_helpers.contains(&helper_ip)
        {
            return false;
        }
        self.tcp_recheck_active = true;
        self.last_tcp_check_started_at = Some(started_at);
        round.active_helpers.insert(helper_ip)
    }

    /// Release one helper slot after an outbound Kad TCP firewall probe fails.
    pub fn record_tcp_firewall_probe_failed(&mut self, helper_ip: IpAddr, error: &str) {
        if let Some(round) = &mut self.active_tcp_round {
            round.active_helpers.remove(&helper_ip);
        }
        self.last_helper_ip = Some(helper_ip.to_string());
        self.last_error = Some(error.to_string());
    }

    /// Record one inbound `KADEMLIA_FIREWALLED_RES` reply for the active
    /// oracle-style TCP firewall/IP recheck round.
    pub fn record_firewalled_response(
        &mut self,
        helper_ip: IpAddr,
        reported_ip: IpAddr,
        observed_at: DateTime<Utc>,
    ) -> FirewalledResponseOutcome {
        let Some(round) = &mut self.active_tcp_round else {
            return FirewalledResponseOutcome::Ignored;
        };
        if !round.active_helpers.remove(&helper_ip) {
            return FirewalledResponseOutcome::Ignored;
        }

        round.completed_checks += 1;
        self.tcp_recheck_active = round.completed_checks < TCP_FIREWALL_RECHECK_LIMIT;
        self.last_helper_ip = Some(helper_ip.to_string());
        self.last_reported_external_ip = Some(reported_ip.to_string());
        self.last_tcp_check_completed_at = Some(observed_at);
        self.last_error = None;

        if round.completed_checks >= TCP_FIREWALL_RECHECK_LIMIT {
            self.active_tcp_round = None;
            FirewalledResponseOutcome::Completed
        } else {
            FirewalledResponseOutcome::Recorded
        }
    }

    /// Start a new UDP firewall-check round.
    pub fn begin_udp_check(
        &mut self,
        helper_ips: impl IntoIterator<Item = IpAddr>,
        expected_ports: impl IntoIterator<Item = u16>,
        started_at: DateTime<Utc>,
    ) -> bool {
        let helper_outcomes = helper_ips
            .into_iter()
            .map(|ip| (ip, HelperOutcome::Pending))
            .collect::<HashMap<_, _>>();
        if helper_outcomes.is_empty() {
            self.last_error = Some("no UDP firewall-check helpers available".to_string());
            return false;
        }

        let expected_ports = expected_ports
            .into_iter()
            .filter(|port| *port != 0)
            .collect::<HashSet<_>>();
        if expected_ports.is_empty() {
            self.last_error = Some("UDP firewall-check has no expected ports".to_string());
            return false;
        }

        self.last_udp_check_started_at = Some(started_at);
        self.last_error = None;
        // Keep the public verdict from the previous round while this probe is in
        // flight. MFC's ReCheckFirewallUDP(false) preserves IsVerified() and
        // IsFirewalledUDP(true) reports the last state while testing, so a normal
        // recheck must not temporarily block Kad source publishing after a verified
        // open result.
        self.active_round = Some(UdpFirewallCheckRound {
            started_at,
            expected_ports,
            helper_outcomes,
            discovered_port_reporters: HashMap::new(),
            discovered_external_udp_port: None,
        });
        true
    }

    /// Whether a UDP firewall-check round is currently waiting for helper
    /// replies.
    #[must_use]
    pub fn udp_check_in_progress(&self) -> bool {
        self.active_round.is_some()
    }

    /// Mark one helper request as failed before any UDP probe arrives.
    pub fn record_helper_request_failed(&mut self, helper_ip: IpAddr, error: &str) {
        if let Some(round) = &mut self.active_round
            && let Some(outcome) = round.helper_outcomes.get_mut(&helper_ip)
        {
            *outcome = HelperOutcome::RequestFailed;
            self.last_helper_ip = Some(helper_ip.to_string());
            self.last_error = Some(error.to_string());
        }
    }

    /// Mark one helper test as failed after the helper accepted the UDP probe request.
    pub fn record_helper_test_failed(&mut self, helper_ip: IpAddr, error: &str) {
        if let Some(round) = &mut self.active_round
            && let Some(outcome) = round.helper_outcomes.get_mut(&helper_ip)
        {
            *outcome = HelperOutcome::TestFailed;
            self.last_helper_ip = Some(helper_ip.to_string());
            self.last_error = Some(error.to_string());
        }
    }

    /// Record an inbound `KADEMLIA2_FIREWALLUDP` packet for the current round.
    pub fn record_firewall_udp_packet(
        &mut self,
        helper_ip: IpAddr,
        error_code: u8,
        incoming_port: u16,
        observed_at: DateTime<Utc>,
    ) -> FirewallUdpPacketOutcome {
        let Some(round) = &mut self.active_round else {
            return FirewallUdpPacketOutcome::Ignored;
        };
        let Some(outcome) = round.helper_outcomes.get_mut(&helper_ip) else {
            return FirewallUdpPacketOutcome::Ignored;
        };

        self.last_helper_ip = Some(helper_ip.to_string());
        self.last_reported_port = Some(incoming_port);

        if error_code == 0 && round.expected_ports.contains(&incoming_port) {
            *outcome = HelperOutcome::Succeeded;
            let summary = finalize_round(
                &mut self.active_round,
                true,
                observed_at,
                &mut self.udp_open,
                &mut self.udp_verified,
                &mut self.last_udp_check_succeeded_at,
                &mut self.last_udp_check_failed_at,
            )
            .expect("active round disappeared while marking success");
            self.last_error = None;
            return FirewallUdpPacketOutcome::Open(summary);
        }

        if error_code == 0 && incoming_port != 0 {
            // A positive result on a port we did not predict means a NAT remapped
            // our source UDP port: the helper observed (and echoed) our real
            // external port. Treat it as a discovery candidate and only trust it
            // once enough distinct helpers corroborate the same port, matching the
            // oracle preferring a corroborated open external port over a guess.
            let reporters = round
                .discovered_port_reporters
                .entry(incoming_port)
                .or_default();
            reporters.insert(helper_ip);
            if reporters.len() >= FIREWALL_UDP_PORT_DISCOVERY_REPORTERS {
                *outcome = HelperOutcome::Succeeded;
                round.discovered_external_udp_port = Some(incoming_port);
                self.discovered_external_udp_port = Some(incoming_port);
                let summary = finalize_round(
                    &mut self.active_round,
                    true,
                    observed_at,
                    &mut self.udp_open,
                    &mut self.udp_verified,
                    &mut self.last_udp_check_succeeded_at,
                    &mut self.last_udp_check_failed_at,
                )
                .expect("active round disappeared while marking discovery success");
                self.last_error = None;
                return FirewallUdpPacketOutcome::Open(summary);
            }
            *outcome = HelperOutcome::WrongPort;
            return FirewallUdpPacketOutcome::Recorded;
        }

        // MFC treats wrong-port and remote-error FIREWALLUDP replies as cancelled
        // tests (`bTestCancelled=true`), not completed negative votes.
        *outcome = if error_code == 0 {
            HelperOutcome::WrongPort
        } else {
            HelperOutcome::RemoteError
        };
        FirewallUdpPacketOutcome::Recorded
    }

    /// Finalize the current round after the runtime wait timeout expires.
    pub fn finish_udp_check(
        &mut self,
        completed_at: DateTime<Utc>,
    ) -> Option<UdpFirewallCheckSummary> {
        let round = self.active_round.as_ref()?;
        if round
            .helper_outcomes
            .values()
            .all(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        {
            return None;
        }

        if round
            .helper_outcomes
            .values()
            .any(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        {
            return finalize_round(
                &mut self.active_round,
                true,
                completed_at,
                &mut self.udp_open,
                &mut self.udp_verified,
                &mut self.last_udp_check_succeeded_at,
                &mut self.last_udp_check_failed_at,
            );
        }

        let no_requests_sent = round
            .helper_outcomes
            .values()
            .all(|outcome| matches!(outcome, HelperOutcome::RequestFailed));
        if no_requests_sent {
            self.last_error = Some("all UDP firewall-check TCP requests failed".to_string());
            self.active_round = None;
            return None;
        }

        let explicit_failed_helpers = round
            .helper_outcomes
            .values()
            .filter(|outcome| matches!(outcome, HelperOutcome::TestFailed))
            .count();
        if explicit_failed_helpers < UDP_FIREWALL_CHECK_CLIENTS_TO_ASK {
            self.last_error =
                Some("UDP firewall-check timed out without enough helper replies".to_string());
            self.active_round = None;
            return None;
        }

        self.last_error =
            Some("UDP firewall-check timed out without a positive result".to_string());
        finalize_round(
            &mut self.active_round,
            false,
            completed_at,
            &mut self.udp_open,
            &mut self.udp_verified,
            &mut self.last_udp_check_succeeded_at,
            &mut self.last_udp_check_failed_at,
        )
    }

    /// Whether we should treat ourselves as UDP-firewalled for the purpose of
    /// responding to inbound publishes / buddy requests.
    ///
    /// Mirrors `CUDPFirewallTester::IsFirewalledUDP(true)`: an unknown/unverified
    /// state is treated as OPEN (returns false); we only report firewalled once a
    /// completed check has verified the UDP port is closed.
    #[must_use]
    pub fn is_udp_firewalled(&self) -> bool {
        self.udp_verified && !self.udp_open
    }
}

fn finalize_round(
    round: &mut Option<UdpFirewallCheckRound>,
    open: bool,
    completed_at: DateTime<Utc>,
    udp_open: &mut bool,
    udp_verified: &mut bool,
    last_succeeded_at: &mut Option<DateTime<Utc>>,
    last_failed_at: &mut Option<DateTime<Utc>>,
) -> Option<UdpFirewallCheckSummary> {
    let round = round.take()?;
    let helpers_selected = round.helper_outcomes.len();
    let helpers_requested = round
        .helper_outcomes
        .values()
        .filter(|outcome| !matches!(outcome, HelperOutcome::RequestFailed))
        .count();
    let helpers_succeeded = round
        .helper_outcomes
        .values()
        .filter(|outcome| matches!(outcome, HelperOutcome::Succeeded))
        .count();
    let helpers_failed = round
        .helper_outcomes
        .values()
        .filter(|outcome| matches!(outcome, HelperOutcome::TestFailed))
        .count();

    *udp_open = open;
    *udp_verified = true;
    if open {
        *last_succeeded_at = Some(completed_at);
    } else {
        *last_failed_at = Some(completed_at);
    }

    let external_udp_port = if open {
        round.discovered_external_udp_port
    } else {
        None
    };

    Some(UdpFirewallCheckSummary {
        open,
        helpers_selected,
        helpers_requested,
        helpers_succeeded,
        helpers_failed,
        started_at: round.started_at,
        completed_at,
        external_udp_port,
    })
}

mod tcp_recheck;

#[cfg(test)]
mod tests;
