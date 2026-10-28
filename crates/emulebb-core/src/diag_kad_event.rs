//! `family:"kad_event"` `diag_event_v2` emitters (uniform-diagnostics-v2, lane E).
//!
//! These build the `keys` + `body` for the Kad milestone events (schema §3.3)
//! from real call-site data and forward them to the shared writer
//! (`emulebb_ed2k::diag_event::emit`). They live in `emulebb-core` because the
//! Kad drivers they observe (the firewall self-check verdict, the buddy
//! acquisition/loss, the periodic buddy/maintenance tick, and the keyword/source
//! lookup completion) run here. Emit is compiled to a no-op unless
//! `packet-diagnostics` is enabled and then remains runtime-gated by
//! `EMULEBB_RUST_LOG_DIR`.
//!
//! The `event` value is the coarse milestone bucket the harness aligns on
//! (`bootstrap`/`lookup`/`firewall`/`buddy`/`routing_summary`), matching the
//! master's `ClassifyKadEvent` buckets byte-for-byte; the specific milestone name
//! (`firewalled`/`open`, `buddy_established`/`buddy_released`, ...) is carried in
//! the comparable `body.milestone` field exactly as the master does.
//!
//! No field is ever faked: optional `keys` (`peer`, `searchId`) are omitted when
//! the call site does not have them, and `nodeId` is omitted because the rust Kad
//! milestone hooks below operate on endpoints, not a resolved peer node id.

use std::net::SocketAddr;

use emulebb_ed2k::diag_event::emit;
use emulebb_kad_dht::{KadRoutingSummaryCounts, KadSearchCompletion, PublishAttemptStats};
use serde_json::{Value, json};

const FAMILY: &str = "kad_event";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KadBuddyRequestDecision {
    Accepted,
    TcpFirewallCheckCollision,
    SelfEndpoint,
    SelfFirewalled,
    AlreadyHaveBuddy,
    ResponseSendFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KadBuddyRequestState {
    pub(crate) tcp_firewalled: bool,
    pub(crate) udp_verified: bool,
    pub(crate) udp_open: bool,
    pub(crate) requester_has_udp_key: bool,
    pub(crate) requester_tcp_port: u16,
    pub(crate) local_tcp_port: u16,
}

impl KadBuddyRequestDecision {
    fn diagnostic_fields(
        self,
    ) -> (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    ) {
        match self {
            Self::Accepted => (
                "buddy_request_accepted",
                "accept",
                "accepted",
                "eligible",
                "info",
            ),
            Self::TcpFirewallCheckCollision => (
                "buddy_request_refused",
                "refuse",
                "refused",
                "tcp_firewall_check_collision",
                "low",
            ),
            Self::SelfEndpoint => (
                "buddy_request_refused",
                "refuse",
                "refused",
                "self_endpoint",
                "low",
            ),
            Self::SelfFirewalled => (
                "buddy_request_refused",
                "refuse",
                "refused",
                "self_firewalled",
                "low",
            ),
            Self::AlreadyHaveBuddy => (
                "buddy_request_refused",
                "refuse",
                "refused",
                "already_serving_buddy",
                "low",
            ),
            Self::ResponseSendFailed => (
                "buddy_response_send_failed",
                "reply",
                "send_failed",
                "response_send_failed",
                "low",
            ),
        }
    }
}

/// Which outbound Kad publish kind a milestone describes. Carried in
/// `body.publishKind` so a live harness can split keyword vs source vs notes
/// store rounds; the `event` value stays the coarse milestone bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KadPublishKind {
    Keyword,
    Source,
    Notes,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct KadLocalStorePacketSummary {
    pub(crate) packet_kind: &'static str,
    pub(crate) count: u64,
    pub(crate) error_count: u64,
    pub(crate) elapsed_us: u64,
    pub(crate) max_elapsed_us: u64,
}

impl KadPublishKind {
    fn publish_kind(self) -> &'static str {
        match self {
            Self::Keyword => "keyword",
            Self::Source => "source",
            Self::Notes => "notes",
        }
    }

    fn event(self) -> &'static str {
        match self {
            Self::Keyword => "kad_keyword_publish",
            Self::Source => "kad_source_publish",
            Self::Notes => "kad_notes_publish",
        }
    }

    fn milestone(self) -> &'static str {
        match self {
            Self::Keyword => "keyword_published",
            Self::Source => "source_published",
            Self::Notes => "notes_published",
        }
    }

    fn no_ack_milestone(self) -> &'static str {
        match self {
            Self::Keyword => "keyword_publish_no_ack",
            Self::Source => "source_publish_no_ack",
            Self::Notes => "notes_publish_no_ack",
        }
    }

    fn no_contacts_milestone(self) -> &'static str {
        match self {
            Self::Keyword => "keyword_publish_no_contacts",
            Self::Source => "source_publish_no_contacts",
            Self::Notes => "notes_publish_no_contacts",
        }
    }

    fn failure_milestone(self) -> &'static str {
        match self {
            Self::Keyword => "keyword_publish_failed",
            Self::Source => "source_publish_failed",
            Self::Notes => "notes_publish_failed",
        }
    }
}

/// Outbound-publish milestone (uniform-diagnostics-v2 §3.3): we STORE one shared
/// file's keywords/sources/notes to Kad. Emitted once per file per publish round
/// on a successful store fanout, mirroring the inbound `indexedKeywords/Sources`
/// gauges so a live run shows "we published N files' keywords/sources to Kad".
///
/// `keys.fileHash` is the published file's eD2k hash. The body carries the store
/// outcome counts so the harness can see reach (target node count) and ack/fail.
pub(crate) fn publish(
    kind: KadPublishKind,
    file_hash: &str,
    file_count: usize,
    stats: PublishAttemptStats,
) {
    let outcome = publish_outcome(stats);
    // `fileCount` mirrors the MFC oracle body key (files carried by this publish:
    // the keyword's file batch, or 1 for a single source/notes STORE). rust also
    // emits the richer contact stats as a superset.
    let body = json!({
        "milestone": publish_milestone(kind, outcome),
        "action": "publish",
        "publishKind": kind.publish_kind(),
        "fileCount": file_count,
        "outcome": outcome.label(),
        "acknowledged": outcome == KadPublishOutcome::Acked,
        "closestContactsConsidered": stats.closest_contacts_considered,
        "attemptedContacts": stats.attempted_contacts,
        "ackedContacts": stats.acked_contacts,
        "timedOutContacts": stats.timed_out_contacts,
        "failedContacts": stats.failed_contacts(),
    });
    emit(
        FAMILY,
        kind.event(),
        publish_severity(outcome),
        json!({ "fileHash": file_hash }),
        body,
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KadPublishOutcome {
    Acked,
    NoAck,
    NoContacts,
}

impl KadPublishOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Acked => "acked",
            Self::NoAck => "noAck",
            Self::NoContacts => "noContacts",
        }
    }
}

fn publish_outcome(stats: PublishAttemptStats) -> KadPublishOutcome {
    if stats.acked_contacts > 0 {
        KadPublishOutcome::Acked
    } else if stats.attempted_contacts > 0 {
        KadPublishOutcome::NoAck
    } else {
        KadPublishOutcome::NoContacts
    }
}

fn publish_milestone(kind: KadPublishKind, outcome: KadPublishOutcome) -> &'static str {
    match outcome {
        KadPublishOutcome::Acked => kind.milestone(),
        KadPublishOutcome::NoAck => kind.no_ack_milestone(),
        KadPublishOutcome::NoContacts => kind.no_contacts_milestone(),
    }
}

const fn publish_severity(outcome: KadPublishOutcome) -> &'static str {
    match outcome {
        KadPublishOutcome::Acked => "info",
        KadPublishOutcome::NoAck | KadPublishOutcome::NoContacts => "low",
    }
}

/// Outbound-publish failure milestone. This keeps live parity runs explainable
/// when a store search is admitted but fails before any contact ACKs are counted.
pub(crate) fn publish_failure(
    kind: KadPublishKind,
    file_hash: &str,
    file_count: usize,
    failure_class: &str,
    elapsed_ms: u64,
    error: &str,
) {
    // `fileCount` mirrors the MFC oracle body key on the SUCCESS path too, so a
    // window where a keyword publish only ever fails still carries it — otherwise the
    // observed `kad_keyword_publish` body would be missing an oracle key (conformance
    // gap surfaced by the offline parity diff).
    let body = json!({
        "milestone": kind.failure_milestone(),
        "action": "publish",
        "publishKind": kind.publish_kind(),
        "fileCount": file_count,
        "failureClass": failure_class,
        "elapsedMs": elapsed_ms,
        "error": error,
    });
    emit(
        FAMILY,
        kind.event(),
        "low",
        json!({ "fileHash": file_hash }),
        body,
    );
}

/// Per-round rollup (uniform-diagnostics-v2 §3.3): one publish cycle finished and
/// stored at least one file. Surfaces how many files' keywords/sources/notes were
/// published this round (vs the total publishable item count), so a live run has
/// a single line summarizing outbound Kad publish reach.
pub(crate) fn publish_round(
    item_count: usize,
    keyword_published: usize,
    keyword_acked: u32,
    source_published: usize,
    source_acked: u32,
    notes_published: usize,
    notes_acked: u32,
) {
    let body = json!({
        "milestone": "publish_round",
        "action": "observe",
        "itemCount": item_count,
        "keywordPublished": keyword_published,
        "keywordAckedContacts": keyword_acked,
        "sourcePublished": source_published,
        "sourceAckedContacts": source_acked,
        "notesPublished": notes_published,
        "notesAckedContacts": notes_acked,
    });
    emit(FAMILY, "kad_publish_round", "info", json!({}), body);
}

/// Periodic snapshot of the Kad shared-file publish loop's gate state
/// (schema §3.3, milestone `publish_snapshot`). Surfaces the rich publish-loop
/// diagnostics — in-flight vs budget, available DHT search permits, due vs
/// skipped-by-budget — as a diag_event time-series so the publish-reach ramp and
/// permit starvation are analysable from the log, not only the live
/// `/api/v1/status` `kadPublish` snapshot. rust-only (the MFC oracle keeps the
/// nearest data in its free-text upload-slot summary), so it reads as an allowed
/// rust superset under the conformance model.
pub(crate) fn kad_publish_snapshot(diag: &crate::kad_publish_diagnostics::KadPublishDiagnostics) {
    let body = json!({
        "milestone": "publish_snapshot",
        "action": "observe",
        "phase": diag.phase,
        "itemCount": diag.item_count,
        "inFlightCount": diag.in_flight_count,
        "inFlightBudget": diag.in_flight_budget,
        "availableSearchPermits": diag.available_search_permits,
        "budgetExhausted": diag.budget_exhausted,
        "sourceDueCount": diag.source_due_count,
        "sourceSkippedByBudget": diag.source_skipped_by_budget,
        "keywordDueCount": diag.keyword_due_count,
        "keywordSkippedByBudget": diag.keyword_skipped_by_budget,
        "sourcePublishedTotal": diag.source_published_total,
        "keywordPublishedTotal": diag.keyword_published_total,
        "completedCount": diag.completed_count,
        "failedCount": diag.failed_count,
        "timedOutCount": diag.timed_out_count,
        "busyCount": diag.busy_count,
    });
    emit(FAMILY, "kad_publish_snapshot", "info", json!({}), body);
}

/// `firewall` milestone (schema §3.3): the Kad UDP firewall self-check resolved.
/// `firewalled=false` -> milestone `open`; `firewalled=true` -> `firewalled`,
/// matching the master's firewall bucket.
pub(crate) fn firewall(firewalled: bool) {
    let milestone = if firewalled { "firewalled" } else { "open" };
    let body = json!({
        "milestone": milestone,
        "action": "observe",
        "firewalled": firewalled,
    });
    let severity = if firewalled { "low" } else { "info" };
    emit(FAMILY, "firewall", severity, json!({}), body);
}

/// `buddy` milestone (schema §3.3): a Kad buddy was acquired (`buddy_established`)
/// or lost (`buddy_released`). `peer` is the buddy's Kad UDP endpoint.
pub(crate) fn buddy(established: bool, peer: SocketAddr) {
    let milestone = if established {
        "buddy_established"
    } else {
        "buddy_released"
    };
    let action = if established { "acquired" } else { "released" };
    let body = json!({ "milestone": milestone, "action": action });
    emit(
        FAMILY,
        "buddy",
        "info",
        json!({ "peer": peer.to_string() }),
        body,
    );
}

fn buddy_request_parts(
    decision: KadBuddyRequestDecision,
    peer: SocketAddr,
    state: KadBuddyRequestState,
) -> (&'static str, Value, Value) {
    let (milestone, action, outcome, reason, severity) = decision.diagnostic_fields();
    let keys = json!({ "peer": peer.to_string() });
    let body = json!({
        "milestone": milestone,
        "action": action,
        "outcome": outcome,
        "reason": reason,
        "tcpFirewalled": state.tcp_firewalled,
        "udpVerified": state.udp_verified,
        "udpOpen": state.udp_open,
        "requesterHasUdpKey": state.requester_has_udp_key,
        "requesterTcpPort": state.requester_tcp_port,
        "localTcpPort": state.local_tcp_port,
    });
    (severity, keys, body)
}

pub(crate) fn buddy_request(
    decision: KadBuddyRequestDecision,
    peer: SocketAddr,
    state: KadBuddyRequestState,
) {
    let (severity, keys, body) = buddy_request_parts(decision, peer, state);
    emit(FAMILY, "buddy_request", severity, keys, body);
}

/// `callback` milestone (uniform-diagnostics-v2 §3.3, rust superset): we
/// originated an outbound Kad `KADEMLIA_CALLBACK_REQ` to a firewalled buddy
/// source's buddy so the source connects back to us (oracle `BaseClient.cpp`
/// `CCS_KADCALLBACK`). `outcome` is `sent`, `send_failed`, or
/// `delivery_unknown`; `keys.peer` is the buddy relay endpoint the request went
/// to when known, while FINDSOURCE traversal omits it. This has no direct MFC
/// diag_event analog (MFC only `DebugSend`s), so it is an allowed rust-only
/// superset event.
pub(crate) fn callback(
    outcome: &str,
    buddy_peer: Option<SocketAddr>,
    source: SocketAddr,
    file_hash: &str,
) {
    let milestone = match outcome {
        "sent" => "callback_requested",
        _ => "callback_request_failed",
    };
    let severity = if outcome == "sent" { "info" } else { "low" };
    let body = json!({
        "milestone": milestone,
        "action": "callback",
        "outcome": outcome,
        "source": source.to_string(),
        "fileHash": file_hash,
    });
    let mut keys = json!({ "fileHash": file_hash });
    if let Some(peer) = buddy_peer {
        keys["peer"] = json!(peer.to_string());
    }
    emit(FAMILY, "callback", severity, keys, body);
}

fn lookup_parts(
    milestone: &'static str,
    search_id: Option<&str>,
    search_kind: &'static str,
    result_count: u32,
) -> (Value, Value) {
    let keys = search_id.map_or_else(|| json!({}), |search_id| json!({ "searchId": search_id }));
    let body = json!({
        "milestone": milestone,
        "action": "search",
        "searchKind": search_kind,
        "resultCount": result_count,
    });
    (keys, body)
}

/// Emits the start of one Kad lookup. `searchId` correlates public searches;
/// internal metadata and source lookups omit it rather than inventing an ID.
pub(crate) fn lookup_started(search_id: Option<&str>, search_kind: &'static str) {
    let (keys, body) = lookup_parts("lookup_started", search_id, search_kind, 0);
    emit(FAMILY, "lookup", "info", keys, body);
}

/// Emits the terminal result count for one Kad lookup.
pub(crate) fn lookup_complete(
    search_id: Option<&str>,
    search_kind: &'static str,
    result_count: u32,
) {
    let (keys, mut body) = lookup_parts("lookup_complete", search_id, search_kind, result_count);
    body["outcome"] = json!("completed");
    emit(FAMILY, "lookup", "info", keys, body);
}

/// Emits a search start rejection separately from a legitimate completed-empty
/// traversal. The exact reason is stable queue/diagnostic data.
pub(crate) fn lookup_not_dispatched(
    search_id: Option<&str>,
    search_kind: &'static str,
    reason: &'static str,
) {
    let (keys, mut body) = lookup_parts("lookup_not_dispatched", search_id, search_kind, 0);
    body["outcome"] = json!("not-dispatched");
    body["reason"] = json!(reason);
    emit(FAMILY, "lookup", "low", keys, body);
}

/// Emits the authoritative post-admission traversal receipt. A closed result
/// stream is only a successful lookup when at least one phase-2 search packet
/// reached the local UDP socket and the traversal completed normally.
pub(crate) fn lookup_finished(
    search_id: Option<&str>,
    search_kind: &'static str,
    completion: KadSearchCompletion,
) {
    let dispatched = completion.search_packet_dispatched();
    let completed = dispatched
        && completion.terminal_reason == emulebb_kad_dht::KadSearchTerminalReason::Completed;
    let outcome = if completed {
        "completed"
    } else if completion.terminal_reason == emulebb_kad_dht::KadSearchTerminalReason::Cancelled {
        "cancelled"
    } else {
        "not-dispatched"
    };
    let (keys, mut body) = lookup_parts(
        "lookup_complete",
        search_id,
        search_kind,
        completion.accepted_result_count as u32,
    );
    body["outcome"] = json!(outcome);
    body["reason"] = json!(completion.terminal_reason.reason());
    body["routingSeedCount"] = json!(completion.routing_seed_count);
    body["respondingContactCount"] = json!(completion.responding_contact_count);
    body["phase2AttemptedCount"] = json!(completion.phase2_attempted_count);
    body["phase2SentCount"] = json!(completion.phase2_sent_count);
    body["rawResultCount"] = json!(completion.raw_result_count);
    body["acceptedResultCount"] = json!(completion.accepted_result_count);
    body["elapsedMs"] = json!(completion.elapsed.as_millis());
    emit(
        FAMILY,
        "lookup",
        if completed { "info" } else { "low" },
        keys,
        body,
    );
}

/// `routing_summary` (schema §3.3, periodic): the routing-table + connection
/// gauge emitted from the periodic Kad buddy/maintenance tick. Field names match
/// the master's `LogRoutingSummary` diag_event_v2 body byte-for-byte.
pub(crate) fn routing_summary(
    connected: bool,
    bootstrapping: bool,
    firewalled: bool,
    lan_mode: bool,
    counts: KadRoutingSummaryCounts,
) {
    let body = json!({
        "milestone": "routing_summary",
        "action": "observe",
        "connected": connected,
        "bootstrapping": bootstrapping,
        "firewalled": firewalled,
        "lanMode": lan_mode,
        "contactTotal": counts.total,
        "contactVerified": counts.verified,
        "contactWithUdpKey": counts.with_udp_key,
    });
    emit(FAMILY, "routing_summary", "info", json!({}), body);
}

/// Periodic local-store packet summary (rust superset): aggregates the inbound
/// Kad packet dispatcher by packet kind so live profiles can distinguish hot
/// lookup, publish, routing, and firewall lanes without logging every packet.
pub(crate) fn local_store_summary(elapsed_secs: u64, summaries: &[KadLocalStorePacketSummary]) {
    if summaries.is_empty() {
        return;
    }
    let packet_summaries = summaries
        .iter()
        .map(|summary| {
            json!({
                "packetKind": summary.packet_kind,
                "count": summary.count,
                "errorCount": summary.error_count,
                "elapsedUs": summary.elapsed_us,
                "maxElapsedUs": summary.max_elapsed_us,
            })
        })
        .collect::<Vec<_>>();
    let total_count = summaries.iter().map(|summary| summary.count).sum::<u64>();
    let total_errors = summaries
        .iter()
        .map(|summary| summary.error_count)
        .sum::<u64>();
    let body = json!({
        "milestone": "local_store_summary",
        "action": "observe",
        "elapsedSecs": elapsed_secs,
        "packetCount": total_count,
        "errorCount": total_errors,
        "packets": packet_summaries,
    });
    emit(FAMILY, "kad_local_store", "info", json!({}), body);
}

pub(crate) const KAD_SEARCH_KIND_KEYWORD: &str = "keyword";
pub(crate) const KAD_SEARCH_KIND_FILE: &str = "file";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_kind_constants_are_stable() {
        assert_eq!(KAD_SEARCH_KIND_KEYWORD, "keyword");
        assert_eq!(KAD_SEARCH_KIND_FILE, "file");
    }

    #[test]
    fn lookup_lifecycle_correlates_public_searches() {
        let (keys, body) = lookup_parts("lookup_complete", Some("42"), KAD_SEARCH_KIND_KEYWORD, 7);
        assert_eq!(keys, json!({ "searchId": "42" }));
        assert_eq!(
            body,
            json!({
                "milestone": "lookup_complete",
                "action": "search",
                "searchKind": KAD_SEARCH_KIND_KEYWORD,
                "resultCount": 7,
            })
        );
    }

    #[test]
    fn lookup_lifecycle_omits_unknown_search_id() {
        let (keys, _) = lookup_parts("lookup_started", None, KAD_SEARCH_KIND_FILE, 0);
        assert_eq!(keys, json!({}));
    }

    #[test]
    fn firewall_emit_is_a_noop_without_log_dir() {
        // EMULEBB_RUST_LOG_DIR is unset in the unit-test environment, so the
        // shared writer is a no-op; this just exercises the builder paths.
        firewall(true);
        firewall(false);
        buddy(true, "1.2.3.4:4672".parse().unwrap());
        buddy(false, "1.2.3.4:4672".parse().unwrap());
        buddy_request(
            KadBuddyRequestDecision::Accepted,
            "1.2.3.4:4672".parse().unwrap(),
            KadBuddyRequestState {
                tcp_firewalled: false,
                udp_verified: true,
                udp_open: true,
                requester_has_udp_key: true,
                requester_tcp_port: 4662,
                local_tcp_port: 4663,
            },
        );
        callback(
            "sent",
            Some("198.51.100.9:5000".parse().unwrap()),
            "192.0.2.77:4662".parse().unwrap(),
            "abc123",
        );
        callback(
            "send_failed",
            Some("198.51.100.9:5000".parse().unwrap()),
            "192.0.2.77:4662".parse().unwrap(),
            "abc123",
        );
        callback(
            "send_failed",
            None,
            "192.0.2.77:4662".parse().unwrap(),
            "abc123",
        );
        lookup_started(None, KAD_SEARCH_KIND_FILE);
        lookup_complete(None, KAD_SEARCH_KIND_FILE, 7);
        lookup_not_dispatched(
            Some("search-1"),
            KAD_SEARCH_KIND_KEYWORD,
            "kad-search-capacity-busy",
        );
        routing_summary(
            true,
            false,
            false,
            false,
            KadRoutingSummaryCounts {
                total: 10,
                verified: 4,
                with_udp_key: 6,
            },
        );
        let stats = PublishAttemptStats {
            closest_contacts_considered: 10,
            attempted_contacts: 8,
            acked_contacts: 5,
            timed_out_contacts: 3,
            total_load: 0,
            load_responses: 0,
        };
        publish(KadPublishKind::Keyword, "abc123", 7, stats);
        publish(KadPublishKind::Source, "abc123", 1, stats);
        publish(KadPublishKind::Notes, "abc123", 1, stats);
        publish_round(4, 2, 9, 1, 4, 1, 2);
        local_store_summary(
            30,
            &[KadLocalStorePacketSummary {
                packet_kind: "SearchSourceReq",
                count: 4,
                error_count: 1,
                elapsed_us: 2_000,
                max_elapsed_us: 750,
            }],
        );
    }

    #[test]
    fn buddy_request_diagnostics_preserve_terminal_decision_and_state() {
        let peer = "198.51.100.7:4672".parse().unwrap();
        let state = KadBuddyRequestState {
            tcp_firewalled: true,
            udp_verified: false,
            udp_open: false,
            requester_has_udp_key: true,
            requester_tcp_port: 4662,
            local_tcp_port: 4663,
        };

        let (severity, keys, body) =
            buddy_request_parts(KadBuddyRequestDecision::SelfFirewalled, peer, state);

        assert_eq!(severity, "low");
        assert_eq!(keys, json!({ "peer": "198.51.100.7:4672" }));
        assert_eq!(
            body,
            json!({
                "milestone": "buddy_request_refused",
                "action": "refuse",
                "outcome": "refused",
                "reason": "self_firewalled",
                "tcpFirewalled": true,
                "udpVerified": false,
                "udpOpen": false,
                "requesterHasUdpKey": true,
                "requesterTcpPort": 4662,
                "localTcpPort": 4663,
            })
        );
    }

    #[test]
    fn buddy_request_decisions_have_stable_terminal_fields() {
        let cases = [
            (
                KadBuddyRequestDecision::Accepted,
                "buddy_request_accepted",
                "accepted",
                "eligible",
            ),
            (
                KadBuddyRequestDecision::TcpFirewallCheckCollision,
                "buddy_request_refused",
                "refused",
                "tcp_firewall_check_collision",
            ),
            (
                KadBuddyRequestDecision::SelfEndpoint,
                "buddy_request_refused",
                "refused",
                "self_endpoint",
            ),
            (
                KadBuddyRequestDecision::AlreadyHaveBuddy,
                "buddy_request_refused",
                "refused",
                "already_serving_buddy",
            ),
            (
                KadBuddyRequestDecision::ResponseSendFailed,
                "buddy_response_send_failed",
                "send_failed",
                "response_send_failed",
            ),
        ];

        for (decision, milestone, outcome, reason) in cases {
            let (actual_milestone, _, actual_outcome, actual_reason, _) =
                decision.diagnostic_fields();
            assert_eq!(actual_milestone, milestone);
            assert_eq!(actual_outcome, outcome);
            assert_eq!(actual_reason, reason);
        }
    }

    #[test]
    fn publish_kind_event_and_milestone_names_are_stable() {
        assert_eq!(KadPublishKind::Keyword.event(), "kad_keyword_publish");
        assert_eq!(KadPublishKind::Source.event(), "kad_source_publish");
        assert_eq!(KadPublishKind::Notes.event(), "kad_notes_publish");
        assert_eq!(KadPublishKind::Keyword.publish_kind(), "keyword");
        assert_eq!(KadPublishKind::Source.publish_kind(), "source");
        assert_eq!(KadPublishKind::Notes.publish_kind(), "notes");
        assert_eq!(KadPublishKind::Keyword.milestone(), "keyword_published");
    }

    #[test]
    fn publish_outcome_classifies_zero_ack_fanouts() {
        let acked = PublishAttemptStats {
            attempted_contacts: 8,
            acked_contacts: 1,
            ..PublishAttemptStats::default()
        };
        let no_ack = PublishAttemptStats {
            attempted_contacts: 8,
            acked_contacts: 0,
            timed_out_contacts: 8,
            ..PublishAttemptStats::default()
        };
        let no_contacts = PublishAttemptStats::default();

        assert_eq!(publish_outcome(acked), KadPublishOutcome::Acked);
        assert_eq!(
            publish_milestone(KadPublishKind::Keyword, publish_outcome(acked)),
            "keyword_published"
        );
        assert_eq!(publish_severity(publish_outcome(acked)), "info");

        assert_eq!(publish_outcome(no_ack), KadPublishOutcome::NoAck);
        assert_eq!(
            publish_milestone(KadPublishKind::Keyword, publish_outcome(no_ack)),
            "keyword_publish_no_ack"
        );
        assert_eq!(publish_severity(publish_outcome(no_ack)), "low");

        assert_eq!(publish_outcome(no_contacts), KadPublishOutcome::NoContacts);
        assert_eq!(
            publish_milestone(KadPublishKind::Source, publish_outcome(no_contacts)),
            "source_publish_no_contacts"
        );
        assert_eq!(publish_severity(publish_outcome(no_contacts)), "low");
    }
}
