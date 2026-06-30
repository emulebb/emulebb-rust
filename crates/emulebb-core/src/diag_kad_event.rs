//! `family:"kad_event"` `diag_event_v1` emitters (uniform-diagnostics-v2, lane E).
//!
//! These build the `keys` + `body` for the Kad milestone events (schema §3.3)
//! from real call-site data and forward them to the shared writer
//! (`emulebb_ed2k::diag_event::emit`). They live in `emulebb-core` because the
//! Kad drivers they observe (the firewall self-check verdict, the buddy
//! acquisition/loss, the periodic buddy/maintenance tick, and the keyword/source
//! lookup completion) run here. Emit is a cheap no-op when `EMULEBB_RUST_LOG_DIR`
//! is unset, so the call sites need no extra gating.
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
use emulebb_kad_dht::{KadRoutingSummaryCounts, PublishAttemptStats};
use serde_json::json;

const FAMILY: &str = "kad_event";

/// Which outbound Kad publish kind a milestone describes. Carried in
/// `body.publishKind` so a live harness can split keyword vs source vs notes
/// store rounds; the `event` value stays the coarse milestone bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KadPublishKind {
    Keyword,
    Source,
    Notes,
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
pub(crate) fn publish(kind: KadPublishKind, file_hash: &str, stats: PublishAttemptStats) {
    let body = json!({
        "milestone": kind.milestone(),
        "action": "publish",
        "publishKind": kind.publish_kind(),
        "closestContactsConsidered": stats.closest_contacts_considered,
        "attemptedContacts": stats.attempted_contacts,
        "ackedContacts": stats.acked_contacts,
        "timedOutContacts": stats.timed_out_contacts,
        "failedContacts": stats.failed_contacts(),
    });
    emit(
        FAMILY,
        kind.event(),
        "info",
        json!({ "fileHash": file_hash }),
        body,
    );
}

/// Outbound-publish failure milestone. This keeps live parity runs explainable
/// when a store search is admitted but fails before any contact ACKs are counted.
pub(crate) fn publish_failure(
    kind: KadPublishKind,
    file_hash: &str,
    failure_class: &str,
    elapsed_ms: u64,
    error: &str,
) {
    let body = json!({
        "milestone": kind.failure_milestone(),
        "action": "publish",
        "publishKind": kind.publish_kind(),
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
#[allow(clippy::too_many_arguments)]
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

/// `lookup` milestone `lookup_complete` (schema §3.3): a Kad search/lookup
/// completed. `searchType` mirrors the master's `LogSearchResponseEvent` search
/// type integer; `resultCount` is the number of results gathered.
pub(crate) fn lookup_complete(search_type: u32, result_count: u32) {
    let body = json!({
        "milestone": "lookup_complete",
        "action": "observe",
        "searchType": search_type,
        "resultCount": result_count,
    });
    emit(FAMILY, "lookup", "info", json!({}), body);
}

/// `routing_summary` (schema §3.3, periodic): the routing-table + connection
/// gauge emitted from the periodic Kad buddy/maintenance tick. Field names match
/// the master's `LogRoutingSummary` diag_event_v1 body byte-for-byte.
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

/// The master uses these Kad search-type integers in `LogSearchResponseEvent`
/// (`KadSearchTypeFile`/`KadSearchTypeKeyword`). The rust lookup hooks know which
/// kind they are, so map them to the same integers for harness alignment.
pub(crate) const KAD_SEARCH_TYPE_KEYWORD: u32 = 0;
pub(crate) const KAD_SEARCH_TYPE_FILE: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_type_constants_match_master() {
        assert_eq!(KAD_SEARCH_TYPE_KEYWORD, 0);
        assert_eq!(KAD_SEARCH_TYPE_FILE, 1);
    }

    #[test]
    fn firewall_emit_is_a_noop_without_log_dir() {
        // EMULEBB_RUST_LOG_DIR is unset in the unit-test environment, so the
        // shared writer is a no-op; this just exercises the builder paths.
        firewall(true);
        firewall(false);
        buddy(true, "1.2.3.4:4672".parse().unwrap());
        buddy(false, "1.2.3.4:4672".parse().unwrap());
        lookup_complete(KAD_SEARCH_TYPE_FILE, 7);
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
        };
        publish(KadPublishKind::Keyword, "abc123", stats);
        publish(KadPublishKind::Source, "abc123", stats);
        publish(KadPublishKind::Notes, "abc123", stats);
        publish_round(4, 2, 9, 1, 4, 1, 2);
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
}
