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
use emulebb_kad_dht::KadRoutingSummaryCounts;
use serde_json::json;

const FAMILY: &str = "kad_event";

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
    emit(FAMILY, "buddy", "info", json!({ "peer": peer.to_string() }), body);
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
            KadRoutingSummaryCounts { total: 10, verified: 4, with_udp_key: 6 },
        );
    }
}
