//! Per-file Kad (re)publish due-time scheduling (oracle `CSharedFileList::Publish`).
//!
//! The master does **not** republish every shared file on a flat interval. It
//! keeps a per-file timestamp for the next keyword publish and the next source
//! publish, and on each `Publish()` tick it only (re)publishes a file whose
//! per-file timer is due:
//!
//! - **Keyword**: `CPublishKeyword::SetNextPublishTime(tNow + KADEMLIAREPUBLISHTIMEK)`
//!   with `KADEMLIAREPUBLISHTIMEK = HR2S(24)` (24h) — SharedFileList.cpp:3150,
//!   Opcodes.h:78.
//! - **Source**: `CKnownFile::SetLastPublishTimeKadSrc(tNow + KADEMLIAREPUBLISHTIMES)`
//!   with `KADEMLIAREPUBLISHTIMES = HR2S(5)` (5h) — KnownFile.cpp:1839,
//!   Opcodes.h:76. Due when `tNow >= GetLastPublishTimeKadSrc()`
//!   (`IsKadSourcePublishDue`, SharedFileList.cpp:240).
//!
//! Previously the Rust publish loop republished every shared file's keyword AND
//! source on one flat `kad_republish_interval_secs` (default 30 min), which
//! over-publishes keywords ~48x and sources ~10x versus the master and risks a
//! live-network ban. This tracker restores the per-file, per-kind due gating.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Master keyword republish interval: `KADEMLIAREPUBLISHTIMEK = HR2S(24)` (24h),
/// Opcodes.h:78.
pub(crate) const KAD_KEYWORD_REPUBLISH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Master source republish interval: `KADEMLIAREPUBLISHTIMES = HR2S(5)` (5h),
/// Opcodes.h:76.
pub(crate) const KAD_SOURCE_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60 * 60);

/// Master notes (comment/rating) republish interval:
/// `KADEMLIAREPUBLISHTIMEN = HR2S(24)` (24h), Opcodes.h:77
/// (`CKnownFile::PublishNotes`).
pub(crate) const KAD_NOTES_REPUBLISH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Inputs to the master `CSharedFileList::Publish` firewall/buddy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KadPublishGateInput {
    /// Kad is connected/bootstrapped (`CKademlia::IsConnected()`).
    pub kad_connected: bool,
    /// We advertise the eD2k/Kad TCP-firewalled (LowID) bit (`IsFirewalled()`).
    pub tcp_firewalled: bool,
    /// We have an established outgoing buddy relay
    /// (`clientlist->GetBuddyStatus() == Connected`).
    pub buddy_connected: bool,
    /// Our Kad UDP port is verified open. The master's
    /// `(IsFirewalledUDP(true) || !IsVerified())` term is true (i.e. UDP not
    /// usable) exactly when the UDP port is *not* verified-open, so this single
    /// flag captures both sub-conditions.
    pub udp_open: bool,
}

/// Whether `CSharedFileList::Publish` would emit publishes now.
///
/// Mirrors the gate at SharedFileList.cpp:3066-3076:
/// publish only when connected, and *not* in the firewalled-and-unreachable
/// state (`IsFirewalled() && BuddyStatus != Connected &&
/// (IsFirewalledUDP(true) || !IsVerified())`). The `GetCount()` / `GetPublish()`
/// terms are handled by the caller (it skips when there is nothing to publish
/// and only runs post-bootstrap).
#[must_use]
pub(crate) fn kad_publish_allowed(input: KadPublishGateInput) -> bool {
    if !input.kad_connected {
        return false;
    }
    let firewalled_and_unreachable =
        input.tcp_firewalled && !input.buddy_connected && !input.udp_open;
    !firewalled_and_unreachable
}

/// Whether a file has any user-set comment/rating worth publishing as a Kad note
/// (master `CKnownFile::PublishNotes`: `!GetFileComment().IsEmpty() ||
/// GetFileRating() > 0`). Pure so the notes gating is unit-testable.
#[must_use]
pub(crate) fn file_has_publishable_note(comment: &str, rating: u8) -> bool {
    !comment.is_empty() || rating > 0
}

/// Convert a monotonic last-publish `Instant` to wall-clock unix-ms relative to
/// the current instant/wall time. Only the elapsed interval matters to the
/// publish-rank age term, so this stays correct across a clock with no fixed
/// epoch. Saturates rather than panicking if `last` is somehow in the future.
fn instant_to_wall_ms(last: Instant, now_instant: Instant, now_unix_ms: i64) -> i64 {
    let elapsed_ms = now_instant.saturating_duration_since(last).as_millis();
    now_unix_ms.saturating_sub(i64::try_from(elapsed_ms).unwrap_or(i64::MAX))
}

#[derive(Debug, Clone, Default)]
struct FilePublishState {
    last_source: Option<Instant>,
    last_source_buddy_ip: Option<Ipv4Addr>,
    last_notes: Option<Instant>,
    keywords: HashMap<String, Instant>,
    keyword_terms: Vec<String>,
}

/// Node-load average above which a completed keyword store defers that
/// keyword's republish (oracle `GetNodeLoad() > 20`, Search.cpp:166).
const KEYWORD_LOAD_DEFER_THRESHOLD: u32 = 20;

/// Full-scale keyword load deferral (oracle `DAY2S(7)`): a keyword whose
/// answering nodes average load 100 is not republished for 7 days; lower
/// averages defer proportionally (`DAY2S(7) * (load / 100.0)`).
const KEYWORD_LOAD_DEFER_FULL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Tracks per-file keyword/source last-publish times so each kind is only
/// republished once its master interval has elapsed.
#[derive(Debug, Default)]
pub(crate) struct KadPublishSchedule {
    files: HashMap<String, FilePublishState>,
    /// Per-keyword load deferrals (oracle `CIndexed::AddLoad` keyed by the
    /// keyword target id — global across files sharing the keyword).
    keyword_load_deferrals: HashMap<String, Instant>,
    next_cursor: usize,
}

impl KadPublishSchedule {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether the file's keyword publish is due (never published, or the 24h
    /// keyword interval has elapsed since the last keyword publish) and the
    /// keyword itself is not load-deferred (oracle `CIndexed::SendStoreRequest`
    /// refuses a keyword with a live load entry).
    pub(crate) fn keyword_due(&self, file_hash: &str, keyword: &str, now: Instant) -> bool {
        if let Some(deferred_until) = self.keyword_load_deferrals.get(keyword)
            && now < *deferred_until
        {
            return false;
        }
        match self
            .files
            .get(file_hash)
            .and_then(|state| state.keywords.get(keyword))
            .copied()
        {
            None => true,
            Some(last) => now.duration_since(last) >= KAD_KEYWORD_REPUBLISH_INTERVAL,
        }
    }

    /// Apply the average `KADEMLIA2_PUBLISH_RES` load of a completed keyword
    /// store: above the oracle threshold the keyword is deferred
    /// proportionally, up to 7 days at load 100 (Search.cpp:166-167 →
    /// `CIndexed::AddLoad`). Expired/low-load results clear nothing — the
    /// oracle keeps existing load entries until they lapse.
    pub(crate) fn defer_keyword_by_load(&mut self, keyword: &str, node_load: u32, now: Instant) {
        if node_load <= KEYWORD_LOAD_DEFER_THRESHOLD {
            return;
        }
        let deferral = KEYWORD_LOAD_DEFER_FULL.mul_f64(f64::from(node_load.min(100)) / 100.0);
        self.keyword_load_deferrals
            .insert(keyword.to_string(), now + deferral);
    }

    /// Whether the file's source publish is due (never published, or the 5h
    /// source interval has elapsed since the last source publish).
    pub(crate) fn source_due(
        &self,
        file_hash: &str,
        now: Instant,
        current_buddy_ip: Option<Ipv4Addr>,
    ) -> bool {
        match self.files.get(file_hash) {
            None => true,
            Some(state) if state.last_source.is_none() => true,
            Some(state)
                if current_buddy_ip.is_some() && state.last_source_buddy_ip != current_buddy_ip =>
            {
                true
            }
            Some(state) => {
                now.duration_since(state.last_source.expect("checked above"))
                    >= KAD_SOURCE_REPUBLISH_INTERVAL
            }
        }
    }

    /// Record that the file's keyword was (re)published at `now`.
    pub(crate) fn mark_keyword_published(&mut self, file_hash: &str, keyword: &str, now: Instant) {
        self.files
            .entry(file_hash.to_string())
            .or_default()
            .keywords
            .insert(keyword.to_string(), now);
    }

    /// Record that the file's source was (re)published at `now`.
    pub(crate) fn mark_source_published(
        &mut self,
        file_hash: &str,
        now: Instant,
        buddy_ip: Option<Ipv4Addr>,
    ) {
        let state = self.files.entry(file_hash.to_string()).or_default();
        state.last_source = Some(now);
        state.last_source_buddy_ip = buddy_ip;
    }

    /// Whether the file's notes (comment/rating) publish is due (never published,
    /// or the 24h notes interval has elapsed). The caller additionally gates this
    /// on the file actually having a comment/rating (master
    /// `CKnownFile::PublishNotes`: only when `!comment.IsEmpty() || rating > 0`).
    pub(crate) fn notes_due(&self, file_hash: &str, now: Instant) -> bool {
        match self.files.get(file_hash).and_then(|s| s.last_notes) {
            None => true,
            Some(last) => now.duration_since(last) >= KAD_NOTES_REPUBLISH_INTERVAL,
        }
    }

    /// Reset the file's NOTES publish clock so `notes_due` becomes true on the
    /// next tick. The analog of the oracle `SetLastPublishTimeKadNotes(0)` called
    /// from `CKnownFile::SetFileComment`/`SetFileRating` (KnownFile.cpp:1340,1360)
    /// when a comment/rating actually changes, so the edited note republishes
    /// promptly instead of waiting up to the 24h interval. Only the notes clock
    /// is touched; source/keyword timers are unaffected.
    pub(crate) fn reset_notes(&mut self, file_hash: &str) {
        if let Some(state) = self.files.get_mut(file_hash) {
            state.last_notes = None;
        }
    }

    /// Reset the file's SOURCE publish clock so `source_due` becomes true on the
    /// next tick. The analog of the oracle `SetLastPublishTimeKadSrc(0, 0)` called
    /// when the source store search could not be CREATED
    /// (`PrepareLookup(STOREFILE, ...) == NULL`, SharedFileList.cpp:3389-3390) —
    /// nothing was sent, so the advanced-at-admission clock is rolled back for an
    /// immediate retry instead of waiting the 5h interval. Only the source clock
    /// is touched; keyword/notes timers are unaffected.
    pub(crate) fn reset_source(&mut self, file_hash: &str) {
        if let Some(state) = self.files.get_mut(file_hash) {
            state.last_source = None;
            state.last_source_buddy_ip = None;
        }
    }

    /// Reset the file's KEYWORD publish clock for one keyword so `keyword_due`
    /// becomes true on the next tick. Used to roll back the advanced-at-admission
    /// keyword clock when the keyword store search could not be CREATED (no search
    /// permit — nothing was sent), the oracle `PrepareLookup == NULL` analog for
    /// the keyword kind. Only this (file, keyword) pair is affected; sibling
    /// keywords and the source/notes timers are unaffected.
    pub(crate) fn reset_keyword(&mut self, file_hash: &str, keyword: &str) {
        if let Some(state) = self.files.get_mut(file_hash) {
            state.keywords.remove(keyword);
        }
    }

    /// Record that the file's notes were (re)published at `now`.
    pub(crate) fn mark_notes_published(&mut self, file_hash: &str, now: Instant) {
        self.files
            .entry(file_hash.to_string())
            .or_default()
            .last_notes = Some(now);
    }

    /// Wall-clock ms of the file's last **source** publish (0 = never), for the
    /// balanced publish-rank age term. Mirrors the oracle source selection which
    /// ranks due files by `GetLastPublishTimeKadSrc()` (SharedFileList.cpp:3377);
    /// a never-published file returns 0 so `GetPublishAgeScore` treats it as
    /// most-overdue (max age boost). The stored instant is converted to
    /// wall-clock ms relative to `now_instant`/`now_unix_ms` so the rank only
    /// depends on the elapsed interval.
    pub(crate) fn source_last_publish_unix_ms(
        &self,
        file_hash: &str,
        now_instant: Instant,
        now_unix_ms: i64,
    ) -> i64 {
        self.files
            .get(file_hash)
            .and_then(|state| state.last_source)
            .map(|last| instant_to_wall_ms(last, now_instant, now_unix_ms))
            .unwrap_or(0)
    }

    /// Wall-clock ms of the file's last **notes** publish (0 = never), for the
    /// balanced publish-rank age term. Mirrors the oracle notes selection which
    /// ranks due files by `GetLastPublishTimeKadNotes()` (SharedFileList.cpp:3424)
    /// — a clock distinct from the source clock above.
    pub(crate) fn notes_last_publish_unix_ms(
        &self,
        file_hash: &str,
        now_instant: Instant,
        now_unix_ms: i64,
    ) -> i64 {
        self.files
            .get(file_hash)
            .and_then(|state| state.last_notes)
            .map(|last| instant_to_wall_ms(last, now_instant, now_unix_ms))
            .unwrap_or(0)
    }

    pub(crate) fn hydrate_keyword_published(
        &mut self,
        file_hash: &str,
        keyword: &str,
        at: Instant,
    ) {
        self.mark_keyword_published(file_hash, keyword, at);
    }

    pub(crate) fn hydrate_source_published(&mut self, file_hash: &str, at: Instant) {
        self.mark_source_published(file_hash, at, None);
    }

    pub(crate) fn hydrate_notes_published(&mut self, file_hash: &str, at: Instant) {
        self.mark_notes_published(file_hash, at);
    }

    /// Drop bookkeeping for files no longer shared, so the map cannot grow
    /// without bound as transfers come and go. `keep` is the set of currently
    /// publishable file hashes.
    #[cfg(test)]
    pub(crate) fn retain_only<'a>(&mut self, keep: impl IntoIterator<Item = &'a str>) {
        let keep: HashSet<&str> = keep.into_iter().collect();
        self.files.retain(|hash, _| keep.contains(hash.as_str()));
    }

    pub(crate) fn retain_only_set(&mut self, keep: &HashSet<String>) {
        self.files.retain(|hash, _| keep.contains(hash));
    }

    /// Update remembered filename-derived keyword terms for one file, pruning only
    /// that file's keyword clocks when the derived set actually changed. Returns
    /// true when pruning ran.
    pub(crate) fn sync_keyword_terms(&mut self, file_hash: &str, keep_keywords: &[String]) -> bool {
        let state = self.files.entry(file_hash.to_string()).or_default();
        if state.keyword_terms.as_slice() == keep_keywords {
            return false;
        }

        let keep_set = keep_keywords
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        state
            .keywords
            .retain(|keyword, _| keep_set.contains(keyword.as_str()));
        state.keyword_terms = keep_keywords.to_vec();
        true
    }

    /// Rotating scan cursor for budgeted publish rounds. The publish loop uses
    /// this to avoid revisiting the first files forever when a large shared
    /// library needs several cycles to drain.
    pub(crate) fn cursor(&self, item_count: usize) -> usize {
        if item_count == 0 {
            0
        } else {
            self.next_cursor % item_count
        }
    }

    /// Advance the rotating scan cursor by the number of entries inspected this
    /// round. `start` is passed back in so callers can use a local modulo view
    /// without exposing the stored cursor.
    pub(crate) fn advance_cursor(&mut self, start: usize, inspected: usize, item_count: usize) {
        if item_count == 0 {
            self.next_cursor = 0;
        } else {
            self.next_cursor = (start + inspected) % item_count;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "abc123";
    const KEYWORD: &str = "ubuntu";

    fn gate(
        kad_connected: bool,
        tcp_firewalled: bool,
        buddy_connected: bool,
        udp_open: bool,
    ) -> bool {
        kad_publish_allowed(KadPublishGateInput {
            kad_connected,
            tcp_firewalled,
            buddy_connected,
            udp_open,
        })
    }

    #[test]
    fn gate_requires_kad_connected() {
        assert!(!gate(false, false, false, true));
        assert!(gate(true, false, false, true));
    }

    #[test]
    fn gate_blocks_firewalled_without_buddy_and_udp_closed() {
        // The exact master block state: firewalled, no buddy, UDP not usable.
        assert!(!gate(true, true, false, false));
    }

    #[test]
    fn gate_allows_firewalled_when_buddy_connected() {
        // A buddy relay satisfies the master's BuddyStatus == Connected term.
        assert!(gate(true, true, true, false));
    }

    #[test]
    fn gate_allows_firewalled_when_udp_open() {
        // Verified-open UDP makes (IsFirewalledUDP(true) || !IsVerified()) false.
        assert!(gate(true, true, false, true));
    }

    #[test]
    fn gate_allows_non_firewalled() {
        assert!(gate(true, false, false, false));
    }

    #[test]
    fn never_published_is_due_for_both_kinds() {
        let sched = KadPublishSchedule::new();
        let now = Instant::now();
        assert!(sched.keyword_due(HASH, KEYWORD, now));
        assert!(sched.source_due(HASH, now, None));
    }

    #[test]
    fn keyword_gated_by_24h_interval() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, KEYWORD, t0);

        // Just before the 24h interval: not due.
        let almost = t0 + KAD_KEYWORD_REPUBLISH_INTERVAL - Duration::from_secs(1);
        assert!(!sched.keyword_due(HASH, KEYWORD, almost));

        // At exactly the interval: due.
        let due = t0 + KAD_KEYWORD_REPUBLISH_INTERVAL;
        assert!(sched.keyword_due(HASH, KEYWORD, due));
    }

    #[test]
    fn keyword_load_defers_republish_proportionally_and_across_files() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, KEYWORD, t0);

        // Load at/below the oracle threshold (20): no deferral recorded.
        sched.defer_keyword_by_load(KEYWORD, 20, t0);
        let base_due = t0 + KAD_KEYWORD_REPUBLISH_INTERVAL;
        assert!(sched.keyword_due(HASH, KEYWORD, base_due));

        // Load 50 -> deferred 3.5 days from completion (7d * 50/100), which
        // outlasts the base 24h interval, and applies to EVERY file sharing
        // the keyword (oracle AddLoad keys on the keyword target).
        sched.defer_keyword_by_load(KEYWORD, 50, t0);
        assert!(!sched.keyword_due(HASH, KEYWORD, base_due));
        assert!(!sched.keyword_due("otherfilehash", KEYWORD, base_due));
        let after_deferral = t0 + Duration::from_secs(7 * 24 * 60 * 60 / 2);
        assert!(sched.keyword_due(HASH, KEYWORD, after_deferral));

        // Load is clamped at 100: never defers beyond 7 days.
        sched.defer_keyword_by_load(KEYWORD, 250, t0);
        assert!(!sched.keyword_due(HASH, KEYWORD, t0 + Duration::from_secs(6 * 24 * 60 * 60)));
        assert!(sched.keyword_due(HASH, KEYWORD, t0 + Duration::from_secs(7 * 24 * 60 * 60)));
    }

    #[test]
    fn source_gated_by_5h_interval() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_source_published(HASH, t0, None);

        let almost = t0 + KAD_SOURCE_REPUBLISH_INTERVAL - Duration::from_secs(1);
        assert!(!sched.source_due(HASH, almost, None));

        let due = t0 + KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(sched.source_due(HASH, due, None));
    }

    #[test]
    fn source_republishes_when_firewalled_buddy_ip_changes() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        let old_buddy = Ipv4Addr::new(198, 51, 100, 10);
        let new_buddy = Ipv4Addr::new(198, 51, 100, 11);
        sched.mark_source_published(HASH, t0, Some(old_buddy));

        let almost = t0 + KAD_SOURCE_REPUBLISH_INTERVAL - Duration::from_secs(1);

        assert!(!sched.source_due(HASH, almost, Some(old_buddy)));
        assert!(sched.source_due(HASH, almost, Some(new_buddy)));
        assert!(!sched.source_due(HASH, almost, None));
    }

    #[test]
    fn keyword_and_source_track_independently() {
        // A source republish (5h) must not reset the keyword's 24h timer.
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, KEYWORD, t0);
        sched.mark_source_published(HASH, t0, None);

        // After 5h: source due again, keyword still gated.
        let t5h = t0 + KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(sched.source_due(HASH, t5h, None));
        assert!(!sched.keyword_due(HASH, KEYWORD, t5h));

        sched.mark_source_published(HASH, t5h, None);
        // Keyword remains gated until 24h from its own publish.
        let t10h = t0 + 2 * KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(!sched.keyword_due(HASH, KEYWORD, t10h));
    }

    #[test]
    fn notes_gated_by_24h_interval_and_track_independently() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        // Never published -> due.
        assert!(sched.notes_due(HASH, t0));
        sched.mark_notes_published(HASH, t0);

        let almost = t0 + KAD_NOTES_REPUBLISH_INTERVAL - Duration::from_secs(1);
        assert!(!sched.notes_due(HASH, almost));
        let due = t0 + KAD_NOTES_REPUBLISH_INTERVAL;
        assert!(sched.notes_due(HASH, due));

        // Notes track independently of keyword/source: a keyword publish does not
        // reset the notes timer.
        sched.mark_keyword_published(HASH, KEYWORD, almost);
        assert!(!sched.notes_due(HASH, almost));
    }

    #[test]
    fn reset_notes_makes_notes_due_again() {
        // A comment/rating edit resets the notes clock (SetLastPublishTimeKadNotes(0)),
        // so a just-published note becomes due again without waiting 24h. Only the
        // notes clock is affected -- the source clock is left intact.
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_notes_published(HASH, t0);
        sched.mark_source_published(HASH, t0, None);
        assert!(!sched.notes_due(HASH, t0));

        sched.reset_notes(HASH);
        assert!(sched.notes_due(HASH, t0));
        // Source timer untouched by a notes reset.
        assert!(!sched.source_due(HASH, t0, None));

        // Resetting an unknown file is a harmless no-op (stays due-by-default).
        sched.reset_notes("unknownhash");
        assert!(sched.notes_due("unknownhash", t0));
    }

    #[test]
    fn reset_source_makes_source_due_again() {
        // A source store that could not be CREATED (oracle PrepareLookup==NULL ->
        // SetLastPublishTimeKadSrc(0,0)) rolls the admission-advanced clock back to
        // due, without disturbing the notes clock.
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_source_published(HASH, t0, None);
        sched.mark_notes_published(HASH, t0);
        assert!(!sched.source_due(HASH, t0, None));

        sched.reset_source(HASH);
        assert!(sched.source_due(HASH, t0, None));
        // Notes timer untouched by a source reset.
        assert!(!sched.notes_due(HASH, t0));

        // Resetting an unknown file is a harmless no-op (stays due-by-default).
        sched.reset_source("unknownhash");
        assert!(sched.source_due("unknownhash", t0, None));
    }

    #[test]
    fn reset_keyword_makes_only_that_keyword_due_again() {
        // A keyword store that could not be CREATED rolls only that (file,keyword)
        // clock back to due; a sibling keyword on the same file keeps its clock.
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, "ubuntu", t0);
        sched.mark_keyword_published(HASH, "python", t0);
        assert!(!sched.keyword_due(HASH, "ubuntu", t0));
        assert!(!sched.keyword_due(HASH, "python", t0));

        sched.reset_keyword(HASH, "ubuntu");
        assert!(sched.keyword_due(HASH, "ubuntu", t0));
        assert!(!sched.keyword_due(HASH, "python", t0));
    }

    #[test]
    fn source_and_notes_last_publish_report_distinct_wall_times() {
        // The publish-rank age term reads the source clock for source publishes
        // and the notes clock for notes publishes; the two must not alias.
        let mut sched = KadPublishSchedule::new();
        let now = Instant::now();
        let now_unix_ms = 10_000_000i64;

        // Never published on either kind reads as 0 (most-overdue) for both.
        assert_eq!(sched.source_last_publish_unix_ms(HASH, now, now_unix_ms), 0);
        assert_eq!(sched.notes_last_publish_unix_ms(HASH, now, now_unix_ms), 0);

        // Source published 3h ago, notes published 1h ago: each clock reports its
        // own elapsed interval, independent of the other.
        let source_at = now - Duration::from_secs(3 * 60 * 60);
        let notes_at = now - Duration::from_secs(60 * 60);
        sched.mark_source_published(HASH, source_at, None);
        sched.mark_notes_published(HASH, notes_at);

        assert_eq!(
            sched.source_last_publish_unix_ms(HASH, now, now_unix_ms),
            now_unix_ms - 3 * 60 * 60 * 1000
        );
        assert_eq!(
            sched.notes_last_publish_unix_ms(HASH, now, now_unix_ms),
            now_unix_ms - 60 * 60 * 1000
        );
    }

    #[test]
    fn notes_publish_only_for_commented_or_rated_files() {
        // Master CKnownFile::PublishNotes gate: only when comment non-empty OR
        // rating > 0; an un-annotated file is never published as a note even when
        // its interval is due.
        assert!(file_has_publishable_note("nice file", 0));
        assert!(file_has_publishable_note("", 4));
        assert!(file_has_publishable_note("comment", 5));
        assert!(!file_has_publishable_note("", 0));
    }

    #[test]
    fn retain_only_drops_unshared_files() {
        let mut sched = KadPublishSchedule::new();
        let now = Instant::now();
        sched.mark_keyword_published("keep", KEYWORD, now);
        sched.mark_keyword_published("drop", KEYWORD, now);

        sched.retain_only(["keep"]);
        // "keep" still has state (not due right after publishing).
        assert!(!sched.keyword_due("keep", KEYWORD, now));
        // "drop" was forgotten, so it reads as due (never published).
        assert!(sched.keyword_due("drop", KEYWORD, now));
    }

    #[test]
    fn keyword_terms_track_independently() {
        let mut sched = KadPublishSchedule::new();
        let now = Instant::now();
        sched.mark_keyword_published(HASH, "ubuntu", now);

        assert!(!sched.keyword_due(HASH, "ubuntu", now));
        assert!(sched.keyword_due(HASH, "python", now));
    }

    #[test]
    fn sync_keyword_terms_drops_stale_filename_terms() {
        let mut sched = KadPublishSchedule::new();
        let now = Instant::now();
        sched.mark_keyword_published(HASH, "ubuntu", now);
        sched.mark_keyword_published(HASH, "python", now);

        sched.sync_keyword_terms(HASH, &["python".to_string()]);

        assert!(sched.keyword_due(HASH, "ubuntu", now));
        assert!(!sched.keyword_due(HASH, "python", now));
    }

    #[test]
    fn sync_keyword_terms_prunes_only_when_terms_change() {
        let mut sched = KadPublishSchedule::new();
        let now = Instant::now();
        sched.mark_keyword_published(HASH, "ubuntu", now);
        sched.mark_keyword_published(HASH, "python", now);
        sched.mark_keyword_published("otherhash", "ubuntu", now);

        let original_terms = vec!["ubuntu".to_string(), "python".to_string()];
        assert!(sched.sync_keyword_terms(HASH, &original_terms));
        assert!(!sched.sync_keyword_terms(HASH, &original_terms));
        assert!(!sched.keyword_due(HASH, "ubuntu", now));
        assert!(!sched.keyword_due(HASH, "python", now));

        let changed_terms = vec!["python".to_string()];
        assert!(sched.sync_keyword_terms(HASH, &changed_terms));
        assert!(sched.keyword_due(HASH, "ubuntu", now));
        assert!(!sched.keyword_due(HASH, "python", now));
        assert!(!sched.keyword_due("otherhash", "ubuntu", now));
    }

    #[test]
    fn cursor_rotates_through_budgeted_rounds() {
        let mut sched = KadPublishSchedule::new();
        assert_eq!(sched.cursor(10), 0);

        sched.advance_cursor(0, 3, 10);
        assert_eq!(sched.cursor(10), 3);

        sched.advance_cursor(8, 5, 10);
        assert_eq!(sched.cursor(10), 3);

        sched.advance_cursor(3, 0, 0);
        assert_eq!(sched.cursor(10), 0);
    }
}
