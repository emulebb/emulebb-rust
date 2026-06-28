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

use std::collections::HashMap;
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

#[derive(Debug, Clone, Copy, Default)]
struct FilePublishState {
    last_keyword: Option<Instant>,
    last_source: Option<Instant>,
    last_notes: Option<Instant>,
}

/// Tracks per-file keyword/source last-publish times so each kind is only
/// republished once its master interval has elapsed.
#[derive(Debug, Default)]
pub(crate) struct KadPublishSchedule {
    files: HashMap<String, FilePublishState>,
    next_cursor: usize,
}

impl KadPublishSchedule {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether the file's keyword publish is due (never published, or the 24h
    /// keyword interval has elapsed since the last keyword publish).
    pub(crate) fn keyword_due(&self, file_hash: &str, now: Instant) -> bool {
        match self.files.get(file_hash).and_then(|s| s.last_keyword) {
            None => true,
            Some(last) => now.duration_since(last) >= KAD_KEYWORD_REPUBLISH_INTERVAL,
        }
    }

    /// Whether the file's source publish is due (never published, or the 5h
    /// source interval has elapsed since the last source publish).
    pub(crate) fn source_due(&self, file_hash: &str, now: Instant) -> bool {
        match self.files.get(file_hash).and_then(|s| s.last_source) {
            None => true,
            Some(last) => now.duration_since(last) >= KAD_SOURCE_REPUBLISH_INTERVAL,
        }
    }

    /// Record that the file's keyword was (re)published at `now`.
    pub(crate) fn mark_keyword_published(&mut self, file_hash: &str, now: Instant) {
        self.files
            .entry(file_hash.to_string())
            .or_default()
            .last_keyword = Some(now);
    }

    /// Record that the file's source was (re)published at `now`.
    pub(crate) fn mark_source_published(&mut self, file_hash: &str, now: Instant) {
        self.files
            .entry(file_hash.to_string())
            .or_default()
            .last_source = Some(now);
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

    /// Record that the file's notes were (re)published at `now`.
    pub(crate) fn mark_notes_published(&mut self, file_hash: &str, now: Instant) {
        self.files
            .entry(file_hash.to_string())
            .or_default()
            .last_notes = Some(now);
    }

    /// Drop bookkeeping for files no longer shared, so the map cannot grow
    /// without bound as transfers come and go. `keep` is the set of currently
    /// publishable file hashes.
    pub(crate) fn retain_only<'a>(&mut self, keep: impl IntoIterator<Item = &'a str>) {
        let keep: std::collections::HashSet<&str> = keep.into_iter().collect();
        self.files.retain(|hash, _| keep.contains(hash.as_str()));
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
        assert!(sched.keyword_due(HASH, now));
        assert!(sched.source_due(HASH, now));
    }

    #[test]
    fn keyword_gated_by_24h_interval() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, t0);

        // Just before the 24h interval: not due.
        let almost = t0 + KAD_KEYWORD_REPUBLISH_INTERVAL - Duration::from_secs(1);
        assert!(!sched.keyword_due(HASH, almost));

        // At exactly the interval: due.
        let due = t0 + KAD_KEYWORD_REPUBLISH_INTERVAL;
        assert!(sched.keyword_due(HASH, due));
    }

    #[test]
    fn source_gated_by_5h_interval() {
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_source_published(HASH, t0);

        let almost = t0 + KAD_SOURCE_REPUBLISH_INTERVAL - Duration::from_secs(1);
        assert!(!sched.source_due(HASH, almost));

        let due = t0 + KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(sched.source_due(HASH, due));
    }

    #[test]
    fn keyword_and_source_track_independently() {
        // A source republish (5h) must not reset the keyword's 24h timer.
        let mut sched = KadPublishSchedule::new();
        let t0 = Instant::now();
        sched.mark_keyword_published(HASH, t0);
        sched.mark_source_published(HASH, t0);

        // After 5h: source due again, keyword still gated.
        let t5h = t0 + KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(sched.source_due(HASH, t5h));
        assert!(!sched.keyword_due(HASH, t5h));

        sched.mark_source_published(HASH, t5h);
        // Keyword remains gated until 24h from its own publish.
        let t10h = t0 + 2 * KAD_SOURCE_REPUBLISH_INTERVAL;
        assert!(!sched.keyword_due(HASH, t10h));
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
        sched.mark_keyword_published(HASH, almost);
        assert!(!sched.notes_due(HASH, almost));
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
        sched.mark_keyword_published("keep", now);
        sched.mark_keyword_published("drop", now);

        sched.retain_only(["keep"]);
        // "keep" still has state (not due right after publishing).
        assert!(!sched.keyword_due("keep", now));
        // "drop" was forgotten, so it reads as due (never published).
        assert!(sched.keyword_due("drop", now));
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
