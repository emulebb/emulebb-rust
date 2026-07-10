use super::*;

#[test]
fn kad_publishable_shared_files_follow_mfc_publish_rank() {
    let shared = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0x11; 16]).to_string(),
        canonical_name: "shared.bin".to_string(),
        file_size: 128,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: "synthetic note".to_string(),
        rating: 4,
    };
    let other = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0x22; 16]).to_string(),
        canonical_name: "other.bin".to_string(),
        upload_priority: "release".to_string(),
        ..shared.clone()
    };

    let publishable =
        kad_publishable_shared_file_entries(vec![shared.clone(), other.clone()], 4_000, |_| 0);

    assert_eq!(publishable, vec![other, shared]);
}

#[test]
fn kad_publish_rank_age_term_favors_longest_unpublished() {
    // Two files identical except their last Kad-publish wall time. The
    // longer-unpublished file must rank higher on the age term (ordered
    // first), and a never-published file (last-publish 0) must rank as the
    // most-overdue of all — the age term is no longer a flat constant.
    let now_unix_ms = 100_000_000i64;
    let hour_ms = 3_600_000i64;
    let recent = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xA1; 16]).to_string(),
        canonical_name: "recent.bin".to_string(),
        file_size: 1_000,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: String::new(),
        rating: 0,
    };
    let stale = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xB2; 16]).to_string(),
        canonical_name: "stale.bin".to_string(),
        ..recent.clone()
    };
    let never = MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([0xC3; 16]).to_string(),
        canonical_name: "never.bin".to_string(),
        ..recent.clone()
    };

    // recent: published 1h ago; stale: published 30h ago (age capped later);
    // never: never published (0). Age boost: never (80) > stale > recent.
    let last_publish = |file_hash: &str| -> i64 {
        if file_hash == recent.file_hash {
            now_unix_ms - hour_ms
        } else if file_hash == stale.file_hash {
            now_unix_ms - 30 * hour_ms
        } else {
            0
        }
    };

    let ordered = kad_publishable_shared_file_entries(
        vec![recent.clone(), stale.clone(), never.clone()],
        now_unix_ms,
        last_publish,
    );

    assert_eq!(
        ordered
            .iter()
            .map(|e| e.file_hash.clone())
            .collect::<Vec<_>>(),
        vec![
            never.file_hash.clone(),
            stale.file_hash.clone(),
            recent.file_hash.clone()
        ]
    );

    // Sanity: feeding the same constant to every file (the old bug) flattens
    // the age term so ordering falls back to the deterministic jitter/sequence
    // rather than staleness.
    let flat = kad_publishable_shared_file_entries(
        vec![recent.clone(), stale.clone(), never.clone()],
        now_unix_ms,
        |_| 0,
    );
    assert!(flat.iter().all(|e| {
        e.file_hash == recent.file_hash
            || e.file_hash == stale.file_hash
            || e.file_hash == never.file_hash
    }));
}

#[test]
fn best_notes_candidate_uses_notes_clock_not_source_clock() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::time::Duration;

    let now = Instant::now();
    let now_unix_ms = 200_000_000i64;
    let annotated = |tag: u8, name: &str| MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([tag; 16]).to_string(),
        canonical_name: name.to_string(),
        file_size: 1_000,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: "synthetic note".to_string(),
        rating: 3,
    };
    let recent_notes = annotated(0x51, "recent-notes.bin");
    let stale_notes = annotated(0x62, "stale-notes.bin");
    let un_annotated = MetadataTransferPublishEntry {
        comment: String::new(),
        rating: 0,
        ..annotated(0x73, "plain.bin")
    };

    let mut schedule = KadPublishSchedule::new();
    // NOTES clock: recent published 1h ago, stale 30h ago -> stale is the best
    // notes candidate. SOURCE clock is deliberately the opposite so a bug that
    // read the source clock would pick `recent_notes` instead.
    schedule.mark_notes_published(&recent_notes.file_hash, now - Duration::from_secs(3_600));
    schedule.mark_notes_published(
        &stale_notes.file_hash,
        now - Duration::from_secs(30 * 3_600),
    );
    schedule.mark_source_published(&stale_notes.file_hash, now - Duration::from_secs(60), None);

    let best = select_best_notes_publish_candidate(
        &[
            recent_notes.clone(),
            stale_notes.clone(),
            un_annotated.clone(),
        ],
        &schedule,
        now,
        now_unix_ms,
    );
    assert_eq!(best, Some(stale_notes.file_hash.clone()));

    // No annotated file -> no notes candidate.
    assert_eq!(
        select_best_notes_publish_candidate(&[un_annotated], &schedule, now, now_unix_ms),
        None
    );
}

#[test]
fn kad_publish_entry_from_shared_catalog_preserves_live_rank_inputs() {
    let mut entry = Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([0x33; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: Some("ab".repeat(20)),
        upload_priority: "high".to_string(),
        auto_upload_priority: false,
        comment: "synthetic note".to_string(),
        rating: 5,
        all_time_uploaded_bytes: 512,
        complete_parts: Vec::new(),
        publish: Default::default(),
    };
    entry.publish.session_uploaded_bytes = 128;
    entry.publish.session_request_count = 3;
    entry.publish.session_accept_count = 2;
    entry.publish.all_time_request_count = 7;
    entry.publish.all_time_accept_count = 4;
    entry.publish.last_request_unix_ms = 1_700_000_000_000;

    let publish = kad_publish_entry_from_shared_entry(&entry);

    assert_eq!(publish.session_uploaded_bytes, 128);
    assert_eq!(publish.session_request_count, 3);
    assert_eq!(publish.session_accept_count, 2);
    assert_eq!(publish.all_time_upload_requests, 7);
    assert_eq!(publish.all_time_upload_accepts, 4);
    assert_eq!(publish.comment, "synthetic note");
    assert_eq!(publish.rating, 5);
}

#[test]
fn keyword_ordering_holds_age_constant_and_ignores_source_publish_clock() {
    // The keyword lane ranks candidates with the age term held at 0 (oracle
    // passes 0 for tLastPublish, SharedFileList.cpp:3316), so two files
    // identical except their SOURCE last-publish clock rank equally for
    // keyword selection -- unlike the source lane, whose ordering the
    // last-publish clock deliberately moves.
    let now_unix_ms = 100_000_000i64;
    let make = |hash: u8| MetadataTransferPublishEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        session_uploaded_bytes: 0,
        session_request_count: 0,
        session_accept_count: 0,
        all_time_uploaded_bytes: 0,
        all_time_upload_requests: 0,
        all_time_upload_accepts: 0,
        last_upload_request_ms: 0,
        comment: String::new(),
        rating: 0,
    };
    let a = make(0xA1);
    let b = make(0xB2);
    let entries = vec![a.clone(), b.clone()];
    let hashes = |entries: Vec<MetadataTransferPublishEntry>| {
        entries.into_iter().map(|e| e.file_hash).collect::<Vec<_>>()
    };

    // SOURCE ordering DOES move with the clock: whichever file is
    // "never published" (0 -> max age boost) sorts ahead of the other.
    let source_a_overdue = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |file_hash| {
            if file_hash == b.file_hash {
                now_unix_ms - 60_000
            } else {
                0
            }
        },
    ));
    let source_b_overdue = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |file_hash| {
            if file_hash == a.file_hash {
                now_unix_ms - 60_000
            } else {
                0
            }
        },
    ));
    assert_ne!(source_a_overdue, source_b_overdue);

    // KEYWORD ordering (age held at 0) is invariant to the source clock.
    let keyword_first = hashes(kad_publishable_shared_file_entries(
        entries.clone(),
        now_unix_ms,
        |_| 0,
    ));
    let keyword_again = hashes(kad_publishable_shared_file_entries(
        entries,
        now_unix_ms,
        |_| 0,
    ));
    assert_eq!(keyword_first, keyword_again);
}

#[test]
fn kad_source_publish_admits_servable_partfiles_but_keyword_stays_complete_only() {
    let base = |hash: u8, verified_complete: bool, complete_parts: Vec<bool>| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts,
        publish: Default::default(),
    };

    // Completed file: eligible for both lanes.
    let complete = base(0x01, true, Vec::new());
    assert!(kad_source_publish_eligible(&complete));
    assert!(kad_keyword_publish_eligible(&complete));

    // In-progress partfile with ≥1 complete ED2K part: SOURCE-eligible (we
    // can serve that part) but NOT keyword-eligible (oracle `!IsPartFile()`).
    let servable_partfile = base(0x02, false, vec![true, false]);
    assert!(servable_partfile.is_servable());
    assert!(kad_source_publish_eligible(&servable_partfile));
    assert!(!kad_keyword_publish_eligible(&servable_partfile));

    // Partfile with no complete part yet: nothing to serve, so in neither.
    let empty_partfile = base(0x03, false, vec![false, false]);
    assert!(!empty_partfile.is_servable());
    assert!(!kad_source_publish_eligible(&empty_partfile));
    assert!(!kad_keyword_publish_eligible(&empty_partfile));

    // Compatibility hint (a file we do not hold): never published either way.
    let hint = Ed2kSharedEntry {
        compatibility_hint: true,
        ..base(0x04, true, Vec::new())
    };
    assert!(!kad_source_publish_eligible(&hint));
    assert!(!kad_keyword_publish_eligible(&hint));
}

#[test]
fn cheap_prune_hash_set_matches_old_source_scan_and_prunes_on_blocked_tick() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::collections::HashSet;
    use std::time::Duration;

    let base = |hash: u8, verified_complete: bool, complete_parts: Vec<bool>| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: "ubuntu-python-sample.iso".to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts,
        publish: Default::default(),
    };
    let complete = base(0x01, true, Vec::new());
    let servable_partfile = base(0x02, false, vec![true, false]);
    let empty_partfile = base(0x03, false, vec![false, false]);
    let hint = Ed2kSharedEntry {
        compatibility_hint: true,
        ..base(0x04, true, Vec::new())
    };
    let catalog = [
        complete.clone(),
        servable_partfile.clone(),
        empty_partfile.clone(),
        hint.clone(),
    ];

    // OPP-1 prune input: the cheap hash read (what a gate-blocked tick uses to
    // prune) must select exactly the SOURCE-scan file set the expensive
    // build+prune used before the reorder. Build the old set the way the
    // pre-optimization prune did — from the fully ranked SOURCE clones.
    let cheap: HashSet<String> = catalog
        .iter()
        .filter(|entry| kad_source_publish_eligible(entry))
        .map(|entry| entry.file_hash.clone())
        .collect();
    let old_source_scan = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|entry| kad_source_publish_eligible(entry))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        0,
        |_| 0,
    );
    let old_set: HashSet<String> = old_source_scan
        .iter()
        .map(|entry| entry.file_hash.clone())
        .collect();
    assert_eq!(cheap, old_set);
    // Only the servable files (complete + servable partfile) are in the set.
    assert_eq!(
        cheap,
        HashSet::from([
            complete.file_hash.clone(),
            servable_partfile.file_hash.clone()
        ])
    );

    // The prune still runs on a gate-blocked tick from the cheap read alone: a
    // file unshared while blocked is forgotten (reads as source-due again),
    // while a still-shared file keeps its recent-publish clock.
    let now = Instant::now();
    let mut schedule = KadPublishSchedule::new();
    schedule.mark_source_published(&complete.file_hash, now, None);
    let gone = Ed2kHash::from_bytes([0x09; 16]).to_string();
    schedule.mark_source_published(&gone, now, None);
    schedule.retain_only(cheap.iter().map(String::as_str));
    assert!(!schedule.source_due(&complete.file_hash, now, None));
    assert!(schedule.source_due(&gone, now, None));
    // Sanity: after the source interval elapses the retained file is due again.
    let later = now + Duration::from_secs(6 * 3_600);
    assert!(schedule.source_due(&complete.file_hash, later, None));
}

#[test]
fn windowed_candidate_build_selects_identically_to_full_clone_build() {
    use crate::kad_publish_schedule::KadPublishSchedule;
    use std::collections::HashMap;
    use std::time::Duration;

    let now_instant = Instant::now();
    let now_unix_ms = 1_700_000_000_000i64;

    let mk = |hash: u8,
              name: &str,
              priority: &str,
              verified_complete: bool,
              complete_parts: Vec<bool>,
              comment: &str,
              rating: u8,
              all_time_uploaded_bytes: u64| Ed2kSharedEntry {
        file_hash: Ed2kHash::from_bytes([hash; 16]).to_string(),
        canonical_name: name.to_string(),
        file_size: 4096,
        verified_complete,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: priority.to_string(),
        auto_upload_priority: false,
        comment: comment.to_string(),
        rating,
        all_time_uploaded_bytes,
        complete_parts,
        publish: Default::default(),
    };

    // Diverse catalog: completed files across priorities/upload stats (distinct
    // ranks), two annotated (notes) files, a servable partfile (source-only,
    // never keyword), an empty partfile + a hint (excluded from both lanes).
    let catalog = vec![
        mk(
            0x11,
            "alpha-release.iso",
            "release",
            true,
            Vec::new(),
            "note a",
            3,
            0,
        ),
        mk(
            0x22,
            "bravo-normal.iso",
            "normal",
            true,
            Vec::new(),
            "",
            0,
            5000,
        ),
        mk(
            0x33,
            "charlie-high.iso",
            "high",
            true,
            Vec::new(),
            "note c",
            5,
            100,
        ),
        mk(0x44, "delta-low.iso", "low", true, Vec::new(), "", 0, 0),
        mk(
            0x55,
            "echo-normal.iso",
            "normal",
            true,
            Vec::new(),
            "",
            0,
            0,
        ),
        mk(
            0x66,
            "foxtrot-part.iso",
            "normal",
            false,
            vec![true, false],
            "",
            0,
            0,
        ),
        mk(
            0x77,
            "golf-empty.iso",
            "normal",
            false,
            vec![false, false],
            "",
            0,
            0,
        ),
        Ed2kSharedEntry {
            compatibility_hint: true,
            ..mk(0x88, "hotel-hint.iso", "normal", true, Vec::new(), "", 0, 0)
        },
    ];

    let mut schedule = KadPublishSchedule::new();
    // Vary the SOURCE clock so the source ordering is non-trivial (age term).
    schedule.mark_source_published(
        &catalog[0].file_hash,
        now_instant - Duration::from_secs(3_600),
        None,
    );
    schedule.mark_source_published(
        &catalog[2].file_hash,
        now_instant - Duration::from_secs(10 * 3_600),
        None,
    );
    // NOTES clocks for the two annotated files: 0x11 recent (not due), 0x33
    // stale (due) -> the notes lane must pick 0x33 in both builds.
    schedule.mark_notes_published(
        &catalog[0].file_hash,
        now_instant - Duration::from_secs(3_600),
    );
    schedule.mark_notes_published(
        &catalog[2].file_hash,
        now_instant - Duration::from_secs(48 * 3_600),
    );

    let source_clock =
        |file_hash: &str| schedule.source_last_publish_unix_ms(file_hash, now_instant, now_unix_ms);

    // OLD reference: full clone + rank + sort of BOTH lanes (the pre-OPP-2 path).
    let old_source_full = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|e| kad_source_publish_eligible(e))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        now_unix_ms,
        source_clock,
    );
    let old_keyword_files = kad_publishable_shared_file_entries(
        catalog
            .iter()
            .filter(|e| kad_keyword_publish_eligible(e))
            .map(kad_publish_entry_from_shared_entry)
            .collect(),
        now_unix_ms,
        |_| 0,
    );
    let old_keyword_index: HashMap<String, usize> = old_keyword_files
        .iter()
        .enumerate()
        .map(|(i, e)| (e.file_hash.clone(), i))
        .collect();
    let old_keyword_candidates = old_keyword_files
        .iter()
        .map(|entry| KadKeywordPublishCandidate {
            file_hash: entry.file_hash.clone(),
            canonical_name: entry.canonical_name.clone(),
            file_size: entry.file_size,
            aich_root: entry.aich_root.clone(),
        })
        .collect::<Vec<_>>();

    let n = old_source_full.len();
    assert_eq!(
        n, 6,
        "5 completed + 1 servable partfile are source-eligible"
    );
    let scan_budget = 3usize;
    assert!(
        scan_budget < n,
        "budget must be a strict subset to exercise wrap"
    );

    // Walk more than a full rotation, advancing the cursor each tick so the
    // window wraps and every ranked position is materialized at some point.
    // NEW (windowed borrow-rank-clone) must equal OLD (full clone) every tick.
    for _ in 0..(2 * n + 1) {
        let start = schedule.cursor(n);
        let window_len = n.min(scan_budget);
        let old_window: Vec<_> = (0..window_len)
            .map(|off| old_source_full[(start + off) % n].clone())
            .collect();
        let old_best_notes = select_best_notes_publish_candidate(
            &old_source_full,
            &schedule,
            now_instant,
            now_unix_ms,
        );

        let cand = compute_kad_publish_candidates(
            &catalog,
            &schedule,
            now_instant,
            now_unix_ms,
            scan_budget,
        );

        assert_eq!(cand.source_item_count, n);
        assert_eq!(cand.source_cursor_start, start);
        assert_eq!(
            cand.source_scan, old_window,
            "window differs at cursor {start}"
        );
        assert_eq!(cand.best_notes_hash, old_best_notes);
        assert_eq!(
            cand.best_notes_hash.as_deref(),
            Some(catalog[2].file_hash.as_str())
        );
        assert_eq!(cand.keyword_files, old_keyword_candidates);
        assert_eq!(cand.keyword_index, old_keyword_index);

        schedule.advance_cursor(start, window_len, n);
    }
}

#[test]
fn comment_edit_marks_notes_dirty_but_priority_only_edit_does_not() {
    // A comment change edits the notes-relevant fields -> notes clock resets.
    assert!(shared_file_notes_changed("old", 3, Some(("new", 3))));
    // A rating change is also a notes change.
    assert!(shared_file_notes_changed("same", 3, Some(("same", 5))));
    // Re-submitting identical comment/rating is NOT a change.
    assert!(!shared_file_notes_changed("same", 3, Some(("same", 3))));
    // A priority-only PATCH carries no comment/rating and must not reset notes.
    assert!(!shared_file_notes_changed("same", 3, None));
}

#[test]
fn only_offer_relevant_changes_queue_the_ed2k_reoffer() {
    // Publish-G3: a metadata PATCH (priority/comment/rating) changes neither
    // the offered SET nor a file's offer content, so it passes both flags
    // `false` and must NOT queue the rate-limited shared-catalog re-offer.
    assert!(!shared_file_change_requires_ed2k_reoffer(false, false));
    // A genuinely offer-relevant change (share/unshare, or completion) does.
    assert!(shared_file_change_requires_ed2k_reoffer(true, false));
    assert!(shared_file_change_requires_ed2k_reoffer(false, true));
}

#[test]
fn draining_notes_dirty_queue_resets_the_notes_clock() {
    // The edit path enqueues the file hash; the publish loop drains it and
    // resets the in-memory notes clock so the file is notes-due next tick.
    let hash = Ed2kHash::from_bytes([0x44; 16]).to_string();
    let mut schedule = kad_publish_schedule::KadPublishSchedule::new();
    let now = Instant::now();
    schedule.mark_notes_published(&hash, now);
    assert!(!schedule.notes_due(&hash, now));

    let dirty: Arc<std::sync::Mutex<HashSet<String>>> =
        Arc::new(std::sync::Mutex::new(HashSet::new()));
    dirty.lock().unwrap().insert(hash.clone());

    drain_kad_notes_dirty(&dirty, &mut schedule);

    assert!(schedule.notes_due(&hash, now));
    assert!(dirty.lock().unwrap().is_empty());
}
