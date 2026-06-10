use super::super::SnoopQueueFamilyCounts;
use super::*;
use crate::SnoopEntry;

#[test]
fn zero_result_replays_back_off_until_fresh_demand_reappears() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(110)).unwrap();
    assert_eq!(
        selected.logical_key,
        "source:00112233445566778899aabbccddeeff:0000:4096"
    );
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);

    assert!(queue.select_next_source_request(ts(151)).is_none());

    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        170,
    ));
    assert!(queue.select_next_source_request(ts(171)).is_some());
}

#[test]
fn zero_result_history_is_deprioritized_behind_unseen_candidates() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    let selected = queue.select_next_source_request(ts(110)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);

    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        121,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        122,
    ));

    let next_selected = queue.select_next_source_request(ts(160)).unwrap();
    assert_eq!(
        next_selected.logical_key,
        "source:11112222333344445555666677778888:0000:8192"
    );
}

#[test]
fn successful_replay_evicts_drained_entry() {
    let mut queue = queue();
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));

    queue.record_replay_outcome(logical_key, ts(120), 3);

    assert!(queue.snapshot().is_empty());
    assert_eq!(queue.family_counts(), SnoopQueueFamilyCounts::default());
}

#[test]
fn repeated_zero_yield_source_entry_is_evicted() {
    let mut queue = queue();
    let logical_key = "source:00112233445566778899aabbccddeeff:0000:4096";
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));

    let selected = queue.select_next_source_request(ts(110)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(120), 0);
    let selected = queue.select_next_source_request(ts(200)).unwrap();
    queue.record_replay_outcome(&selected.logical_key, ts(210), 0);

    assert!(queue.snapshot().is_empty());
}

#[test]
fn restore_skips_drained_source_entries_without_fresh_demand() {
    let mut queue = queue();
    queue.merge_snapshot(vec![
        SnoopEntry::Source {
            logical_key: "source:00112233445566778899aabbccddeeff:0000:4096".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0,
            size: 4096,
            hit_count: 3,
            first_seen: ts(100),
            last_seen: ts(120),
            last_drained_at: Some(ts(130)),
        },
        SnoopEntry::Source {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            target: "11112222333344445555666677778888".to_string(),
            start_position: 0,
            size: 8192,
            hit_count: 2,
            first_seen: ts(100),
            last_seen: ts(140),
            last_drained_at: Some(ts(130)),
        },
    ]);

    let snapshot = queue.snapshot();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].logical_key(),
        "source:11112222333344445555666677778888:0000:8192"
    );
}

#[test]
fn restore_skips_probationary_one_off_source_entries() {
    let mut queue = queue();
    queue.merge_snapshot(vec![
        SnoopEntry::Source {
            logical_key: "source:00112233445566778899aabbccddeeff:0000:4096".to_string(),
            target: "00112233445566778899aabbccddeeff".to_string(),
            start_position: 0,
            size: 4096,
            hit_count: 1,
            first_seen: ts(100),
            last_seen: ts(120),
            last_drained_at: None,
        },
        SnoopEntry::Source {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            target: "11112222333344445555666677778888".to_string(),
            start_position: 0,
            size: 8192,
            hit_count: 2,
            first_seen: ts(100),
            last_seen: ts(121),
            last_drained_at: None,
        },
    ]);

    let snapshot = queue.snapshot();

    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].logical_key(),
        "source:11112222333344445555666677778888:0000:8192"
    );
}
