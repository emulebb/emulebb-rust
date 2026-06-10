use super::super::{ScheduledSnoopRequest, SnoopQueue};
use super::*;
use crate::SnoopQueueConfig;
use emulebb_kad_proto::SearchSourceReq;

#[test]
fn source_drain_selects_source_entries_without_keyword_shapes() {
    let mut queue = queue();
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:8000:4096",
        "00112233445566778899aabbccddeeff",
        0x8000,
        4096,
        110,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:8000:4096",
        "00112233445566778899aabbccddeeff",
        0x8000,
        4096,
        111,
    ));

    let selected = queue.select_next_source_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "source:00112233445566778899aabbccddeeff:8000:4096".to_string(),
            request: SearchSourceReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0x8000,
                size: 4096,
            },
        })
    );
}

#[test]
fn source_drain_skips_zero_sized_requests() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:0",
        "00112233445566778899aabbccddeeff",
        0,
        0,
        100,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:8192",
        "11112222333344445555666677778888",
        0,
        8192,
        111,
    ));

    let selected = queue.select_next_source_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "source:11112222333344445555666677778888:0000:8192".to_string(),
            request: SearchSourceReq {
                target: "11112222333344445555666677778888".parse().unwrap(),
                start_position: 0,
                size: 8192,
            },
        })
    );
}

#[test]
fn source_drain_uses_dedicated_rate_budget() {
    let mut queue = SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 1,
        general_drain_cooldown_secs: 30,
        source_max_queries_per_600s: 2,
        source_drain_cooldown_secs: 30,
        source_stop_after_results: 2,
    });
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:4096",
        "11112222333344445555666677778888",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        "source:11112222333344445555666677778888:0000:4096",
        "11112222333344445555666677778888",
        0,
        4096,
        102,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_source_request(ts(111)).is_some());
}

#[test]
fn source_drain_uses_shorter_dedicated_cooldown() {
    let mut queue = SnoopQueue::new(SnoopQueueConfig {
        dedup_window_secs: 60,
        general_max_queries_per_600s: 4,
        general_drain_cooldown_secs: 90,
        source_max_queries_per_600s: 4,
        source_drain_cooldown_secs: 20,
        source_stop_after_results: 2,
    });
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
    queue.record_replay_outcome(&selected.logical_key, ts(111), 0);
    queue.record(source_entry(
        logical_key,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        131,
    ));

    assert!(queue.select_next_source_request(ts(132)).is_some());
}

#[test]
fn source_drain_prefers_repeated_hot_entries() {
    let mut queue = queue();
    let repeated = "source:00112233445566778899aabbccddeeff:0000:4096";
    let fresh = "source:11112222333344445555666677778888:0000:8192";
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        fresh,
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, repeated);
}

#[test]
fn one_off_source_entries_backfill_source_drain_when_queue_would_idle() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));

    assert!(queue.select_next_source_request(ts(130)).is_some());
}

#[test]
fn second_hit_promotes_probationary_source_entry() {
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

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, logical_key);
}

#[test]
fn repeated_source_entries_still_beat_one_off_backfill() {
    let mut queue = queue();
    let repeated = "source:00112233445566778899aabbccddeeff:0000:4096";
    let one_off = "source:11112222333344445555666677778888:0000:8192";
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(source_entry(
        repeated,
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        101,
    ));
    queue.record(source_entry(
        one_off,
        "11112222333344445555666677778888",
        0,
        8192,
        110,
    ));

    let selected = queue.select_next_source_request(ts(130)).unwrap();

    assert_eq!(selected.logical_key, repeated);
}
