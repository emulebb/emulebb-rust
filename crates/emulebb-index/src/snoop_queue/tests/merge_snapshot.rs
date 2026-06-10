use super::super::{ScheduledSnoopRequest, SnoopQueueFamilyCounts};
use super::*;
use crate::SnoopEntry;
use emulebb_kad_proto::SearchKeyReq;

#[test]
fn repeated_hits_merge_and_preserve_first_seen() {
    let mut queue = queue();
    let entry = keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    );
    queue.record(entry.clone());
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        140,
    ));

    let snapshot = queue.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].hit_count(), 2);
    assert_eq!(snapshot[0].first_seen(), ts(100));
    assert_eq!(snapshot[0].last_seen(), ts(140));
}

#[test]
fn different_keyword_payloads_do_not_collapse() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:8000:aabb",
        "00112233445566778899aabbccddeeff",
        0x8000,
        Some("aabb"),
        100,
    ));
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:8000:ccdd",
        "00112233445566778899aabbccddeeff",
        0x8000,
        Some("ccdd"),
        110,
    ));

    let snapshot = queue.snapshot();
    assert_eq!(snapshot.len(), 2);
}

#[test]
fn snapshot_merge_round_trips_last_drained_at_and_payload() {
    let mut queue = queue();
    let entry = SnoopEntry::Keyword {
        logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
        target: "00112233445566778899aabbccddeeff".to_string(),
        start_position: 0x8000,
        restrictive_payload_hex: Some("aabb".to_string()),
        hit_count: 5,
        first_seen: ts(100),
        last_seen: ts(120),
        last_drained_at: Some(ts(130)),
    };

    queue.merge_snapshot(vec![entry.clone()]);
    let snapshot = queue.snapshot();
    assert_eq!(snapshot, vec![entry.clone()]);

    let selected = queue.select_next_keyword_request(ts(1000)).unwrap();
    assert_eq!(
        selected,
        ScheduledSnoopRequest {
            logical_key: "keyword:00112233445566778899aabbccddeeff:8000:aabb".to_string(),
            request: SearchKeyReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                start_position: 0x8000,
                restrictive_payload: vec![0xAA, 0xBB],
            },
        }
    );
}

#[test]
fn family_counts_report_each_variant_depth() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        110,
    ));
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        120,
    ));

    assert_eq!(
        queue.family_counts(),
        SnoopQueueFamilyCounts {
            keyword: 1,
            source: 1,
            notes: 1,
        }
    );
}
