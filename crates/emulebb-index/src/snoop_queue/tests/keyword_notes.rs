use super::super::ScheduledSnoopRequest;
use super::*;
use emulebb_kad_proto::SearchNotesReq;

#[test]
fn source_and_notes_entries_are_not_selected_for_keyword_drain() {
    let mut queue = queue();
    queue.record(source_entry(
        "source:00112233445566778899aabbccddeeff:0000:4096",
        "00112233445566778899aabbccddeeff",
        0,
        4096,
        100,
    ));
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        110,
    ));
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        120,
    ));

    let selected = queue.select_next_keyword_request(ts(130));
    assert!(selected.is_some());
}

#[test]
fn notes_drain_selects_notes_entries_with_size_shape() {
    let mut queue = queue();
    queue.record(notes_entry(
        "notes:00112233445566778899aabbccddeeff:4096",
        "00112233445566778899aabbccddeeff",
        4096,
        110,
    ));

    let selected = queue.select_next_notes_request(ts(130));
    assert_eq!(
        selected,
        Some(ScheduledSnoopRequest {
            logical_key: "notes:00112233445566778899aabbccddeeff:4096".to_string(),
            request: SearchNotesReq {
                target: "00112233445566778899aabbccddeeff".parse().unwrap(),
                size: 4096,
            },
        })
    );
}

#[test]
fn cooldown_blocks_immediate_reselection_and_later_allows_retry() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_keyword_request(ts(120)).is_none());
    assert!(queue.select_next_keyword_request(ts(141)).is_some());
}

#[test]
fn rate_limit_caps_drains_within_ten_minutes() {
    let mut queue = queue();
    queue.record(keyword_entry(
        "keyword:00112233445566778899aabbccddeeff:0000",
        "00112233445566778899aabbccddeeff",
        0,
        None,
        100,
    ));
    queue.record(keyword_entry(
        "keyword:11112222333344445555666677778888:0000",
        "11112222333344445555666677778888",
        0,
        None,
        101,
    ));
    queue.record(keyword_entry(
        "keyword:9999aaaabbbbccccddddeeeeffff0000:0000",
        "9999aaaabbbbccccddddeeeeffff0000",
        0,
        None,
        102,
    ));

    assert!(queue.select_next_keyword_request(ts(110)).is_some());
    assert!(queue.select_next_keyword_request(ts(150)).is_some());
    assert!(queue.select_next_keyword_request(ts(200)).is_none());
    assert!(queue.select_next_keyword_request(ts(711)).is_some());
}
