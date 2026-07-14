use std::net::Ipv4Addr;

use super::super::tag_codec::{DecodedTagValue, decode_tag_value};
use crate::ed2k_transfer::Ed2kSharedEntry;

use super::*;

fn one_entry() -> Ed2kSharedEntry {
    Ed2kSharedEntry {
        file_hash: "00112233445566778899aabbccddeeff".to_string(),
        display_name: "lan-bind-source.bin".to_string(),
        file_size: 1234,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts: Vec::new(),
        publish: Default::default(),
    }
}

fn shared_entry(index: usize) -> Ed2kSharedEntry {
    let mut hash = [0u8; 16];
    hash[0..8].copy_from_slice(&(index as u64).to_le_bytes());
    hash[8..16].copy_from_slice(&(!(index as u64)).to_le_bytes());
    Ed2kSharedEntry {
        file_hash: hex::encode(hash),
        display_name: format!("sample-file-{index:03}.bin"),
        file_size: 1_000 + index as u64,
        verified_complete: true,
        verified_ranges: Vec::new(),
        compatibility_hint: false,
        source_count_hint: None,
        aich_root: None,
        upload_priority: "normal".to_string(),
        auto_upload_priority: false,
        comment: String::new(),
        rating: 0,
        all_time_uploaded_bytes: 0,
        complete_parts: Vec::new(),
        publish: Default::default(),
    }
}

#[tokio::test]
async fn server_list_request_gated_on_add_servers_from_server() {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let mut peer = peer_task.await.unwrap();
    let mut session = super::ServerSession::from_stream_for_test(server_stream, peer_addr);

    // Stock default (AddServersFromServer off): no OP_GETSERVERLIST is sent.
    send_server_list_request(&mut session, false).await.unwrap();
    assert!(!session.server_list_requested);
    let mut probe = [0u8; 1];
    let idle = tokio::time::timeout(Duration::from_millis(150), peer.read(&mut probe)).await;
    assert!(
        idle.is_err(),
        "no packet must be sent when AddServersFromServer is off"
    );

    // Preference enabled: exactly one OP_GETSERVERLIST (empty payload).
    send_server_list_request(&mut session, true).await.unwrap();
    assert!(session.server_list_requested);
    let mut header = [0u8; 6];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], super::super::OP_EDONKEYPROT);
    // Length field covers the opcode byte only (empty body).
    assert_eq!(u32::from_le_bytes(header[1..5].try_into().unwrap()), 1);
    assert_eq!(header[5], OP_GETSERVERLIST);

    // A second call is idempotent (already requested this session).
    send_server_list_request(&mut session, true).await.unwrap();
    let idle_again = tokio::time::timeout(Duration::from_millis(150), peer.read(&mut probe)).await;
    assert!(
        idle_again.is_err(),
        "server list must be requested at most once"
    );
    drop(peer);
}

#[test]
fn offer_files_uses_bind_ip_for_dialable_same_host_lan_sources() {
    let bind_ip = Ipv4Addr::new(192, 168, 1, 210);
    let synthetic_duplicate_high_id = u32::from_le_bytes([1, 0, 0, 1]);
    let payload = encode_offer_files_payload(
        &[one_entry()],
        Some(synthetic_duplicate_high_id),
        bind_ip,
        4662,
        None,
    );

    assert_eq!(u32::from_le_bytes(payload[0..4].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        u32::from_le_bytes(bind_ip.octets())
    );
    assert_eq!(
        u16::from_le_bytes(payload[24..26].try_into().unwrap()),
        4662
    );
}

#[test]
fn offer_files_preserves_complete_sentinel_for_compression_servers() {
    let bind_ip = Ipv4Addr::new(192, 168, 1, 210);
    let payload = encode_offer_files_payload(
        &[one_entry()],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        bind_ip,
        4662,
        Some(SERVER_TCP_FLAG_COMPRESSION),
    );

    assert_eq!(
        u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        OFFER_FILE_COMPLETE_SENTINEL_CLIENT_ID
    );
    assert_eq!(
        u16::from_le_bytes(payload[24..26].try_into().unwrap()),
        OFFER_FILE_COMPLETE_SENTINEL_CLIENT_PORT
    );
}

#[test]
fn offer_files_preserves_unicode_filename_tag() {
    let mut entry = one_entry();
    entry.display_name = "unicode-\u{00e9}-\u{6f22}.bin".to_string();
    let payload = encode_offer_files_payload(
        &[entry],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        None,
    );

    let tag_count_offset = 26;
    assert_eq!(
        u32::from_le_bytes(
            payload[tag_count_offset..tag_count_offset + 4]
                .try_into()
                .unwrap()
        ),
        3
    );
    let (tag_name, tag_value, _rest) = decode_tag_value(&payload[tag_count_offset + 4..]).unwrap();

    assert_eq!(tag_name, Some(FT_FILENAME));
    assert_eq!(
        tag_value,
        Some(DecodedTagValue::String(
            "unicode-\u{00e9}-\u{6f22}.bin".to_string()
        ))
    );
}

#[test]
fn server_offer_file_limit_clamps_like_mfc() {
    use super::super::server_entry::server_offer_file_limit;
    // Unknown (0) and above-200 soft limits fall back to 200; an in-range
    // soft limit is used verbatim (eMule offer-batch clamp).
    assert_eq!(server_offer_file_limit(0), 200);
    assert_eq!(server_offer_file_limit(50), 50);
    assert_eq!(server_offer_file_limit(200), 200);
    assert_eq!(server_offer_file_limit(500), 200);
}

#[test]
fn offered_files_catalog_honors_server_soft_limit() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    // A soft limit below 200 caps the batch at the soft limit and advances
    // the cursor by that amount (so the next batch continues the rotation).
    let limited = offered_files_catalog_at_cursor(&shared_catalog, 0, 50, true);
    assert_eq!(limited.entries.len(), 50);
    assert_eq!(limited.total_entries, 450);
    assert_eq!(limited.next_cursor, 50);
    // The catalog clamps an out-of-range cap to [1, MAX]; 0 cannot zero the
    // batch and a huge cap cannot exceed MAX_OFFER_FILES_PER_ADVERTISEMENT.
    assert_eq!(
        offered_files_catalog_at_cursor(&shared_catalog, 0, 0, true)
            .entries
            .len(),
        1
    );
    assert_eq!(
        offered_files_catalog_at_cursor(&shared_catalog, 0, 10_000, true)
            .entries
            .len(),
        MAX_OFFER_FILES_PER_ADVERTISEMENT
    );
}

#[test]
fn large_file_offered_only_to_largefiles_server() {
    let mut small = shared_entry(1);
    small.file_size = 1_000;
    let mut large = shared_entry(2);
    // > 4 GiB: high dword is non-zero, so eMule treats it as a large file.
    large.file_size = u64::from(u32::MAX) + 4_096;
    let catalog = vec![small.clone(), large.clone()];
    let small_hash = popular_hash_offer_file(&small).unwrap().0;

    // Non-LARGEFILES server: the >4GB file is excluded from the candidate
    // set entirely (SharedFileList.cpp:2649), so only the small file remains.
    let without = ranked_offer_files(&catalog, false);
    assert_eq!(without.len(), 1);
    assert_eq!(without[0].0, small_hash);

    // LARGEFILES server: both files are offered.
    let with = ranked_offer_files(&catalog, true);
    assert_eq!(with.len(), 2);

    // Wire path: server_flags without LARGEFILES advertises one file; with
    // the LARGEFILES bit set it advertises both.
    let no_largefiles = encode_offer_files_payload(
        &catalog,
        Some(u32::from_le_bytes([192, 168, 1, 5])),
        Ipv4Addr::new(192, 168, 1, 5),
        4662,
        None,
    );
    assert_eq!(
        u32::from_le_bytes(no_largefiles[0..4].try_into().unwrap()),
        1
    );
    let with_largefiles = encode_offer_files_payload(
        &catalog,
        Some(u32::from_le_bytes([192, 168, 1, 5])),
        Ipv4Addr::new(192, 168, 1, 5),
        4662,
        Some(SERVER_TCP_FLAG_LARGEFILES),
    );
    assert_eq!(
        u32::from_le_bytes(with_largefiles[0..4].try_into().unwrap()),
        2
    );
}

#[test]
fn empty_share_advertises_zero_files_without_a_placeholder() {
    // Stock parity: an empty share sends a 0-file OP_OFFERFILES, not a
    // fabricated sample entry.
    let catalog = offered_files_catalog_at_cursor(&[], 0, MAX_OFFER_FILES_PER_ADVERTISEMENT, true);
    assert_eq!(catalog.entries.len(), 0);
    assert_eq!(catalog.total_entries, 0);
    let payload = encode_offer_files_payload(&[], Some(0), Ipv4Addr::LOCALHOST, 4662, None);
    assert_eq!(&payload[..4], &0u32.to_le_bytes(), "0 offered files");
    assert_eq!(payload.len(), 4, "no file entries follow the count");
}

#[test]
fn offered_files_catalog_rotates_large_libraries() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);

    let first = offered_files_catalog_at_cursor(
        &shared_catalog,
        0,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );
    let second = offered_files_catalog_at_cursor(
        &shared_catalog,
        first.next_cursor,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );
    let third = offered_files_catalog_at_cursor(
        &shared_catalog,
        second.next_cursor,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );

    assert_eq!(first.entries.len(), MAX_OFFER_FILES_PER_ADVERTISEMENT);
    assert_eq!(first.total_entries, 450);
    assert_eq!(first.next_cursor, 200);
    assert_eq!(second.next_cursor, 400);
    assert_eq!(third.next_cursor, 150);
    assert!(!offer_files_cursor_wrapped(
        first.total_entries,
        0,
        first.next_cursor
    ));
    assert!(!offer_files_cursor_wrapped(
        second.total_entries,
        first.next_cursor,
        second.next_cursor
    ));
    assert!(offer_files_cursor_wrapped(
        third.total_entries,
        second.next_cursor,
        third.next_cursor
    ));
    assert_ne!(first.entries[0].0, second.entries[0].0);
    assert_ne!(second.entries[0].0, third.entries[0].0);
    assert_eq!(third.entries[0].0, ranked[400].0);
    assert_eq!(third.entries[50].0, ranked[0].0);
}

#[test]
fn offered_files_catalog_small_libraries_do_not_rotate() {
    let shared_catalog = (0..3).map(shared_entry).collect::<Vec<_>>();

    let offered = offered_files_catalog_at_cursor(
        &shared_catalog,
        2,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );

    assert_eq!(offered.entries.len(), 3);
    assert_eq!(offered.next_cursor, 0);
    assert_eq!(offered.total_entries, 3);
}

#[test]
fn offered_files_catalog_prioritizes_unpublished_hashes() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let mut already_published = HashSet::new();
    for entry in ranked.iter().take(200) {
        already_published.insert(entry.0);
    }

    let offered = offered_files_catalog_at_cursor_skipping_published(
        &shared_catalog,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );

    assert_eq!(offered.entries.len(), MAX_OFFER_FILES_PER_ADVERTISEMENT);
    assert_eq!(offered.next_cursor, 400);
    assert_eq!(offered.entries[0].0, ranked[200].0);
}

#[test]
fn offered_files_catalog_scans_to_late_new_hash() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    let mut already_published = HashSet::new();
    for entry in shared_catalog.iter().take(449) {
        already_published.insert(popular_hash_offer_file(entry).unwrap().0);
    }

    let offered = offered_files_catalog_at_cursor_skipping_published(
        &shared_catalog,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );

    assert_eq!(offered.entries.len(), 1);
    assert_eq!(offered.next_cursor, 0);
    assert_eq!(
        offered.entries[0].0,
        popular_hash_offer_file(&shared_catalog[449]).unwrap().0
    );
}

#[test]
fn offered_files_catalog_restarts_ranked_cycle_when_every_hash_was_published() {
    let shared_catalog = (0..3).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let already_published = shared_catalog
        .iter()
        .map(|entry| popular_hash_offer_file(entry).unwrap().0)
        .collect::<HashSet<_>>();

    let offered = offered_files_catalog_at_cursor_skipping_published(
        &shared_catalog,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
        true,
    );

    assert_eq!(offered.entries, ranked);
    assert_eq!(offered.next_cursor, 0);
    assert_eq!(offered.total_entries, 3);
}
