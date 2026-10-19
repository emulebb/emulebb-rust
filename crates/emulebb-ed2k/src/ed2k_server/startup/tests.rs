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
        media: Default::default(),
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
        media: Default::default(),
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
fn old_server_offer_files_use_assigned_high_id_behind_nat() {
    let bind_ip = Ipv4Addr::new(192, 168, 1, 210);
    let assigned_high_id = u32::from_le_bytes([203, 0, 113, 42]);
    let payload =
        encode_offer_files_payload(&[one_entry()], Some(assigned_high_id), bind_ip, 4662, None);

    assert_eq!(u32::from_le_bytes(payload[0..4].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        assigned_high_id
    );
    assert_eq!(
        u16::from_le_bytes(payload[24..26].try_into().unwrap()),
        4662
    );
}

#[test]
fn old_server_offer_files_hide_endpoint_for_low_id_client() {
    let payload = encode_offer_files_payload(
        &[one_entry()],
        Some(42),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        None,
    );

    assert_eq!(u32::from_le_bytes(payload[20..24].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(payload[24..26].try_into().unwrap()), 0);
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
fn old_server_offer_files_use_long_media_names_and_string_length() {
    let mut entry = one_entry();
    entry.media.length_seconds = 3_661;
    entry.media.bitrate_kbps = 128;
    entry.media.codec = "PCM".to_string();
    let payload = encode_offer_files_payload(
        &[entry],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        None,
    );

    assert!(payload.windows(6).any(|window| window == b"length"));
    assert!(payload.windows(7).any(|window| window == b"1:01:01"));
    assert!(payload.windows(7).any(|window| window == b"bitrate"));
    assert!(payload.windows(5).any(|window| window == b"codec"));
}

#[test]
fn offer_files_uses_incomplete_sentinel_for_part_files() {
    let mut entry = one_entry();
    entry.verified_complete = false;
    entry.complete_parts = vec![true, false];
    let payload = encode_offer_files_payload(
        &[entry],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        Some(SERVER_TCP_FLAG_COMPRESSION),
    );

    assert_eq!(
        u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        OFFER_FILE_INCOMPLETE_SENTINEL_CLIENT_ID
    );
    assert_eq!(
        u16::from_le_bytes(payload[24..26].try_into().unwrap()),
        OFFER_FILE_INCOMPLETE_SENTINEL_CLIENT_PORT
    );
}

#[test]
fn offer_files_publishes_nonzero_rating() {
    let mut entry = one_entry();
    entry.rating = 4;
    let payload = encode_offer_files_payload(
        &[entry],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        Some(SERVER_TCP_FLAG_COMPRESSION),
    );

    let tag_count_offset = 26;
    let tag_count = u32::from_le_bytes(
        payload[tag_count_offset..tag_count_offset + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(tag_count, 4);
    let mut tags = &payload[tag_count_offset + 4..];
    let mut rating = None;
    for _ in 0..tag_count {
        let (name, value, rest) = decode_tag_value(tags).unwrap();
        if name == Some(FT_FILERATING) {
            rating = value;
        }
        tags = rest;
    }
    assert_eq!(rating, Some(DecodedTagValue::Unsigned(4)));
}

#[test]
fn offer_files_publish_stock_media_subset() {
    let mut entry = one_entry();
    entry.media = crate::ed2k_transfer::Ed2kMediaMetadata {
        artist: "Artist stays Kad-only".to_string(),
        album: "Album stays Kad-only".to_string(),
        title: "Title stays Kad-only".to_string(),
        length_seconds: 321,
        bitrate_kbps: 192,
        codec: "XVID".to_string(),
    };
    let payload = encode_offer_files_payload(
        &[entry],
        Some(u32::from_le_bytes([192, 168, 1, 210])),
        Ipv4Addr::new(192, 168, 1, 210),
        4662,
        Some(SERVER_TCP_FLAG_COMPRESSION | SERVER_TCP_FLAG_NEWTAGS),
    );

    let tag_count_offset = 26;
    let tag_count = u32::from_le_bytes(
        payload[tag_count_offset..tag_count_offset + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(tag_count, 6);
    let mut tags = &payload[tag_count_offset + 4..];
    let mut decoded = Vec::new();
    for _ in 0..tag_count {
        let (name, value, rest) = decode_tag_value(tags).unwrap();
        decoded.push((name, value));
        tags = rest;
    }
    assert!(decoded.contains(&(Some(FT_MEDIA_LENGTH), Some(DecodedTagValue::Unsigned(321)))));
    assert!(decoded.contains(&(Some(FT_MEDIA_BITRATE), Some(DecodedTagValue::Unsigned(192)))));
    assert!(decoded.contains(&(
        Some(FT_MEDIA_CODEC),
        Some(DecodedTagValue::String("XVID".to_string()))
    )));
    assert!(
        !decoded
            .iter()
            .any(|(name, _)| matches!(name, Some(0xD0..=0xD2)))
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
    // soft limit is used verbatim, and a known hard limit remains exclusive.
    assert_eq!(server_offer_file_limit(0, 0), 200);
    assert_eq!(server_offer_file_limit(50, 0), 50);
    assert_eq!(server_offer_file_limit(200, 0), 200);
    assert_eq!(server_offer_file_limit(500, 0), 200);
    assert_eq!(server_offer_file_limit(500, 3), 2);
    assert_eq!(server_offer_file_limit(50, 1), 0);
}

#[test]
fn offered_files_catalog_honors_server_soft_limit() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let published = HashSet::new();
    // A soft limit below 200 caps the batch at the soft limit and advances
    // the cursor by that amount (so the next batch continues the rotation).
    let limited = ranked_offer_files_at_cursor_skipping_published(&ranked, 0, &published, 50);
    assert_eq!(limited.entries.len(), 50);
    assert_eq!(limited.total_entries, 450);
    assert_eq!(limited.next_cursor, 50);
    // The production helper returns no entries for a zero batch request and
    // clamps oversized batches to MAX_OFFER_FILES_PER_ADVERTISEMENT.
    assert_eq!(
        ranked_offer_files_at_cursor_skipping_published(&ranked, 0, &published, 0)
            .entries
            .len(),
        0
    );
    assert_eq!(
        ranked_offer_files_at_cursor_skipping_published(&ranked, 0, &published, 10_000)
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
fn not_published_files_are_excluded_from_offer_catalog() {
    let mut published = shared_entry(1);
    published.upload_priority = "high".to_string();
    let mut suppressed = shared_entry(2);
    suppressed.upload_priority = "not-published".to_string();
    let catalog = vec![published.clone(), suppressed.clone()];
    let published_hash = popular_hash_offer_file(&published).unwrap().0;
    let suppressed_hash = popular_hash_offer_file(&suppressed).unwrap().0;

    let ranked = ranked_offer_files(&catalog, true);
    assert_eq!(ranked, vec![popular_hash_offer_file(&published).unwrap()]);
    assert_eq!(ranked[0].0, published_hash);
    assert_ne!(ranked[0].0, suppressed_hash);
}

#[test]
fn verified_share_suppresses_same_hash_compatibility_hint() {
    let verified = shared_entry(1);
    let mut hint = verified.clone();
    hint.compatibility_hint = true;
    hint.verified_complete = false;
    hint.display_name = "compatibility-hint.bin".to_string();

    let ranked = ranked_offer_files(&[hint, verified.clone()], true);

    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0], popular_hash_offer_file(&verified).unwrap());
}

#[test]
fn empty_share_advertises_zero_files_without_a_placeholder() {
    // Stock parity: an empty share sends a 0-file OP_OFFERFILES, not a
    // fabricated sample entry.
    let ranked = ranked_offer_files(&[], true);
    let catalog = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &HashSet::new(),
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );
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
    let published = HashSet::new();

    let first = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );
    let second = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        first.next_cursor,
        &published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );
    let third = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        second.next_cursor,
        &published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );

    assert_eq!(first.entries.len(), MAX_OFFER_FILES_PER_ADVERTISEMENT);
    assert_eq!(first.total_entries, 450);
    assert_eq!(first.next_cursor, 200);
    assert_eq!(second.next_cursor, 400);
    assert_eq!(third.next_cursor, 150);
    assert_ne!(first.entries[0].0, second.entries[0].0);
    assert_ne!(second.entries[0].0, third.entries[0].0);
    assert_eq!(third.entries[0].0, ranked[400].0);
    assert_eq!(third.entries[50].0, ranked[0].0);
}

#[test]
fn offered_files_catalog_small_libraries_do_not_rotate() {
    let shared_catalog = (0..3).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);

    let offered = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &HashSet::new(),
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
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

    let offered = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );

    assert_eq!(offered.entries.len(), MAX_OFFER_FILES_PER_ADVERTISEMENT);
    assert_eq!(offered.next_cursor, 400);
    assert_eq!(offered.entries[0].0, ranked[200].0);
}

#[test]
fn offered_files_catalog_scans_to_late_new_hash() {
    let shared_catalog = (0..450).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let last_hash = popular_hash_offer_file(&shared_catalog[449]).unwrap().0;
    let mut already_published = HashSet::new();
    for entry in &ranked {
        if entry.0 != last_hash {
            already_published.insert(entry.0);
        }
    }

    let offered = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );

    assert_eq!(offered.entries.len(), 1);
    assert_eq!(offered.next_cursor, 0);
    assert_eq!(offered.entries[0].0, last_hash);
}

#[test]
fn offered_files_catalog_stops_when_every_hash_was_published() {
    let shared_catalog = (0..3).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let already_published = shared_catalog
        .iter()
        .map(|entry| popular_hash_offer_file(entry).unwrap().0)
        .collect::<HashSet<_>>();

    let offered = ranked_offer_files_at_cursor_skipping_published(
        &ranked,
        0,
        &already_published,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );

    assert!(offered.entries.is_empty());
    assert_eq!(offered.next_cursor, 0);
    assert_eq!(offered.total_entries, 3);
}

#[test]
fn catalog_refresh_only_republishes_new_or_changed_offers() {
    let previous_catalog = (0..3).map(shared_entry).collect::<Vec<_>>();
    let previous_ranked = ranked_offer_files(&previous_catalog, true);
    let unchanged_hash = popular_hash_offer_file(&previous_catalog[0]).unwrap().0;
    let changed_hash = popular_hash_offer_file(&previous_catalog[1]).unwrap().0;
    let removed_hash = popular_hash_offer_file(&previous_catalog[2]).unwrap().0;
    let mut published_hashes = previous_ranked
        .iter()
        .map(|entry| entry.0)
        .collect::<HashSet<_>>();

    let mut changed_entry = previous_catalog[1].clone();
    changed_entry.display_name = "renamed-file.bin".to_string();
    let new_entry = shared_entry(3);
    let new_hash = popular_hash_offer_file(&new_entry).unwrap().0;
    let refreshed_catalog = vec![previous_catalog[0].clone(), changed_entry, new_entry];
    let refreshed_ranked = ranked_offer_files(&refreshed_catalog, true);

    reconcile_offer_files_published_hashes(
        &previous_ranked,
        &refreshed_ranked,
        &mut published_hashes,
    );

    assert_eq!(published_hashes, HashSet::from([unchanged_hash]));
    assert!(!published_hashes.contains(&changed_hash));
    assert!(!published_hashes.contains(&removed_hash));

    let offered = ranked_offer_files_at_cursor_skipping_published(
        &refreshed_ranked,
        0,
        &published_hashes,
        MAX_OFFER_FILES_PER_ADVERTISEMENT,
    );
    let offered_hashes = offered
        .entries
        .iter()
        .map(|entry| entry.0)
        .collect::<HashSet<_>>();
    assert_eq!(offered_hashes, HashSet::from([changed_hash, new_hash]));
}

#[tokio::test]
async fn session_catalog_refresh_sends_only_the_new_offer() {
    use std::sync::Arc;

    use tokio::{
        net::{TcpListener, TcpStream},
        sync::RwLock,
    };

    use crate::ed2k_transfer::IndexedSharedCatalog;

    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let _peer = peer_task.await.unwrap();
    let mut session = super::ServerSession::from_stream_for_test(server_stream, peer_addr);
    session.server_soft_files = MAX_OFFER_FILES_PER_ADVERTISEMENT as u32;
    let shared_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(vec![
        shared_entry(0),
    ])));

    let first =
        send_offer_files_advertisement(&mut session, &shared_catalog, crate::test_bind_ip(), 4662)
            .await
            .unwrap();
    assert_eq!(first.entries_sent, 1);

    shared_catalog.write().await.push(shared_entry(1));
    session.offer_files_refresh_catalog = true;

    let second =
        send_offer_files_advertisement(&mut session, &shared_catalog, crate::test_bind_ip(), 4662)
            .await
            .unwrap();
    assert_eq!(second.entries_sent, 1);
    assert_eq!(second.published_entries, 2);
    assert_eq!(second.pending_entries, 0);
    assert_eq!(session.offer_files_published_hashes.len(), 2);
}

#[tokio::test]
async fn negotiated_refresh_does_not_consume_another_distinct_candidate_slot() {
    use std::sync::Arc;

    use tokio::{
        net::{TcpListener, TcpStream},
        sync::RwLock,
    };

    use crate::ed2k_transfer::IndexedSharedCatalog;

    let listener = TcpListener::bind((crate::test_bind_ip(), 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
    let (server_stream, peer_addr) = listener.accept().await.unwrap();
    let _peer = peer_task.await.unwrap();
    let mut session = super::ServerSession::from_stream_for_test(server_stream, peer_addr);
    session.offer_files_pacing = super::super::session::OfferFilesPacingMode::Negotiated(
        super::super::offer_policy::OfferFilesPolicy::validate(1, 200, 1, 1, 201).unwrap(),
    );
    let original = shared_entry(0);
    let shared_catalog = Arc::new(RwLock::new(IndexedSharedCatalog::from_entries(vec![
        original.clone(),
    ])));

    let first =
        send_offer_files_advertisement(&mut session, &shared_catalog, crate::test_bind_ip(), 4662)
            .await
            .unwrap();
    assert_eq!(first.entries_sent, 1);
    assert_eq!(session.offer_files_distinct_published_hashes.len(), 1);
    assert_eq!(session.offer_files_new_candidate_limit(), 0);
    assert_eq!(session.offer_files_batch_limit(), 200);

    let mut changed = original;
    changed.display_name = "renamed-file.bin".to_string();
    shared_catalog.write().await.replace_with(vec![changed]);
    session.offer_files_refresh_catalog = true;

    let second =
        send_offer_files_advertisement(&mut session, &shared_catalog, crate::test_bind_ip(), 4662)
            .await
            .unwrap();
    assert_eq!(second.entries_sent, 1);
    assert_eq!(session.offer_files_distinct_published_hashes.len(), 1);
    assert_eq!(session.offer_files_new_candidate_limit(), 0);

    shared_catalog.write().await.push(shared_entry(1));
    session.offer_files_refresh_catalog = true;

    let third =
        send_offer_files_advertisement(&mut session, &shared_catalog, crate::test_bind_ip(), 4662)
            .await
            .unwrap();
    assert_eq!(third.entries_sent, 0);
    assert_eq!(third.pending_entries, 1);
    assert_eq!(session.offer_files_distinct_published_hashes.len(), 1);
    session.finish_offer_files_batch(
        third.entries_sent,
        third.pending_entries,
        third.skipped_duplicate_batch,
    );
    assert!(!session.offer_files_publish_requested);
}

#[test]
fn cached_ranked_catalog_covers_one_hundred_thousand_distinct_files_once() {
    let shared_catalog = (0..100_000).map(shared_entry).collect::<Vec<_>>();
    let ranked = ranked_offer_files(&shared_catalog, true);
    let mut published = HashSet::with_capacity(ranked.len());
    let mut cursor = 0usize;
    let mut batches = 0usize;

    while published.len() < ranked.len() {
        let offered = ranked_offer_files_at_cursor_skipping_published(
            &ranked,
            cursor,
            &published,
            MAX_OFFER_FILES_PER_ADVERTISEMENT,
        );
        assert!(!offered.entries.is_empty());
        assert!(offered.entries.len() <= MAX_OFFER_FILES_PER_ADVERTISEMENT);
        for entry in offered.entries {
            assert!(published.insert(entry.0));
        }
        cursor = offered.next_cursor;
        batches += 1;
    }

    assert_eq!(published.len(), 100_000);
    assert_eq!(batches, 500);
    assert!(
        ranked_offer_files_at_cursor_skipping_published(
            &ranked,
            cursor,
            &published,
            MAX_OFFER_FILES_PER_ADVERTISEMENT,
        )
        .entries
        .is_empty()
    );
}
