use super::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kResumeManifest, Ed2kTransferRuntime, Ed2kTransferState,
    PAYLOAD_FILE_NAME, new_transfer_job,
};
use crate::paths::unique_test_dir;
use crate::{HashType, PopularHash};
use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};
use std::{
    fs,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};

mod aich_tree;
mod aich_trust_corroboration;
mod ban_store_runtime;
mod corruption_blackbox;
mod deliver_runtime;
mod download_throttle;
mod file_status_parts;
mod ich_salvage;
mod inbound_admission;
mod reask_reciprocity;
mod salvage;
mod share_in_place;
mod shared_entry;
mod source_exchange;
mod source_hints;
mod upload_queue;
mod upload_queue_credit;
mod upload_queue_firewalled_callback;
mod upload_queue_priority;
mod upload_queue_score_modifiers;
mod upload_queue_support;
mod upload_session_rotation;
mod upload_slot_pacing;
mod upload_slot_recycle_window;

fn write_repeating_pattern_file(path: &Path, size: usize, pattern: &[u8]) {
    assert!(!pattern.is_empty());
    let mut payload = Vec::with_capacity(size);
    while payload.len() < size {
        let remaining = size - payload.len();
        let chunk_len = remaining.min(pattern.len());
        payload.extend_from_slice(&pattern[..chunk_len]);
    }
    let mut file = fs::File::create(path).unwrap();
    file.write_all(&payload).unwrap();
}

#[tokio::test]
async fn download_activity_reports_average_speed_until_stale() {
    let root = unique_test_dir("ed2k-transfer-download-activity");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let file_hash = "00112233445566778899aabbccddeeff";

    runtime.note_download_payload_bytes_at(file_hash, 65_536, now + Duration::from_secs(1));
    runtime.note_download_payload_bytes_at(file_hash, 32_768, now + Duration::from_secs(3));

    assert_eq!(
        runtime.download_speed_bytes_per_sec_at(file_hash, now + Duration::from_secs(3)),
        49_152
    );
    assert_eq!(
        runtime.download_speed_bytes_per_sec_at(file_hash, now + Duration::from_secs(34)),
        0
    );
}

#[tokio::test]
async fn record_upload_file_churn_flags_same_file_repeat() {
    let root = unique_test_dir("ed2k-transfer-file-churn");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file = "00112233445566778899aabbccddeeff";
    let peer = "aabbccddeeff00112233445566778899";
    // First (peer, file) session start is not churn.
    assert_eq!(runtime.record_upload_file_churn(peer, file), None);
    // The same peer re-starting the same file (e.g. after a reconnect) is churn.
    assert_eq!(runtime.record_upload_file_churn(peer, file), Some(2));
    assert_eq!(runtime.record_upload_file_churn(peer, file), Some(3));
    // A different file for the same peer is tracked independently.
    let other_file = "ffffffffffffffffffffffffffffffff";
    assert_eq!(runtime.record_upload_file_churn(peer, other_file), None);
    // A different peer is independent too.
    let other_peer = "00000000000000000000000000000000";
    assert_eq!(runtime.record_upload_file_churn(other_peer, file), None);
}

#[tokio::test]
async fn stale_download_sources_are_evicted_on_next_write() {
    // A long-running transfer must not accumulate one inner-map entry per
    // endpoint ever observed: a later write opportunistically drops entries
    // older than the staleness window (30s), leaving only the live peer.
    let root = unique_test_dir("ed2k-transfer-source-eviction");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let file_hash = "00112233445566778899aabbccddeeff";

    let stale_peer = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 4662));
    let fresh_peer = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 4662));

    runtime.note_download_source_bytes_at(
        file_hash,
        stale_peer,
        Some([0x01; 16]),
        None,
        4_096,
        now,
    );
    {
        let sources = runtime.download_sources.lock().unwrap();
        assert_eq!(sources.get(file_hash).map(|peers| peers.len()), Some(1));
    }

    // A write well past the staleness window for a different peer must evict the
    // now-stale entry, leaving only the fresh peer.
    let later = now + Duration::from_secs(31);
    runtime.note_download_source_bytes_at(
        file_hash,
        fresh_peer,
        Some([0x02; 16]),
        None,
        4_096,
        later,
    );
    {
        let sources = runtime.download_sources.lock().unwrap();
        let peers = sources.get(file_hash).expect("file entry present");
        assert_eq!(peers.len(), 1, "stale peer should have been evicted");
        assert!(
            peers.contains_key(&fresh_peer.to_string()),
            "fresh peer retained"
        );
        assert!(
            !peers.contains_key(&stale_peer.to_string()),
            "stale peer dropped"
        );
    }
}

#[tokio::test]
async fn download_speed_tracks_sliding_window_not_whole_transfer() {
    // B4: the reported rate must be a short sliding-window average (master
    // CalculateDownloadRate), so a recent burst is not diluted by an early
    // slow start the way a whole-transfer average would be.
    let root = unique_test_dir("ed2k-transfer-sliding-window");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let file_hash = "0011223344556677889900aabbccddee";

    // A small early sample, then a long gap, then a recent burst.
    runtime.note_download_payload_bytes_at(file_hash, 1_000, now);
    // Two recent samples 2s apart, 1 MiB each, observed at +21s/+23s.
    runtime.note_download_payload_bytes_at(file_hash, 1_048_576, now + Duration::from_secs(21));
    runtime.note_download_payload_bytes_at(file_hash, 1_048_576, now + Duration::from_secs(23));

    // Whole-transfer average over 23s would be ~91 KiB/s; the window only sees
    // the two recent samples (the early one fell out of the 10s window).
    let windowed =
        runtime.download_speed_bytes_per_sec_at(file_hash, now + Duration::from_secs(23));
    // span from oldest retained sample (+21s) to now (+23s) = 2s, 2 MiB total.
    assert_eq!(windowed, 2 * 1_048_576 * 1_000 / 2_000);
    assert!(
        windowed > 500_000,
        "windowed rate reflects the recent burst"
    );
}

#[tokio::test]
async fn aggregate_download_speed_and_session_counters_roll_up() {
    let root = unique_test_dir("ed2k-transfer-aggregate-speed");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let now = Instant::now();
    let file_a = "00112233445566778899aabbccddeeff";
    let file_b = "ffeeddccbbaa99887766554433221100";

    // Two files each averaging 49_152 B/s over 3s -> aggregate 98_304 B/s.
    runtime.note_download_payload_bytes_at(file_a, 65_536, now + Duration::from_secs(1));
    runtime.note_download_payload_bytes_at(file_a, 32_768, now + Duration::from_secs(3));
    runtime.note_download_payload_bytes_at(file_b, 65_536, now + Duration::from_secs(1));
    runtime.note_download_payload_bytes_at(file_b, 32_768, now + Duration::from_secs(3));

    assert_eq!(
        runtime.aggregate_download_speed_bytes_per_sec_at(now + Duration::from_secs(3)),
        98_304
    );
    // Session received counter accumulates every payload byte, regardless of staleness.
    assert_eq!(runtime.session_downloaded_bytes(), 196_608);
    // Stale files drop out of the live aggregate but stay in the session total.
    assert_eq!(
        runtime.aggregate_download_speed_bytes_per_sec_at(now + Duration::from_secs(40)),
        0
    );
    assert_eq!(runtime.session_downloaded_bytes(), 196_608);

    // Sent-payload counter is independent and monotonic.
    assert_eq!(runtime.session_uploaded_bytes(), 0);
    runtime.note_session_uploaded_bytes(4_096);
    runtime.note_session_uploaded_bytes(2_048);
    assert_eq!(runtime.session_uploaded_bytes(), 6_144);
}

#[tokio::test]
async fn ensure_job_tracks_verified_parts_via_md4_hashset() {
    let root = unique_test_dir("ed2k-transfer-runtime");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let first_piece = vec![1u8; ED2K_PART_SIZE as usize];
    let last_piece = [2u8; 7];
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "ubuntu-linux.iso".to_string(),
        ED2K_PART_SIZE + 7,
    );
    let manifest = runtime.ensure_job(&job).await.unwrap();
    assert_eq!(manifest.pieces.len(), 2);
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();

    runtime
        .mark_piece_requested(&job.file_hash, 0)
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first_piece)
        .await
        .unwrap();
    let partial = runtime.ensure_job(&job).await.unwrap();
    assert_eq!(partial.pieces[0].state, Ed2kTransferState::Verified);
    assert!(!partial.completed);
    assert_eq!(partial.verified_ranges.len(), 1);
    assert_eq!(partial.verified_ranges[0].start, 0);
    assert_eq!(partial.verified_ranges[0].end, ED2K_PART_SIZE);

    runtime
        .store_piece_data(&job.file_hash, 1, &last_piece)
        .await
        .unwrap();
    let complete = runtime.ensure_job(&job).await.unwrap();
    assert!(complete.completed);
    assert!(
        complete
            .pieces
            .iter()
            .all(|piece| piece.state == Ed2kTransferState::Verified)
    );

    let shared = runtime.shared_catalog().read().await.clone();
    assert!(
        shared
            .iter()
            .any(|entry| entry.file_hash == job.file_hash && entry.verified_complete)
    );
}

#[tokio::test]
async fn recheck_transfer_detects_corruption_and_marks_part_for_redownload() {
    // A complete 2-part file: recheck re-verifies both parts against the MD4
    // hashset. Corrupting part 1 on disk must demote it to Missing (0 bytes) so
    // it is re-downloaded, and the file must no longer be reported complete; the
    // intact part 0 stays Verified.
    use std::io::{Seek, SeekFrom, Write};
    let root = unique_test_dir("ed2k-transfer-recheck");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let first_piece = vec![7u8; ED2K_PART_SIZE as usize];
    let last_piece = [8u8; 11];
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(file_hash, "recheck.iso".to_string(), ED2K_PART_SIZE + 11);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first_piece)
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 1, &last_piece)
        .await
        .unwrap();
    let complete = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(complete.completed);

    // A recheck of the intact file leaves it complete (both parts re-verify).
    assert!(runtime.recheck_transfer(&job.file_hash).await.unwrap());
    let after_clean = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(after_clean.completed);

    // Corrupt the on-disk bytes of part 1 (the trailing short part).
    let payload_path = runtime.payload_path(&job.file_hash);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&payload_path)
            .unwrap();
        file.seek(SeekFrom::Start(ED2K_PART_SIZE)).unwrap();
        file.write_all(&[0xFFu8; 11]).unwrap();
        file.flush().unwrap();
    }

    // Recheck must now detect the corruption: not complete, part 1 demoted to
    // Missing (re-download), part 0 still Verified.
    assert!(!runtime.recheck_transfer(&job.file_hash).await.unwrap());
    let after = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!after.completed);
    assert_eq!(after.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(after.pieces[1].state, Ed2kTransferState::Missing);
    assert_eq!(after.pieces[1].bytes_written, 0);
    // The verified range now covers only part 0.
    assert_eq!(after.verified_ranges.len(), 1);
    assert_eq!(after.verified_ranges[0].start, 0);
    assert_eq!(after.verified_ranges[0].end, ED2K_PART_SIZE);
}

#[tokio::test]
async fn partfile_serves_complete_parts_while_downloading() {
    // A two-part download: part 0 verified, part 1 still missing. eMule serves a
    // partfile's complete parts ("share while downloading"): the part-status
    // answer advertises only the verified part, a block range inside the complete
    // part is served, and a range in the incomplete part is rejected.
    let root = unique_test_dir("ed2k-transfer-partfile-serve");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    // A non-PARTSIZE-multiple size yields exactly two ED2K parts (no phantom
    // trailing zero-length part), with a shorter trailing part.
    let last_part_len = ED2K_PART_SIZE / 2;
    let file_size = ED2K_PART_SIZE + last_part_len;
    let first_piece = vec![3u8; ED2K_PART_SIZE as usize];
    let last_piece = vec![4u8; last_part_len as usize];
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(file_hash, "partfile.iso".to_string(), file_size);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();
    runtime
        .mark_piece_requested(&job.file_hash, 0)
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first_piece)
        .await
        .unwrap();

    // The in-progress partfile is a servable entry with part 0 complete and
    // part 1 missing.
    let entry = runtime.local_entry(&file_hash).await.unwrap().unwrap();
    assert!(!entry.verified_complete);
    assert!(entry.is_servable());
    assert_eq!(entry.complete_parts, vec![true, false]);

    // OP_FILESTATUS body: part_count=2 (LE), then one bit per part LSB-first
    // (only part 0 set) — mirrors CPartFile::WritePartStatus.
    assert_eq!(entry.encode_part_status_body(), vec![0x02, 0x00, 0x01]);

    // A block range inside the verified part 0 is served.
    let in_part0 = runtime
        .read_verified_range(&file_hash, 0, ED2K_EMBLOCK_SIZE)
        .await
        .unwrap();
    assert_eq!(in_part0, Some(vec![3u8; ED2K_EMBLOCK_SIZE as usize]));

    // A range inside the not-yet-complete part 1 is rejected.
    let in_part1 = runtime
        .read_verified_range(
            &file_hash,
            ED2K_PART_SIZE,
            ED2K_PART_SIZE + ED2K_EMBLOCK_SIZE,
        )
        .await
        .unwrap();
    assert!(in_part1.is_none());

    // Once the file completes it becomes fully servable and the part-status
    // answer collapses to the master complete sentinel (WriteUInt16(0)).
    runtime
        .store_piece_data(&job.file_hash, 1, &last_piece)
        .await
        .unwrap();
    let complete = runtime.local_entry(&file_hash).await.unwrap().unwrap();
    assert!(complete.verified_complete);
    assert!(complete.is_servable());
    assert!(complete.complete_parts.is_empty());
    assert_eq!(complete.encode_part_status_body(), vec![0x00, 0x00]);
    let served = runtime
        .read_verified_range(
            &file_hash,
            ED2K_PART_SIZE,
            ED2K_PART_SIZE + ED2K_EMBLOCK_SIZE,
        )
        .await
        .unwrap();
    assert_eq!(served, Some(vec![4u8; ED2K_EMBLOCK_SIZE as usize]));
}

#[tokio::test]
async fn completed_manifest_persists_and_reloads_truthful_aich_hashset() {
    let root = unique_test_dir("ed2k-transfer-runtime-aich");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let first_piece = vec![0x31; ED2K_PART_SIZE as usize];
    let last_piece = vec![0x7A; 32_768];
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "captured-aich.iso".to_string(),
        u64::try_from(first_piece.len() + last_piece.len()).unwrap(),
    );

    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first_piece)
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 1, &last_piece)
        .await
        .unwrap();

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(manifest.aich_hashset.len(), 2);
    let stored_root = manifest.aich_root.clone().expect("missing AICH root");
    let reloaded_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let reloaded = reloaded_runtime
        .aich_hashset(&Ed2kHash::from_str(&job.file_hash).unwrap())
        .await
        .unwrap()
        .expect("missing reloaded AICH hashset");
    assert_eq!(hex::encode(reloaded.master_hash), stored_root);
    assert_eq!(reloaded.part_hashes.len(), 2);

    let local_entry = reloaded_runtime
        .local_entry(&Ed2kHash::from_str(&job.file_hash).unwrap())
        .await
        .unwrap()
        .expect("missing local entry");
    assert_eq!(local_entry.aich_root.as_deref(), Some(stored_root.as_str()));
}

#[tokio::test]
async fn completed_manifest_preserves_remote_aich_identity_over_local_rebuild() {
    let root = unique_test_dir("ed2k-transfer-runtime-remote-aich");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let first_piece = vec![0x31; ED2K_PART_SIZE as usize];
    let last_piece_len = usize::try_from(10_485_760u64 - ED2K_PART_SIZE).unwrap();
    let last_piece = vec![0x7A; last_piece_len];
    let first_piece_hash: [u8; 16] = Md4::digest(&first_piece).into();
    let last_piece_hash: [u8; 16] = Md4::digest(&last_piece).into();
    let mut file_hasher = Md4::new();
    file_hasher.update(first_piece_hash);
    file_hasher.update(last_piece_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "captured-remote-aich.iso".to_string(),
        u64::try_from(first_piece.len() + last_piece.len()).unwrap(),
    );

    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_piece_hash, last_piece_hash])
        .await
        .unwrap();

    let remote_aich = super::Ed2kAichHashset {
        master_hash: hex::decode("050066b767710d1bd84377e71b1b23e522cce4af")
            .unwrap()
            .try_into()
            .unwrap(),
        part_hashes: vec![
            hex::decode("80ebdc35e9618aa7617fa988f756a33b79aa0d6c")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("b05ae2f6c5a179ec4b7ecffdcc18045151be0437")
                .unwrap()
                .try_into()
                .unwrap(),
        ],
    };
    runtime
        .store_aich_hashset(&job.file_hash, remote_aich.clone())
        .await
        .unwrap();

    runtime
        .store_piece_data(&job.file_hash, 0, &first_piece)
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 1, &last_piece)
        .await
        .unwrap();

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some("050066b767710d1bd84377e71b1b23e522cce4af")
    );
    assert_eq!(
        manifest.aich_hashset,
        vec![
            "80ebdc35e9618aa7617fa988f756a33b79aa0d6c".to_string(),
            "b05ae2f6c5a179ec4b7ecffdcc18045151be0437".to_string(),
        ]
    );

    let transfer_dir = Path::new(&root).join(job.file_hash.as_str());
    let rebuilt = super::build_aich_hashset_from_payload(
        &transfer_dir.join(super::PAYLOAD_FILE_NAME),
        manifest.file_size,
    )
    .unwrap();
    assert_ne!(
        hex::encode(rebuilt.master_hash),
        manifest.aich_root.clone().unwrap()
    );

    let local_entry = runtime
        .local_entry(&Ed2kHash::from_str(&job.file_hash).unwrap())
        .await
        .unwrap()
        .expect("missing local entry");
    assert_eq!(
        local_entry.aich_root.as_deref(),
        Some("050066b767710d1bd84377e71b1b23e522cce4af")
    );
}

#[test]
fn build_aich_hashset_matches_stock_tracing_harness_large_roundtrip_fixture() {
    let root = unique_test_dir("ed2k-transfer-stock-aich-fixture");
    let transfer_dir = Path::new(&root).join("fixture");
    fs::create_dir_all(&transfer_dir).unwrap();
    let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
    write_repeating_pattern_file(
        &payload_path,
        10_485_760,
        b"ubuntu-linux-ed2k-private-roundtrip-large",
    );

    let rebuilt = super::build_aich_hashset_from_payload(&payload_path, 10_485_760).unwrap();
    assert_eq!(
        hex::encode(rebuilt.master_hash),
        "050066b767710d1bd84377e71b1b23e522cce4af"
    );
    assert_eq!(
        rebuilt
            .part_hashes
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        vec![
            "80ebdc35e9618aa7617fa988f756a33b79aa0d6c".to_string(),
            "b05ae2f6c5a179ec4b7ecffdcc18045151be0437".to_string(),
        ]
    );
}

#[tokio::test]
async fn ingest_local_file_marks_payload_complete_with_stock_aich_identity() {
    let root = unique_test_dir("ed2k-transfer-local-ingest");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let source_dir = Path::new(&root).join("source");
    fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("ubuntu-linux-private-roundtrip-large.bin");
    write_repeating_pattern_file(
        &source_path,
        10_485_760,
        b"ubuntu-linux-ed2k-private-roundtrip-large",
    );

    let summary = runtime
        .ingest_local_file(&source_path, "ubuntu-linux-private-roundtrip-large.bin")
        .await
        .unwrap();
    assert_eq!(summary.file_size, 10_485_760);
    assert_eq!(summary.md4_hashset_count, 2);
    assert_eq!(summary.aich_hashset_count, 2);
    assert_eq!(
        summary.aich_root,
        "050066b767710d1bd84377e71b1b23e522cce4af"
    );

    let manifest = runtime.manifest(&summary.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(manifest.aich_hashset_acquired);
    assert_eq!(
        manifest.aich_root.as_deref(),
        Some("050066b767710d1bd84377e71b1b23e522cce4af")
    );
    assert_eq!(manifest.md4_hashset.len(), 2);
    assert_eq!(manifest.aich_hashset.len(), 2);
}

#[tokio::test]
async fn ensure_job_ignores_legacy_json_manifest_for_fresh_sql_profiles() {
    let root = unique_test_dir("ed2k-transfer-legacy-json-ignored");
    let file_hash = hex::encode([0x41; 16]);
    let transfer_dir = Path::new(&root).join(&file_hash);
    fs::create_dir_all(&transfer_dir).unwrap();
    fs::write(
            transfer_dir.join("resume-manifest.json"),
            format!(
                "{{\"file_hash\":\"{}\",\"canonical_name\":\"legacy.iso\",\"file_size\":{},\"piece_size\":{},\"completed\":false,\"md4_hashset_acquired\":false,\"md4_hashset\":[],\"verified_ranges\":[],\"pieces\":[],\"sources\":[]}}",
                file_hash,
                ED2K_PART_SIZE + 1,
                ED2K_PART_SIZE,
            ),
        )
        .unwrap();

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let rebuilt = runtime
        .ensure_job(&new_transfer_job(
            Ed2kHash::from_str(&file_hash).unwrap(),
            "legacy.iso".to_string(),
            ED2K_PART_SIZE + 1,
        ))
        .await
        .unwrap();
    assert_eq!(rebuilt.pieces.len(), 2);
    assert!(!rebuilt.aich_hashset_acquired);
    assert!(rebuilt.aich_root.is_none());
    assert!(rebuilt.aich_hashset.is_empty());
}

#[tokio::test]
async fn store_aich_hashset_rejects_internally_inconsistent_root() {
    let root = unique_test_dir("ed2k-transfer-invalid-aich");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x61; 16]);
    let job = new_transfer_job(
        file_hash,
        "invalid-aich.iso".to_string(),
        ED2K_PART_SIZE + 7,
    );
    runtime.ensure_job(&job).await.unwrap();

    let error = runtime
        .store_aich_hashset(
            &job.file_hash,
            super::Ed2kAichHashset {
                master_hash: [0x44; 20],
                part_hashes: vec![[0x11; 20], [0x22; 20]],
            },
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not reconstruct"));
}

#[tokio::test]
async fn reconcile_job_metadata_adopts_unknown_size_and_name() {
    let root = unique_test_dir("ed2k-transfer-reconcile-metadata");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let file_hash = Ed2kHash::from_bytes([0x61; 16]);
    let placeholder_job = new_transfer_job(file_hash, "ed2k-placeholder.bin".to_string(), 0);
    let initial = runtime.ensure_job(&placeholder_job).await.unwrap();
    assert_eq!(initial.file_size, 0);
    assert!(initial.pieces.is_empty());

    let updated = runtime
        .reconcile_job_metadata(
            &placeholder_job.file_hash,
            Some("ubuntu-live.iso"),
            Some(ED2K_PART_SIZE + 7),
        )
        .await
        .unwrap();
    assert_eq!(updated.canonical_name, "ubuntu-live.iso");
    assert_eq!(updated.file_size, ED2K_PART_SIZE + 7);
    assert_eq!(updated.pieces.len(), 2);
    assert!(
        updated
            .pieces
            .iter()
            .all(|piece| piece.state == Ed2kTransferState::Missing)
    );
}

#[tokio::test]
async fn release_piece_request_preserves_partial_piece_progress() {
    let root = unique_test_dir("ed2k-transfer-release-request-progress");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5Au8; 32_768];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();

    let claimed = runtime
        .claim_next_missing_part(&job.file_hash, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed.piece_index, 0);
    assert_eq!(claimed.bytes_written, 0);

    let split = 8_192usize;
    let completed = runtime
        .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
        .await
        .unwrap();
    assert!(!completed.is_completed());

    runtime
        .release_piece_request(&job.file_hash, 0)
        .await
        .unwrap();

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert_eq!(manifest.pieces[0].bytes_written, split as u64);

    let reclaimed = runtime
        .claim_next_missing_part(&job.file_hash, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed.piece_index, 0);
    assert_eq!(reclaimed.bytes_written, split as u64);
}

#[tokio::test]
async fn append_piece_block_keeps_subblock_progress_in_memory_until_checkpoint() {
    let root = unique_test_dir("ed2k-transfer-cached-partial-progress");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x5Au8; 65_536];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = new_transfer_job(
        file_hash,
        "cached-progress.bin".to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .claim_next_missing_part(&job.file_hash, None)
        .await
        .unwrap()
        .unwrap();

    let split = 8_192usize;
    let piece_completed = runtime
        .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
        .await
        .unwrap();
    assert!(!piece_completed.is_completed());

    let cached_manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(
        cached_manifest.pieces[0].state,
        Ed2kTransferState::Requested
    );
    assert_eq!(cached_manifest.pieces[0].bytes_written, split as u64);

    let reloaded_runtime = Ed2kTransferRuntime::load_or_create(Path::new(&root)).unwrap();
    let persisted_manifest = reloaded_runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(
        persisted_manifest.pieces[0].state,
        Ed2kTransferState::Requested
    );
    assert_eq!(persisted_manifest.pieces[0].bytes_written, 0);
}

#[tokio::test]
async fn reclaim_stale_piece_requests_restores_missing_state_with_progress() {
    let root = unique_test_dir("ed2k-transfer-reclaim-stale-request");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6Bu8; 32_768];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = new_transfer_job(file_hash, "resume.bin".to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();

    runtime
        .claim_next_missing_part(&job.file_hash, None)
        .await
        .unwrap()
        .unwrap();
    let split = 8_192usize;
    runtime
        .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
        .await
        .unwrap();

    assert!(
        runtime
            .reclaim_stale_piece_requests(&job.file_hash)
            .await
            .unwrap()
    );

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert_eq!(manifest.pieces[0].bytes_written, split as u64);
}

#[tokio::test]
async fn append_piece_block_persists_piece_completion_after_cached_progress() {
    let root = unique_test_dir("ed2k-transfer-piece-completion-checkpoint");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = vec![0x6Bu8; 65_536];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(&payload).into());
    let job = new_transfer_job(
        file_hash,
        "completion-checkpoint.bin".to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .claim_next_missing_part(&job.file_hash, None)
        .await
        .unwrap()
        .unwrap();

    let split = 8_192usize;
    let first_completed = runtime
        .append_piece_block(&job.file_hash, 0, 0, split as u64, &payload[..split])
        .await
        .unwrap();
    assert!(!first_completed.is_completed());

    let final_completed = runtime
        .append_piece_block(
            &job.file_hash,
            0,
            split as u64,
            payload.len() as u64,
            &payload[split..],
        )
        .await
        .unwrap();
    assert!(final_completed.is_completed());

    let persisted_manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(persisted_manifest.completed);
    assert_eq!(
        persisted_manifest.pieces[0].state,
        Ed2kTransferState::Verified
    );
    assert_eq!(
        persisted_manifest.pieces[0].bytes_written,
        payload.len() as u64
    );

    let reloaded_runtime = Ed2kTransferRuntime::load_or_create(Path::new(&root)).unwrap();
    let reloaded_manifest = reloaded_runtime.manifest(&job.file_hash).await.unwrap();
    assert!(reloaded_manifest.completed);
    assert_eq!(
        reloaded_manifest.pieces[0].state,
        Ed2kTransferState::Verified
    );
    assert_eq!(
        reloaded_manifest.pieces[0].bytes_written,
        payload.len() as u64
    );
}

#[tokio::test]
async fn replace_catalog_hints_preserves_verified_entries() {
    let root = unique_test_dir("ed2k-transfer-hints");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let payload = [9u8, 8, 7, 6];
    let file_hash = Ed2kHash::from_bytes(Md4::digest(payload).into());
    let job = new_transfer_job(file_hash, "verified.bin".to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &payload)
        .await
        .unwrap();

    runtime
        .replace_catalog_hints(&[PopularHash {
            hash: HashType::Ed2k("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            canonical_name: "hint.bin".to_string(),
            size: 12,
            source_count: 3,
        }])
        .await;

    let shared = runtime.shared_catalog().read().await.clone();
    assert!(
        shared
            .iter()
            .any(|entry| entry.file_hash == job.file_hash && entry.verified_complete)
    );
    assert!(shared.iter().any(
        |entry| entry.file_hash == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" && entry.compatibility_hint
    ));
}
