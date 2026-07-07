//! CorruptionBlackBox attribution tests (RUST-PAR-017 DL-1).
//!
//! The oracle never bans on an MD4 part failure alone (PartFile.cpp:5184-5199);
//! a ban requires AICH block-level attribution crossing the 32%
//! `CBB_BANTHRESHOLD` corrupt share with verified data counted in the sender's
//! favor (CorruptionBlackBox.cpp:233-309). These tests drive the rust port
//! through the `Ed2kTransferRuntime` cbb_* surface plus one end-to-end
//! `begin_part_salvage` attribution pass.

use md4::{Digest, Md4};
use std::fs;
use std::net::Ipv4Addr;

use super::super::aich_recovery::AichRecoveryHashSet;
use super::super::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kTransferRuntime, PAYLOAD_FILE_NAME, new_transfer_job,
};
use crate::paths::unique_test_dir;
use emulebb_kad_proto::Ed2kHash;

const FILE_A: &str = "00112233445566778899aabbccddeeff";
const IP_A: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const IP_B: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const HASH_A: [u8; 16] = [0xAA; 16];

const BLOCK: u64 = ED2K_EMBLOCK_SIZE;

fn runtime(tag: &str) -> Ed2kTransferRuntime {
    Ed2kTransferRuntime::load_or_create(&unique_test_dir(tag)).unwrap()
}

/// An MD4 part-hash failure alone must never ban the sender: the download path
/// feeds only `ReceivedData` (no AICH verdict exists yet), and evaluating
/// without corrupted records finds no guilty sender.
#[tokio::test]
async fn md4_failure_alone_does_not_ban_sender() {
    let runtime = runtime("ed2k-cbb-md4-no-ban");
    runtime.cbb_record_received_data(FILE_A, 0, ED2K_PART_SIZE, IP_A, Some(HASH_A));
    // The MD4 failure path records nothing further (no VerifiedData /
    // CorruptedData); even an evaluation pass has no corrupted record to act on.
    runtime.cbb_evaluate_part(FILE_A, 0);
    assert!(!runtime.is_client_banned(Some(IP_A), Some(&HASH_A)));
}

/// AICH verdicts marking a sender's entire contribution corrupt cross the 32%
/// threshold and ban it by both keys (IP and last-known user hash).
#[tokio::test]
async fn aich_corrupt_share_over_threshold_bans_ip_and_hash() {
    let runtime = runtime("ed2k-cbb-over-threshold");
    runtime.cbb_record_received_data(FILE_A, 0, BLOCK, IP_A, Some(HASH_A));
    runtime.cbb_record_received_data(FILE_A, BLOCK, 2 * BLOCK, IP_A, Some(HASH_A));
    runtime.cbb_record_corrupted_data(FILE_A, 0, BLOCK);
    runtime.cbb_record_corrupted_data(FILE_A, BLOCK, 2 * BLOCK);
    runtime.cbb_evaluate_part(FILE_A, 0);
    // Banned by IP alone and by user hash alone (both ban keys covered).
    assert!(runtime.is_client_banned(Some(IP_A), None));
    assert!(runtime.is_client_banned(None, Some(&HASH_A)));
}

/// Verified data counts in the sender's favor: one corrupt block out of a whole
/// otherwise-verified part is a ~2% share, and even exactly 32% does not ban
/// (the oracle comparison is strictly greater than `CBB_BANTHRESHOLD`).
#[tokio::test]
async fn verified_credit_keeps_sender_below_threshold() {
    let runtime = runtime("ed2k-cbb-below-threshold");
    // Whole part from IP_A; AICH says one block bad, the rest good.
    runtime.cbb_record_received_data(FILE_A, 0, ED2K_PART_SIZE, IP_A, Some(HASH_A));
    runtime.cbb_record_corrupted_data(FILE_A, 0, BLOCK);
    runtime.cbb_record_verified_data(FILE_A, BLOCK, ED2K_PART_SIZE);
    runtime.cbb_evaluate_part(FILE_A, 0);
    assert!(!runtime.is_client_banned(Some(IP_A), Some(&HASH_A)));

    // Exactly 32%: corrupt = 184320, verified = 391680 -> 184320*100/576000
    // == 32, not > 32, so still no ban.
    let file_b = "ffeeddccbbaa99887766554433221100";
    runtime.cbb_record_received_data(file_b, 0, BLOCK + 391_680, IP_B, None);
    runtime.cbb_record_corrupted_data(file_b, 0, BLOCK);
    runtime.cbb_record_verified_data(file_b, BLOCK, BLOCK + 391_680);
    runtime.cbb_evaluate_part(file_b, 0);
    assert!(!runtime.is_client_banned(Some(IP_B), None));
}

/// A corrupted record is counted as at least one full 180 KB block
/// (CorruptionBlackBox.cpp:271), so a small corrupt range can still cross the
/// threshold against a modest verified credit.
#[tokio::test]
async fn small_corrupt_range_counts_as_full_block() {
    let runtime = runtime("ed2k-cbb-min-block-counting");
    runtime.cbb_record_received_data(FILE_A, 0, 300_100, IP_A, Some(HASH_A));
    // 100 corrupt bytes count as 184320; 300000 verified.
    // 184320*100/484320 = 38% > 32% -> ban.
    runtime.cbb_record_corrupted_data(FILE_A, 0, 100);
    runtime.cbb_record_verified_data(FILE_A, 100, 300_100);
    runtime.cbb_evaluate_part(FILE_A, 0);
    assert!(runtime.is_client_banned(Some(IP_A), Some(&HASH_A)));
}

/// A part resumed across peers mixes writers: each range must be attributed to
/// its actual writer, so the corrupt-block verdict bans only the peer that
/// wrote that block and never the peer that completed the part.
#[tokio::test]
async fn mixed_writers_attribute_ranges_per_actual_writer() {
    let runtime = runtime("ed2k-cbb-mixed-writers");
    runtime.cbb_record_received_data(FILE_A, 0, BLOCK, IP_A, None);
    runtime.cbb_record_received_data(FILE_A, BLOCK, 2 * BLOCK, IP_B, None);
    runtime.cbb_record_corrupted_data(FILE_A, 0, BLOCK);
    runtime.cbb_record_verified_data(FILE_A, BLOCK, 2 * BLOCK);
    runtime.cbb_evaluate_part(FILE_A, 0);
    assert!(runtime.is_client_banned(Some(IP_A), None));
    assert!(!runtime.is_client_banned(Some(IP_B), None));
}

/// A rewritten range belongs to its LAST writer (`ReceivedData` overwrites
/// pending records), so the rewriting peer takes the corrupt verdict.
#[tokio::test]
async fn rewritten_range_attributes_to_last_writer() {
    let runtime = runtime("ed2k-cbb-rewrite");
    runtime.cbb_record_received_data(FILE_A, 0, BLOCK, IP_A, None);
    runtime.cbb_record_received_data(FILE_A, 0, BLOCK, IP_B, None);
    runtime.cbb_record_corrupted_data(FILE_A, 0, BLOCK);
    runtime.cbb_evaluate_part(FILE_A, 0);
    assert!(!runtime.is_client_banned(Some(IP_A), None));
    assert!(runtime.is_client_banned(Some(IP_B), None));
}

fn md4(data: &[u8]) -> [u8; 16] {
    Md4::digest(data).into()
}

/// End-to-end salvage attribution: `begin_part_salvage` feeds the AICH block
/// verdicts into the blackbox and evaluates. The peer that (re)wrote only the
/// corrupt block is banned (100% corrupt share); the peer that supplied the
/// rest of the part is not.
#[tokio::test]
async fn salvage_verdicts_ban_only_the_corrupt_block_writer() {
    let root = unique_test_dir("ed2k-cbb-salvage-attribution");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    // Two-part payload with distinct block fills so corruption stays local.
    let mut data = Vec::with_capacity(ED2K_PART_SIZE as usize + 12_345);
    let mut idx = 0u8;
    while (data.len() as u64) < ED2K_PART_SIZE {
        let remaining = ED2K_PART_SIZE - data.len() as u64;
        let block = remaining.min(ED2K_EMBLOCK_SIZE) as usize;
        data.extend(std::iter::repeat_n(
            idx.wrapping_mul(7).wrapping_add(1),
            block,
        ));
        idx += 1;
    }
    data.extend(std::iter::repeat_n(0xC3u8, 12_345));

    let mut part_hashes = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let end = (pos + ED2K_PART_SIZE as usize).min(data.len());
        part_hashes.push(md4(&data[pos..end]));
        pos = end;
    }
    let mut file_hasher = Md4::new();
    for part_hash in &part_hashes {
        file_hasher.update(part_hash);
    }
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());

    let aich_dir = unique_test_dir("ed2k-cbb-salvage-attribution-src");
    let aich_path = aich_dir.join("payload.bin");
    fs::write(&aich_path, &data).unwrap();
    let aich =
        super::super::build_aich_hashset_from_payload(&aich_path, data.len() as u64).unwrap();

    let job = new_transfer_job(file_hash, "attribution.bin".to_string(), data.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, part_hashes)
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&job.file_hash, aich.clone())
        .await
        .unwrap();

    // On-disk part 0 with exactly block 10 corrupted.
    let corrupt_block = 10usize;
    let cb_start = corrupt_block as u64 * ED2K_EMBLOCK_SIZE;
    let cb_end = cb_start + ED2K_EMBLOCK_SIZE;
    let mut on_disk = data.clone();
    for byte in &mut on_disk[cb_start as usize..cb_end as usize] {
        *byte ^= 0xFF;
    }
    let payload_path = runtime
        .transfer_dir_path(&job.file_hash)
        .join(PAYLOAD_FILE_NAME);
    fs::write(&payload_path, &on_disk).unwrap();

    // IP_B supplied the whole part, then IP_A rewrote exactly the corrupt block
    // (a resumed part with mixed writers).
    runtime.cbb_record_received_data(&job.file_hash, 0, ED2K_PART_SIZE, IP_B, None);
    runtime.cbb_record_received_data(&job.file_hash, cb_start, cb_end, IP_A, Some(HASH_A));

    // Salvage: the recovery answer marks block 10 corrupt, everything else good.
    let mut sharer = AichRecoveryHashSet::new(data.len() as u64);
    sharer.build_from_data(&data).unwrap();
    let body = sharer.create_part_recovery_data(0).unwrap();
    let outcome = runtime
        .begin_part_salvage(&job.file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .expect("salvage should start");
    assert_eq!(outcome.needed_ranges, vec![(cb_start, cb_end)]);

    // The corrupt block's writer is banned (its only contribution is corrupt);
    // the whole-part supplier keeps a >97% verified share and is not.
    assert!(runtime.is_client_banned(Some(IP_A), Some(&HASH_A)));
    assert!(!runtime.is_client_banned(Some(IP_B), None));
}
