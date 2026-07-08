//! MD4-only ICH salvage tests (RUST-PAR-017 DL-5).
//!
//! Oracle behavior under test (PartFile.cpp): an MD4 flush failure only gaps
//! the part logically and adds it to `corrupted_list` (:5186-5190) — the
//! stale on-disk bytes are RETAINED. Every later flush touching the
//! still-incomplete corrupted part re-runs `HashSinglePart` while ICH is
//! enabled (:5214-5216); on a match the remaining gaps are filled from the
//! retained bytes (`FillGap`, :5220-5222), the blackbox is credited
//! (`VerifiedData`, :5225) and re-downloading stops mid-part.

use md4::{Digest, Md4};
use std::fs;
use std::net::Ipv4Addr;

use super::super::aich_recovery::AichRecoveryHashSet;
use super::super::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kTransferRuntime, Ed2kTransferState, PieceWriteOutcome,
    new_transfer_job,
};
use crate::paths::unique_test_dir;
use emulebb_kad_proto::Ed2kHash;

const BLOCK: u64 = ED2K_EMBLOCK_SIZE;
const IP_FIRST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 30);
const IP_RESUPPLY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 40);

fn md4(data: &[u8]) -> [u8; 16] {
    Md4::digest(data).into()
}

/// A single-part payload of exactly three distinct eMule blocks, so the file
/// hash itself is the MD4 part authority (empty hashset).
fn three_block_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity((3 * BLOCK) as usize);
    payload.extend(std::iter::repeat_n(0x11u8, BLOCK as usize));
    payload.extend(std::iter::repeat_n(0x22u8, BLOCK as usize));
    payload.extend(std::iter::repeat_n(0x33u8, BLOCK as usize));
    payload
}

/// Drive a full contiguous download of the single part with block 0 corrupted:
/// the final append fails the MD4 check, flags the part for ICH and retains
/// the stale bytes on disk. Returns `(runtime, file_hash_hex, good_payload)`.
async fn corrupted_single_part_transfer(tag: &str) -> (Ed2kTransferRuntime, String, Vec<u8>) {
    let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(tag)).unwrap();
    let payload = three_block_payload();
    let file_hash = Ed2kHash::from_bytes(md4(&payload));
    let job = new_transfer_job(file_hash, "ich.bin".to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .mark_piece_requested(&job.file_hash, 0)
        .await
        .unwrap();

    let mut corrupted = payload.clone();
    for byte in &mut corrupted[..BLOCK as usize] {
        *byte ^= 0xFF;
    }
    let mut last_outcome = PieceWriteOutcome::Incomplete;
    for idx in 0..3u64 {
        let start = idx * BLOCK;
        let end = start + BLOCK;
        last_outcome = runtime
            .append_piece_block(
                &job.file_hash,
                0,
                start,
                end,
                &corrupted[start as usize..end as usize],
            )
            .await
            .unwrap();
    }
    assert_eq!(
        last_outcome,
        PieceWriteOutcome::VerificationFailed { part_index: 0 },
        "the corrupted part must fail its MD4 flush check"
    );

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert_eq!(manifest.pieces[0].bytes_written, 0);
    assert!(
        manifest.pieces[0].ich_corrupted,
        "an MD4 flush failure must flag the part for ICH (oracle corrupted_list)"
    );
    // Key ICH precondition: the stale bytes are retained on disk (the gap is
    // logical only), so replacement data overlays them.
    let on_disk = fs::read(runtime.payload_path(&job.file_hash)).unwrap();
    assert_eq!(
        on_disk, corrupted,
        "the corrupted part's bytes must be preserved on disk"
    );
    (runtime, job.file_hash, payload)
}

/// Re-downloading only the corrupt prefix re-verifies the part against the
/// retained tail: the remaining gap is filled without re-download, the part
/// is Verified and the blackbox credits the recorded senders.
#[tokio::test]
async fn ich_rehash_salvages_part_after_prefix_redownload() {
    let (runtime, file_hash, payload) =
        corrupted_single_part_transfer("ed2k-ich-salvage-prefix").await;

    // Attribute the original (corrupt) download and the re-supplied prefix to
    // two distinct senders, like the live flush layer does.
    runtime.cbb_record_received_data(&file_hash, 0, 3 * BLOCK, IP_FIRST, None);
    runtime.cbb_record_received_data(&file_hash, 0, BLOCK, IP_RESUPPLY, None);

    let outcome = runtime
        .append_piece_block(&file_hash, 0, 0, BLOCK, &payload[..BLOCK as usize])
        .await
        .unwrap();
    assert_eq!(
        outcome,
        PieceWriteOutcome::IchSalvaged {
            part_index: 0,
            salvaged_bytes: 2 * BLOCK,
        },
        "the good prefix plus the retained tail must re-verify the part early"
    );

    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(manifest.pieces[0].bytes_written, 3 * BLOCK);
    assert!(!manifest.pieces[0].ich_corrupted, "salvage clears the flag");
    assert!(manifest.completed, "the single-part file is now complete");
    let on_disk = fs::read(runtime.payload_path(&file_hash)).unwrap();
    assert_eq!(on_disk, payload, "gap filled from the retained good bytes");

    // ICH success feeds VerifiedData for the whole part (oracle
    // PartFile.cpp:5225): both recorded senders are credited.
    assert!(
        runtime.cbb_verified_bytes_for_test(&file_hash, IP_RESUPPLY) >= BLOCK,
        "the re-supplying sender must be credited as verified"
    );
    assert!(
        runtime.cbb_verified_bytes_for_test(&file_hash, IP_FIRST) > 0,
        "the original sender's surviving ranges must be credited as verified"
    );
}

/// A salvaged manifest state survives a runtime reload (the corrupted flag and
/// retained bytes are durable, mirroring the persisted FT_CORRUPTEDPARTS list).
#[tokio::test]
async fn ich_corrupted_flag_survives_reload() {
    let tag = "ed2k-ich-flag-reload";
    let root = unique_test_dir(tag);
    let (file_hash, payload) = {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        let payload = three_block_payload();
        let file_hash = Ed2kHash::from_bytes(md4(&payload));
        let job = new_transfer_job(
            file_hash,
            "ich-reload.bin".to_string(),
            payload.len() as u64,
        );
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .mark_piece_requested(&job.file_hash, 0)
            .await
            .unwrap();
        let mut corrupted = payload.clone();
        for byte in &mut corrupted[..BLOCK as usize] {
            *byte ^= 0xFF;
        }
        for idx in 0..3u64 {
            let start = idx * BLOCK;
            let end = start + BLOCK;
            runtime
                .append_piece_block(
                    &job.file_hash,
                    0,
                    start,
                    end,
                    &corrupted[start as usize..end as usize],
                )
                .await
                .unwrap();
        }
        (job.file_hash, payload)
    };

    let reloaded = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let manifest = reloaded.manifest(&file_hash).await.unwrap();
    assert!(
        manifest.pieces[0].ich_corrupted,
        "the corrupted-part flag must survive a restart"
    );

    // And ICH still salvages after the reload.
    reloaded.mark_piece_requested(&file_hash, 0).await.unwrap();
    let outcome = reloaded
        .append_piece_block(&file_hash, 0, 0, BLOCK, &payload[..BLOCK as usize])
        .await
        .unwrap();
    assert!(outcome.is_completed(), "ICH salvage works after reload");
}

/// With ICH disabled (oracle `thePrefs.IsICHEnabled()` false) the corrupted
/// part is fully re-downloaded: no early re-hash, no early completion.
#[tokio::test]
async fn ich_disabled_part_redownloads_fully() {
    let (runtime, file_hash, payload) = corrupted_single_part_transfer("ed2k-ich-disabled").await;
    runtime.set_ich_enabled(false);

    let outcome = runtime
        .append_piece_block(&file_hash, 0, 0, BLOCK, &payload[..BLOCK as usize])
        .await
        .unwrap();
    assert_eq!(
        outcome,
        PieceWriteOutcome::Incomplete,
        "with ICH disabled a mid-part flush must not attempt the re-hash"
    );
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Requested);
    assert_eq!(manifest.pieces[0].bytes_written, BLOCK);
    assert!(manifest.pieces[0].ich_corrupted, "flag stays for later");

    // The part completes only after a full re-download.
    let mut last_outcome = PieceWriteOutcome::Incomplete;
    for idx in 1..3u64 {
        let start = idx * BLOCK;
        let end = start + BLOCK;
        last_outcome = runtime
            .append_piece_block(
                &file_hash,
                0,
                start,
                end,
                &payload[start as usize..end as usize],
            )
            .await
            .unwrap();
    }
    assert_eq!(last_outcome, PieceWriteOutcome::Verified);
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert!(!manifest.pieces[0].ich_corrupted);
}

/// While an AICH salvage is in progress (persisted block bitmap), a mid-salvage
/// ICH re-hash miss must leave the bitmap untouched so the AICH flow proceeds;
/// the part then completes through the salvage path itself.
#[tokio::test]
async fn ich_rehash_miss_keeps_aich_salvage_bitmap() {
    let runtime =
        Ed2kTransferRuntime::load_or_create(&unique_test_dir("ed2k-ich-aich-pending")).unwrap();

    // Two-part payload (full part 0 + short tail), like the AICH salvage tests.
    let mut payload = Vec::with_capacity(ED2K_PART_SIZE as usize + 4096);
    let mut idx = 0usize;
    while (payload.len() as u64) < ED2K_PART_SIZE {
        let remaining = ED2K_PART_SIZE - payload.len() as u64;
        let block = remaining.min(BLOCK) as usize;
        payload.extend(std::iter::repeat_n(
            (idx as u8).wrapping_mul(7).wrapping_add(1),
            block,
        ));
        idx += 1;
    }
    payload.extend(std::iter::repeat_n(0xC3u8, 4096));

    let part0_hash = md4(&payload[..ED2K_PART_SIZE as usize]);
    let part1_hash = md4(&payload[ED2K_PART_SIZE as usize..]);
    let mut file_hasher = Md4::new();
    file_hasher.update(part0_hash);
    file_hasher.update(part1_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(file_hash, "ich-aich.bin".to_string(), payload.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![part0_hash, part1_hash])
        .await
        .unwrap();
    let aich = {
        let dir = unique_test_dir("ed2k-ich-aich-pending-src");
        let path = dir.join("payload.bin");
        fs::write(&path, &payload).unwrap();
        super::super::build_aich_hashset_from_payload(&path, payload.len() as u64).unwrap()
    };
    runtime
        .store_aich_hashset(&job.file_hash, aich.clone())
        .await
        .unwrap();

    // Full contiguous download of part 0 with blocks 3 and 40 corrupted:
    // MD4 fails at the part boundary and flags the part for ICH.
    let corrupt_blocks = [3usize, 40usize];
    let mut corrupted = payload.clone();
    for &block in &corrupt_blocks {
        let start = block * BLOCK as usize;
        for byte in &mut corrupted[start..start + BLOCK as usize] {
            *byte ^= 0xAA;
        }
    }
    runtime
        .mark_piece_requested(&job.file_hash, 0)
        .await
        .unwrap();
    let mut pos = 0u64;
    let mut last_outcome = PieceWriteOutcome::Incomplete;
    while pos < ED2K_PART_SIZE {
        let len = (ED2K_PART_SIZE - pos).min(BLOCK);
        last_outcome = runtime
            .append_piece_block(
                &job.file_hash,
                0,
                pos,
                pos + len,
                &corrupted[pos as usize..(pos + len) as usize],
            )
            .await
            .unwrap();
        pos += len;
    }
    assert_eq!(
        last_outcome,
        PieceWriteOutcome::VerificationFailed { part_index: 0 }
    );
    assert!(runtime.manifest(&job.file_hash).await.unwrap().pieces[0].ich_corrupted);

    // AICH recovery answer arrives: block-level salvage starts and only the
    // two corrupt blocks stay missing (this works precisely BECAUSE the stale
    // bytes were retained on disk).
    let body = {
        let mut sharer = AichRecoveryHashSet::new(payload.len() as u64);
        sharer.build_from_data(&payload).unwrap();
        sharer.create_part_recovery_data(0).unwrap()
    };
    let outcome = runtime
        .begin_part_salvage(&job.file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .expect("salvage must start for the corrupt part");
    assert_eq!(outcome.needed_ranges.len(), 2);

    // Re-supply the FIRST corrupt block: the mid-salvage ICH re-hash runs and
    // misses (block 40 still stale-corrupt) — the salvage bitmap must be left
    // untouched so the AICH flow proceeds (no double salvage / no reset).
    let start3 = 3 * BLOCK;
    let outcome = runtime
        .write_salvage_block(
            &job.file_hash,
            0,
            start3,
            start3 + BLOCK,
            &payload[start3 as usize..(start3 + BLOCK) as usize],
        )
        .await
        .unwrap();
    assert_eq!(
        outcome,
        PieceWriteOutcome::IchRehashFailed { part_index: 0 },
        "the ICH re-hash attempt must miss while an AICH-bad block is stale"
    );
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    let bitmap = manifest.pieces[0].resolve_block_bitmap(ED2K_PART_SIZE);
    assert!(bitmap.is_present(3), "the re-supplied block stays present");
    assert!(!bitmap.is_present(40), "the other bad block stays missing");
    assert!(
        manifest.pieces[0].ich_corrupted,
        "flag stays until verified"
    );

    // Re-supply the second corrupt block: the AICH salvage path completes and
    // MD4-verifies the part itself.
    let start40 = 40 * BLOCK;
    let outcome = runtime
        .write_salvage_block(
            &job.file_hash,
            0,
            start40,
            start40 + BLOCK,
            &payload[start40 as usize..(start40 + BLOCK) as usize],
        )
        .await
        .unwrap();
    assert!(outcome.is_completed());
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert!(!manifest.pieces[0].ich_corrupted);
}
