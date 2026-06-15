//! Deterministic end-to-end correctness tests for ICH block-level salvage.
//!
//! These prove the destructive-mutation half of AICH recovery without the live
//! wire:
//!  1. `salvage_keeps_good_blocks_and_reverifies_after_one_block`: a 2-part
//!     payload with exactly one corrupt 180 KB block of part 0 -- assert only
//!     that block is needed, the others stay present, and re-supplying it makes
//!     the part MD4-verify and become `Verified`.
//!  2. `block_bitmap_persists_round_trip`: save -> reload -> identical
//!     present-block set after a partial salvage.
//!  3. `contiguous_download_still_verifies_with_block_bitmap`: a normal
//!     sequential download verifies identically (no regression from the bitmap).

use md4::{Digest, Md4};

use super::super::aich_recovery::AichRecoveryHashSet;
use super::super::block_bitmap::PartBlockBitmap;
use super::super::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kAichHashset, Ed2kTransferRuntime, Ed2kTransferState,
    PAYLOAD_FILE_NAME, new_transfer_job,
};
use crate::paths::unique_test_dir;
use emulebb_kad_proto::Ed2kHash;
use std::fs;

/// Distinct byte for block `idx` so each 180 KB block hashes differently and a
/// corruption stays localized to one block.
fn block_fill(idx: usize) -> u8 {
    (idx as u8).wrapping_mul(7).wrapping_add(1)
}

/// Build a 2-part payload: part 0 is a full PARTSIZE made of distinct
/// EMBLOCKSIZE blocks (the last block is partial since PARTSIZE is not an exact
/// multiple of EMBLOCKSIZE), part 1 is a short tail. Returns the bytes.
fn build_two_part_payload() -> Vec<u8> {
    let mut data = Vec::with_capacity(ED2K_PART_SIZE as usize + 12_345);
    let mut idx = 0usize;
    while (data.len() as u64) < ED2K_PART_SIZE {
        let remaining = ED2K_PART_SIZE - data.len() as u64;
        let block = remaining.min(ED2K_EMBLOCK_SIZE) as usize;
        data.extend(std::iter::repeat_n(block_fill(idx), block));
        idx += 1;
    }
    assert_eq!(data.len() as u64, ED2K_PART_SIZE);
    // Short part 1 tail.
    data.extend(std::iter::repeat_n(0xC3u8, 12_345));
    data
}

fn md4(data: &[u8]) -> [u8; 16] {
    Md4::digest(data).into()
}

/// Compute the canonical ED2K file hash + per-part MD4 hashset for `data`.
fn md4_hashset(data: &[u8]) -> (Ed2kHash, Vec<[u8; 16]>) {
    let mut part_hashes = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let end = (pos + ED2K_PART_SIZE as usize).min(data.len());
        part_hashes.push(md4(&data[pos..end]));
        pos = end;
    }
    let mut file_hasher = Md4::new();
    for ph in &part_hashes {
        file_hasher.update(ph);
    }
    (Ed2kHash::from_bytes(file_hasher.finalize().into()), part_hashes)
}

/// AICH master + per-part hashes for `data`, derived through the independent
/// recursive part-root reconstruction in `hashset.rs`.
fn aich_hashset(data: &[u8]) -> Ed2kAichHashset {
    let dir = unique_test_dir("ed2k-salvage-aich-src");
    let path = dir.join("payload.bin");
    fs::write(&path, data).unwrap();
    super::super::build_aich_hashset_from_payload(&path, data.len() as u64).unwrap()
}

/// A sharer-side recovery body for `part` of the full payload.
fn recovery_body_for(data: &[u8], part: u64) -> Vec<u8> {
    let mut sharer = AichRecoveryHashSet::new(data.len() as u64);
    sharer.build_from_data(data).unwrap();
    sharer.create_part_recovery_data(part).unwrap()
}

#[tokio::test]
async fn salvage_keeps_good_blocks_and_reverifies_after_one_block() {
    let root = unique_test_dir("ed2k-salvage-one-block");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let data = build_two_part_payload();
    let (file_hash, md4_parts) = md4_hashset(&data);
    let aich = aich_hashset(&data);
    let job = new_transfer_job(file_hash, "salvage.bin".to_string(), data.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, md4_parts)
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&job.file_hash, aich.clone())
        .await
        .unwrap();

    // Write the payload to the piece store but corrupt exactly one block
    // (block 10) of part 0. The on-disk part 0 now fails MD4.
    let corrupt_block = 10usize;
    let mut on_disk = data.clone();
    let cb_start = corrupt_block * ED2K_EMBLOCK_SIZE as usize;
    let cb_end = cb_start + ED2K_EMBLOCK_SIZE as usize;
    for byte in &mut on_disk[cb_start..cb_end] {
        *byte ^= 0xFF;
    }
    let payload_path = runtime.transfer_dir_path(&job.file_hash).join(PAYLOAD_FILE_NAME);
    fs::write(&payload_path, &on_disk).unwrap();

    // Sanity: part 0 as stored fails MD4 (this is the corrupt-part trigger).
    let part0_disk = &on_disk[..ED2K_PART_SIZE as usize];
    let canonical_part0 = md4(&data[..ED2K_PART_SIZE as usize]);
    assert_ne!(md4(part0_disk), canonical_part0, "corrupt part must fail MD4");

    // Begin salvage with a valid recovery answer for part 0.
    let body = recovery_body_for(&data, 0);
    let outcome = runtime
        .begin_part_salvage(&job.file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .expect("salvage should start for a corrupt part with a trusted AICH root");

    // Exactly the one corrupt block is needed; every other block was salvaged.
    assert_eq!(outcome.needed_ranges.len(), 1, "only one block needs redownload");
    assert_eq!(
        outcome.needed_ranges[0],
        (cb_start as u64, cb_end as u64),
        "the needed range is exactly the corrupt block"
    );
    let total_blocks = ED2K_PART_SIZE.div_ceil(ED2K_EMBLOCK_SIZE) as usize;
    assert_eq!(outcome.recovered_ranges.len(), total_blocks - 1);

    // The persisted bitmap reflects only the corrupt block missing.
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    let piece0 = &manifest.pieces[0];
    assert_eq!(piece0.state, Ed2kTransferState::Missing);
    let bitmap = piece0.resolve_block_bitmap(ED2K_PART_SIZE);
    assert_eq!(bitmap.present_count(), total_blocks - 1);
    assert!(!bitmap.is_present(corrupt_block), "corrupt block stays missing");
    for idx in 0..total_blocks {
        if idx != corrupt_block {
            assert!(bitmap.is_present(idx), "good block {idx} stays present");
        }
    }

    // Re-supply exactly that one corrupt block (the correct bytes). After the
    // block-aligned non-contiguous write, the part MD4-reverifies and becomes
    // Verified.
    let good_block = &data[cb_start..cb_end];
    let verified = runtime
        .write_salvage_block(&job.file_hash, 0, cb_start as u64, cb_end as u64, good_block)
        .await
        .unwrap();
    assert!(
        verified.is_completed(),
        "part must MD4-verify after the last block is re-supplied"
    );

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert!(manifest.pieces[0].block_bitmap.is_none(), "verified part drops the bitmap");
    assert_eq!(manifest.pieces[0].bytes_written, ED2K_PART_SIZE);
    // The on-disk part 0 now matches the canonical bytes.
    let restored = fs::read(&payload_path).unwrap();
    assert_eq!(md4(&restored[..ED2K_PART_SIZE as usize]), canonical_part0);
}

#[tokio::test]
async fn block_bitmap_persists_round_trip() {
    let root = unique_test_dir("ed2k-salvage-persist");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let data = build_two_part_payload();
    let (file_hash, md4_parts) = md4_hashset(&data);
    let aich = aich_hashset(&data);
    let job = new_transfer_job(file_hash, "persist.bin".to_string(), data.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime.store_md4_hashset(&job.file_hash, md4_parts).await.unwrap();
    runtime.store_aich_hashset(&job.file_hash, aich.clone()).await.unwrap();

    // Corrupt two non-adjacent blocks (3 and 40) of part 0.
    let corrupt = [3usize, 40usize];
    let mut on_disk = data.clone();
    for &b in &corrupt {
        let s = b * ED2K_EMBLOCK_SIZE as usize;
        for byte in &mut on_disk[s..s + ED2K_EMBLOCK_SIZE as usize] {
            *byte ^= 0xAA;
        }
    }
    let payload_path = runtime.transfer_dir_path(&job.file_hash).join(PAYLOAD_FILE_NAME);
    fs::write(&payload_path, &on_disk).unwrap();

    let body = recovery_body_for(&data, 0);
    let outcome = runtime
        .begin_part_salvage(&job.file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.needed_ranges.len(), 2);

    // Capture present-block set, force a fresh reload from the metadata store,
    // and assert the present-block set is identical after reload.
    let before = runtime.manifest(&job.file_hash).await.unwrap().pieces[0]
        .resolve_block_bitmap(ED2K_PART_SIZE);

    let reloaded_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let after = reloaded_runtime.manifest(&job.file_hash).await.unwrap().pieces[0]
        .resolve_block_bitmap(ED2K_PART_SIZE);

    assert_eq!(before, after, "bitmap survives save -> reload unchanged");
    assert!(!after.is_present(3));
    assert!(!after.is_present(40));
    let total_blocks = ED2K_PART_SIZE.div_ceil(ED2K_EMBLOCK_SIZE) as usize;
    assert_eq!(after.present_count(), total_blocks - 2);
}

#[tokio::test]
async fn contiguous_download_still_verifies_with_block_bitmap() {
    // A normal sequential download path: append contiguous blocks until the
    // part verifies. The block bitmap derivation must not change this behavior.
    let root = unique_test_dir("ed2k-salvage-no-regression");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let first_piece = vec![0x5Au8; ED2K_PART_SIZE as usize];
    let last_piece = [0x17u8; 9];
    let first_hash = md4(&first_piece);
    let last_hash = md4(&last_piece);
    let mut file_hasher = Md4::new();
    file_hasher.update(first_hash);
    file_hasher.update(last_hash);
    let file_hash = Ed2kHash::from_bytes(file_hasher.finalize().into());
    let job = new_transfer_job(file_hash, "seq.bin".to_string(), ED2K_PART_SIZE + 9);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_hash, last_hash])
        .await
        .unwrap();

    // Sequentially append part 0 in EMBLOCKSIZE blocks via the contiguous path.
    runtime.mark_piece_requested(&job.file_hash, 0).await.unwrap();
    let mut pos = 0u64;
    let mut completed = false;
    while pos < ED2K_PART_SIZE {
        let len = (ED2K_PART_SIZE - pos).min(ED2K_EMBLOCK_SIZE);
        completed = runtime
            .append_piece_block(
                &job.file_hash,
                0,
                pos,
                pos + len,
                &first_piece[pos as usize..(pos + len) as usize],
            )
            .await
            .unwrap()
            .is_completed();
        pos += len;
    }
    assert!(completed, "contiguous part completes on the final block");

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    // The contiguous fast path keeps the compact representation (no bitmap).
    assert!(manifest.pieces[0].block_bitmap.is_none());
    assert_eq!(manifest.pieces[0].bytes_written, ED2K_PART_SIZE);

    // Mid-download the bitmap derivation reflects the contiguous prefix exactly.
    let half = PartBlockBitmap::contiguous_prefix(ED2K_PART_SIZE, ED2K_EMBLOCK_SIZE * 3);
    assert_eq!(half.present_count(), 3);
    assert_eq!(half.contiguous_prefix_bytes(), ED2K_EMBLOCK_SIZE * 3);
}
