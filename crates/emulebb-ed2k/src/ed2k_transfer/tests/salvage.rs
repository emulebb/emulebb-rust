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
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;

const GOOD_SENDER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const BAD_SENDER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

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
    (
        Ed2kHash::from_bytes(file_hasher.finalize().into()),
        part_hashes,
    )
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

async fn initialized_salvage_transfer(
    tag: &str,
) -> (Ed2kTransferRuntime, String, Vec<u8>, Ed2kAichHashset) {
    let runtime = Ed2kTransferRuntime::load_or_create(&unique_test_dir(tag)).unwrap();
    let data = build_two_part_payload();
    let (file_hash, md4_parts) = md4_hashset(&data);
    let aich = aich_hashset(&data);
    let job = new_transfer_job(file_hash, "proof.bin".to_string(), data.len() as u64);
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, md4_parts)
        .await
        .unwrap();
    runtime
        .reconcile_aich_root(&job.file_hash, Some(aich.master_hash))
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&job.file_hash, aich.clone())
        .await
        .unwrap();
    fs::write(runtime.payload_path(&job.file_hash), &data).unwrap();
    (runtime, job.file_hash, data, aich)
}

#[tokio::test]
async fn rejected_recovery_proofs_never_attempt_raw_payload_reads_or_change_state() {
    let (runtime, file_hash, data, aich) =
        initialized_salvage_transfer("ed2k-salvage-proof-before-io").await;
    runtime.cbb_record_received_data(&file_hash, 0, ED2K_PART_SIZE, GOOD_SENDER, None);
    let mut before = runtime.manifest(&file_hash).await.unwrap();
    let mut bitmap = PartBlockBitmap::empty(ED2K_PART_SIZE);
    bitmap.set_present(1);
    before.pieces[0].apply_block_bitmap(&bitmap);
    before.pieces[0].ich_corrupted = true;
    {
        let _guard = runtime.lock_manifest(&file_hash).await;
        runtime.store_manifest_unlocked(&before).await.unwrap();
    }
    let attribution = format!("{:?}", runtime.corruption_blackbox.lock().unwrap());
    let mut sharer = AichRecoveryHashSet::new(data.len() as u64);
    sharer.build_from_data(&data).unwrap();
    let body16 = sharer.create_part_recovery_data(0).unwrap();
    let body32 = sharer.create_part_recovery_data_force_32bit(0).unwrap();
    let mut cases = Vec::new();
    for (name, body, count_offset, ident_offset, ident_size) in
        [("16-bit", &body16, 0, 2, 2), ("32-bit", &body32, 2, 4, 4)]
    {
        // Remove hash bytes, rather than the ignored 16-bit trailing count.
        cases.push((
            format!("{name} truncated"),
            body[..body.len() - 5].to_vec(),
            "short",
        ));
        let mut invalid_count = body.clone();
        invalid_count[count_offset..count_offset + 2].copy_from_slice(&1u16.to_le_bytes());
        cases.push((
            format!("{name} count"),
            invalid_count,
            "hash count mismatch",
        ));
        for ident in [0u32, 1] {
            let mut forbidden = body.clone();
            forbidden[ident_offset..ident_offset + ident_size]
                .copy_from_slice(&ident.to_le_bytes()[..ident_size]);
            let message = match (ident, ident_size) {
                (0, _) => "invalid hash ident (0)",
                (_, 2) => "master hash overwrite rejected",
                _ => "invalid 32-bit ident",
            };
            cases.push((
                format!("{name} forbidden ident {ident}"),
                forbidden,
                message,
            ));
        }
        if ident_size == 4 {
            let mut forbidden = body.clone();
            forbidden[ident_offset..ident_offset + 4].copy_from_slice(&0x40_0001u32.to_le_bytes());
            cases.push((
                format!("{name} oversized ident"),
                forbidden,
                "invalid 32-bit ident",
            ));
        }
        let mut wrong_root = body.clone();
        wrong_root[ident_offset + ident_size] ^= 0xFF;
        cases.push((
            format!("{name} root failure"),
            wrong_root,
            "hash tree verification failed",
        ));

        // Supply the correct two part roots, but no block leaves. Repeating the
        // part-0 root preserves the required count and passes root verification;
        // the separate lowest-level coverage check must still reject it.
        let mut incomplete = body.clone();
        let count = u16::from_le_bytes(body[count_offset..count_offset + 2].try_into().unwrap());
        for index in 0..usize::from(count) {
            let offset = ident_offset + index * (ident_size + 20);
            let (ident, hash) = if index == 0 {
                (2u32, aich.part_hashes[1])
            } else {
                (3u32, aich.part_hashes[0])
            };
            incomplete[offset..offset + ident_size]
                .copy_from_slice(&ident.to_le_bytes()[..ident_size]);
            incomplete[offset + ident_size..offset + ident_size + 20].copy_from_slice(&hash);
        }
        cases.push((
            format!("{name} incomplete leaves"),
            incomplete,
            "missing lowest-level block hash",
        ));
    }
    for (name, body, message) in cases {
        let error = runtime
            .begin_part_salvage(&file_hash, 0, aich.master_hash, &body)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(message), "{name}: {error:#}");
        assert_eq!(
            runtime.raw_part_read_attempts.load(Ordering::Relaxed),
            0,
            "{name}"
        );
        assert_eq!(
            runtime.manifest(&file_hash).await.unwrap(),
            before,
            "{name}"
        );
        assert_eq!(
            format!("{:?}", runtime.corruption_blackbox.lock().unwrap()),
            attribution,
            "{name}"
        );
        assert!(!runtime.is_client_banned(Some(GOOD_SENDER), None), "{name}");
    }
    for (part, master) in [(0, [0xAB; 20]), (u16::MAX, aich.master_hash)] {
        assert!(
            runtime
                .begin_part_salvage(&file_hash, part, master, &body16)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(runtime.raw_part_read_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(runtime.manifest(&file_hash).await.unwrap(), before);
        assert_eq!(
            format!("{:?}", runtime.corruption_blackbox.lock().unwrap()),
            attribution
        );
    }
    assert_eq!(fs::read(runtime.payload_path(&file_hash)).unwrap(), data);
}

#[tokio::test]
async fn recovery_proof_errors_precede_payload_errors_but_valid_proofs_keep_storage_errors() {
    let (runtime, file_hash, data, aich) =
        initialized_salvage_transfer("ed2k-salvage-proof-storage-errors").await;
    let before = runtime.manifest(&file_hash).await.unwrap();
    // Separate from the intact-payload rejection fixtures: deliberately make
    // storage unreadable as a complete part to pin the error precedence.
    fs::write(runtime.payload_path(&file_hash), []).unwrap();
    let proof_error = runtime
        .begin_part_salvage(&file_hash, 0, aich.master_hash, &[0])
        .await
        .unwrap_err();
    assert_eq!(proof_error.to_string(), "AICH reader: short u16");
    assert_eq!(runtime.raw_part_read_attempts.load(Ordering::Relaxed), 0);
    let storage_error = runtime
        .begin_part_salvage(
            &file_hash,
            0,
            aich.master_hash,
            &recovery_body_for(&data, 0),
        )
        .await
        .unwrap_err();
    assert_eq!(
        storage_error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::UnexpectedEof,
    );
    assert_eq!(runtime.raw_part_read_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(runtime.manifest(&file_hash).await.unwrap(), before);
}

#[tokio::test]
async fn salvage_repair_still_requires_final_part_md4_verification() {
    let (runtime, file_hash, mut data, aich) =
        initialized_salvage_transfer("ed2k-salvage-md4-required").await;
    let body = recovery_body_for(&data, 0);
    data[0] ^= 0xFF;
    fs::write(runtime.payload_path(&file_hash), &data).unwrap();
    let outcome = runtime
        .begin_part_salvage(&file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.raw_part_read_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(outcome.needed_ranges, vec![(0, ED2K_EMBLOCK_SIZE)]);
    let repair = runtime
        .write_salvage_block(
            &file_hash,
            0,
            0,
            ED2K_EMBLOCK_SIZE,
            &data[..ED2K_EMBLOCK_SIZE as usize],
        )
        .await
        .unwrap();
    assert_eq!(
        repair,
        super::super::PieceWriteOutcome::VerificationFailed { part_index: 0 }
    );
    let manifest = runtime.manifest(&file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert!(manifest.pieces[0].ich_corrupted);
    assert!(!manifest.completed);
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
        .reconcile_aich_root(&job.file_hash, Some(aich.master_hash))
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
    let payload_path = runtime
        .transfer_dir_path(&job.file_hash)
        .join(PAYLOAD_FILE_NAME);
    fs::write(&payload_path, &on_disk).unwrap();

    // Sanity: part 0 as stored fails MD4 (this is the corrupt-part trigger).
    let part0_disk = &on_disk[..ED2K_PART_SIZE as usize];
    let canonical_part0 = md4(&data[..ED2K_PART_SIZE as usize]);
    assert_ne!(
        md4(part0_disk),
        canonical_part0,
        "corrupt part must fail MD4"
    );

    // Begin salvage with a valid recovery answer for part 0.
    let body = recovery_body_for(&data, 0);
    runtime.cbb_record_received_data(&job.file_hash, 0, ED2K_PART_SIZE, GOOD_SENDER, None);
    runtime.cbb_record_received_data(
        &job.file_hash,
        cb_start as u64,
        cb_end as u64,
        BAD_SENDER,
        None,
    );
    let outcome = runtime
        .begin_part_salvage(&job.file_hash, 0, aich.master_hash, &body)
        .await
        .unwrap()
        .expect("salvage should start for a corrupt part with a trusted AICH root");
    assert_eq!(runtime.raw_part_read_attempts.load(Ordering::Relaxed), 1);
    assert!(!runtime.is_client_banned(Some(GOOD_SENDER), None));
    assert!(runtime.is_client_banned(Some(BAD_SENDER), None));
    assert_eq!(
        runtime.cbb_verified_bytes_for_test(&job.file_hash, GOOD_SENDER),
        ED2K_PART_SIZE - ED2K_EMBLOCK_SIZE
    );
    assert_eq!(
        runtime.cbb_verified_bytes_for_test(&job.file_hash, BAD_SENDER),
        0
    );

    // Exactly the one corrupt block is needed; every other block was salvaged.
    assert_eq!(
        outcome.needed_ranges.len(),
        1,
        "only one block needs redownload"
    );
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
    assert!(
        !bitmap.is_present(corrupt_block),
        "corrupt block stays missing"
    );
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
        .write_salvage_block(
            &job.file_hash,
            0,
            cb_start as u64,
            cb_end as u64,
            good_block,
        )
        .await
        .unwrap();
    assert!(
        verified.is_completed(),
        "part must MD4-verify after the last block is re-supplied"
    );

    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert!(
        manifest.pieces[0].block_bitmap.is_none(),
        "verified part drops the bitmap"
    );
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
    runtime
        .store_md4_hashset(&job.file_hash, md4_parts)
        .await
        .unwrap();
    runtime
        .reconcile_aich_root(&job.file_hash, Some(aich.master_hash))
        .await
        .unwrap();
    runtime
        .store_aich_hashset(&job.file_hash, aich.clone())
        .await
        .unwrap();

    // Corrupt two non-adjacent blocks (3 and 40) of part 0.
    let corrupt = [3usize, 40usize];
    let mut on_disk = data.clone();
    for &b in &corrupt {
        let s = b * ED2K_EMBLOCK_SIZE as usize;
        for byte in &mut on_disk[s..s + ED2K_EMBLOCK_SIZE as usize] {
            *byte ^= 0xAA;
        }
    }
    let payload_path = runtime
        .transfer_dir_path(&job.file_hash)
        .join(PAYLOAD_FILE_NAME);
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
    let after = reloaded_runtime
        .manifest(&job.file_hash)
        .await
        .unwrap()
        .pieces[0]
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

#[tokio::test]
async fn out_of_order_requested_blocks_are_persisted_by_bitmap() {
    // MFC accepts any incoming range covered by a pending requested block. Live
    // peers can send the second requested block before the first, so the Rust
    // piece store must preserve that data instead of treating it as a bad range.
    let root = unique_test_dir("ed2k-requested-out-of-order-block");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let mut payload = Vec::with_capacity((ED2K_EMBLOCK_SIZE * 2) as usize);
    payload.extend(std::iter::repeat_n(0x31u8, ED2K_EMBLOCK_SIZE as usize));
    payload.extend(std::iter::repeat_n(0x92u8, ED2K_EMBLOCK_SIZE as usize));
    let file_hash = Ed2kHash::from_bytes(md4(&payload));
    let job = new_transfer_job(
        file_hash,
        "out-of-order.bin".to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();

    let second_start = ED2K_EMBLOCK_SIZE;
    let second_end = ED2K_EMBLOCK_SIZE * 2;
    let (first_outcome, first_manifest) = runtime
        .append_or_salvage_block_with_manifest(
            &job.file_hash,
            0,
            second_start,
            second_end,
            &payload[second_start as usize..second_end as usize],
        )
        .await
        .unwrap();
    assert!(
        !first_outcome.is_completed(),
        "a later block alone cannot complete the part"
    );
    let piece = &first_manifest.pieces[0];
    assert_eq!(piece.state, Ed2kTransferState::Missing);
    assert_eq!(
        piece.bytes_written, 0,
        "the contiguous prefix is still missing"
    );
    assert!(
        piece.block_bitmap.is_some(),
        "non-contiguous presence is persisted in the bitmap"
    );
    let bitmap = piece.resolve_block_bitmap(payload.len() as u64);
    assert!(!bitmap.is_present(0), "first block is still missing");
    assert!(bitmap.is_present(1), "second block was preserved");

    let (completed, final_manifest) = runtime
        .append_or_salvage_block_with_manifest(
            &job.file_hash,
            0,
            0,
            ED2K_EMBLOCK_SIZE,
            &payload[..ED2K_EMBLOCK_SIZE as usize],
        )
        .await
        .unwrap();
    assert!(
        completed.is_completed(),
        "the part verifies when the missing prefix arrives"
    );
    assert_eq!(final_manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert_eq!(final_manifest.pieces[0].bytes_written, payload.len() as u64);
    assert!(
        final_manifest.pieces[0].block_bitmap.is_none(),
        "verified parts return to the compact representation"
    );
    assert!(final_manifest.completed);

    let on_disk = fs::read(runtime.payload_path(&job.file_hash)).unwrap();
    assert_eq!(on_disk, payload);
}

#[tokio::test]
async fn out_of_order_transition_preserves_cached_prefix_blocks() {
    // Live peers can pipeline several blocks after the last durable checkpoint
    // and then deliver a later requested range first. When the part switches to
    // bitmap tracking, all already accepted prefix blocks must seed the bitmap.
    let root = unique_test_dir("ed2k-requested-out-of-order-after-cached-prefix");
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();

    let block_count = 31usize;
    let mut payload = Vec::with_capacity(block_count * ED2K_EMBLOCK_SIZE as usize);
    for idx in 0..block_count {
        payload.extend(std::iter::repeat_n(
            block_fill(idx),
            ED2K_EMBLOCK_SIZE as usize,
        ));
    }
    let file_hash = Ed2kHash::from_bytes(md4(&payload));
    let job = new_transfer_job(
        file_hash,
        "cached-prefix-out-of-order.bin".to_string(),
        payload.len() as u64,
    );
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();

    for idx in 0..29usize {
        let start = idx as u64 * ED2K_EMBLOCK_SIZE;
        let end = start + ED2K_EMBLOCK_SIZE;
        let outcome = runtime
            .append_or_salvage_block_with_manifest(
                &job.file_hash,
                0,
                start,
                end,
                &payload[start as usize..end as usize],
            )
            .await
            .unwrap()
            .0;
        assert!(
            !outcome.is_completed(),
            "block {idx} should not complete the file"
        );
    }

    // Durability is batched (8-block / 2 s checkpoint policy, the scale of
    // eMule's ~1.5 MB write buffer): after 29 accepted blocks the byte
    // threshold guarantees at least 24 durable blocks; interval checkpoints
    // may have persisted more on a slow run. The bitmap transition below
    // works off the live runtime's cached manifest, which always holds all 29.
    let reloaded_runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    let reloaded_manifest = reloaded_runtime.manifest(&job.file_hash).await.unwrap();
    assert!(
        reloaded_manifest.pieces[0].bytes_written >= 24 * ED2K_EMBLOCK_SIZE
            && reloaded_manifest.pieces[0].bytes_written <= 29 * ED2K_EMBLOCK_SIZE,
        "accepted request blocks are durable up to the batched checkpoint floor, got {}",
        reloaded_manifest.pieces[0].bytes_written
    );

    let later_start = 30 * ED2K_EMBLOCK_SIZE;
    let later_end = later_start + ED2K_EMBLOCK_SIZE;
    let (_outcome, manifest) = runtime
        .append_or_salvage_block_with_manifest(
            &job.file_hash,
            0,
            later_start,
            later_end,
            &payload[later_start as usize..later_end as usize],
        )
        .await
        .unwrap();

    let piece = &manifest.pieces[0];
    let bitmap = piece.resolve_block_bitmap(payload.len() as u64);
    for idx in 0..29usize {
        assert!(
            bitmap.is_present(idx),
            "cached prefix block {idx} stayed present"
        );
    }
    assert!(!bitmap.is_present(29), "only the skipped block is missing");
    assert!(
        bitmap.is_present(30),
        "later out-of-order block was preserved"
    );

    let missing_start = 29 * ED2K_EMBLOCK_SIZE;
    let missing_end = missing_start + ED2K_EMBLOCK_SIZE;
    let (completed, manifest) = runtime
        .append_or_salvage_block_with_manifest(
            &job.file_hash,
            0,
            missing_start,
            missing_end,
            &payload[missing_start as usize..missing_end as usize],
        )
        .await
        .unwrap();
    assert!(completed.is_completed());
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Verified);
    assert!(manifest.completed);
}
