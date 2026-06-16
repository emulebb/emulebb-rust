//! Deterministic correctness tests for the block-level AICH hash tree.
//!
//! Correctness is proven three ways, none of which need the live wire:
//!  1. Hand-derived SHA1 vectors for the smallest tree shapes (single block,
//!     two blocks) -- these pin the leaf = SHA1(block) and inner =
//!     SHA1(left||right) semantics exactly.
//!  2. Cross-check against the independent recursive root reconstruction in
//!     `hashset.rs` (`build_aich_hashset_from_payload`): two separately written
//!     ports of the master algorithm must agree on the master hash for many
//!     sizes spanning block/part boundaries.
//!  3. A round-trip: serve recovery data, read it back into a trusted tree,
//!     corrupt exactly one 180 KB block, run the salvage compute, and assert
//!     exactly that block is flagged corrupt and all others are recovered.

use sha1::{Digest, Sha1};

use super::super::aich_recovery::{AichRecoveryHashSet, compute_part_recovery};
use super::super::aich_tree::sha1_block;
use super::super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE};

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    out
}

fn sha1_concat(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(a);
    h.update(b);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    out
}

/// Deterministic, reproducible byte pattern of length `len`.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

/// Repeating byte pattern used by the stock tracing-harness AICH fixture.
fn repeating(len: usize, seed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let take = (len - out.len()).min(seed.len());
        out.extend_from_slice(&seed[..take]);
    }
    out
}

#[test]
fn master_hash_matches_stock_emule_tracing_harness_fixture() {
    // The strongest cross-check: this 10_485_760-byte (2-part) fixture's AICH
    // root + part hashes were produced by eMule itself via the stock tracing
    // harness (see tests.rs build_aich_hashset_matches_stock_tracing_harness_*).
    // Our independent mutable-tree port must reproduce them byte for byte.
    let size = 10_485_760u64;
    let data = repeating(size as usize, b"ubuntu-linux-ed2k-private-roundtrip-large");
    let mut set = AichRecoveryHashSet::new(size);
    set.build_from_data(&data).unwrap();
    assert_eq!(
        hex::encode(set.master_hash()),
        "050066b767710d1bd84377e71b1b23e522cce4af",
        "AICH master hash must match the eMule-derived fixture root"
    );
    // Part 0 is a full PARTSIZE part: it must expose the full block count.
    let expected_blocks = ED2K_PART_SIZE.div_ceil(ED2K_EMBLOCK_SIZE) as usize;
    assert_eq!(set.part_block_hashes(0).unwrap().len(), expected_blocks);
}

#[test]
fn served_recovery_data_round_trips_for_stock_fixture() {
    // End-to-end of the serve path algorithm on the eMule-derived fixture:
    // build the full tree, emit recovery data for each part, read it back into a
    // tree that only trusts the master hash, and confirm every block verifies.
    let size = 10_485_760u64;
    let data = repeating(size as usize, b"ubuntu-linux-ed2k-private-roundtrip-large");
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let master = sharer.master_hash();

    let parts = size.div_ceil(ED2K_PART_SIZE);
    for part in 0..parts {
        let body = sharer.create_part_recovery_data(part).unwrap();
        let mut downloader = AichRecoveryHashSet::new(size);
        downloader.set_master_hash(master);
        downloader
            .read_recovery_data(part, &body)
            .unwrap_or_else(|e| panic!("part {part} recovery must verify: {e}"));
        let trusted = downloader.part_block_hashes(part).unwrap();
        let p_start = (part * ED2K_PART_SIZE) as usize;
        let p_size = (size - part * ED2K_PART_SIZE).min(ED2K_PART_SIZE) as usize;
        let clean =
            compute_part_recovery(size, part, &data[p_start..p_start + p_size], &trusted).unwrap();
        assert!(clean.corrupt_ranges.is_empty(), "part {part} must be clean");
    }
}

#[test]
fn single_block_master_hash_is_sha1_of_data() {
    // File of exactly one block-or-less => root is a single leaf node whose
    // hash is SHA1(data). Hand-derived vector.
    let data = pattern(1000);
    let mut set = AichRecoveryHashSet::new(data.len() as u64);
    set.build_from_data(&data).unwrap();
    assert!(set.master_hash_valid());
    assert_eq!(set.master_hash(), sha1(&data));
    // sha1_block helper agrees.
    assert_eq!(sha1_block(&data), sha1(&data));
}

#[test]
fn full_single_block_master_hash() {
    // Exactly EMBLOCKSIZE bytes: still a single block leaf.
    let data = pattern(ED2K_EMBLOCK_SIZE as usize);
    let mut set = AichRecoveryHashSet::new(data.len() as u64);
    set.build_from_data(&data).unwrap();
    assert_eq!(set.master_hash(), sha1(&data));
}

#[test]
fn two_block_master_hash_is_sha1_of_children() {
    // One block + a partial block, both under PARTSIZE => root base is
    // EMBLOCKSIZE, root splits 1 block left / 1 block right.
    // master = SHA1( SHA1(block0) || SHA1(block1) ). Hand-derived vector.
    let len = ED2K_EMBLOCK_SIZE as usize + 5000;
    let data = pattern(len);
    let mut set = AichRecoveryHashSet::new(len as u64);
    set.build_from_data(&data).unwrap();

    let block0 = sha1(&data[..ED2K_EMBLOCK_SIZE as usize]);
    let block1 = sha1(&data[ED2K_EMBLOCK_SIZE as usize..]);
    let expected = sha1_concat(&block0, &block1);
    assert_eq!(set.master_hash(), expected);
}

#[test]
fn three_block_tree_shape_matches_master_split() {
    // 3 blocks under PARTSIZE. Master: nBlocks=3, root is left branch =>
    // nLeft = (3+1)/2 = 2 blocks, nRight = 1 block.
    // left node (2 blocks, left): nLeft=(2+1)/2=1, nRight=1.
    // => master = SHA1( SHA1(SHA1(b0)||SHA1(b1)) || SHA1(b2) ).
    let len = 2 * ED2K_EMBLOCK_SIZE as usize + 10;
    let data = pattern(len);
    let mut set = AichRecoveryHashSet::new(len as u64);
    set.build_from_data(&data).unwrap();

    let bs = ED2K_EMBLOCK_SIZE as usize;
    let b0 = sha1(&data[..bs]);
    let b1 = sha1(&data[bs..2 * bs]);
    let b2 = sha1(&data[2 * bs..]);
    let left = sha1_concat(&b0, &b1);
    let expected = sha1_concat(&left, &b2);
    assert_eq!(set.master_hash(), expected);
}

#[test]
fn master_hash_matches_independent_reconstruction() {
    // Cross-check the full mutable tree against the independent recursive root
    // reconstruction in hashset.rs across many sizes, including those that span
    // the PARTSIZE boundary (multi-part trees).
    use std::io::Write;
    let sizes = [
        1u64,
        100,
        ED2K_EMBLOCK_SIZE - 1,
        ED2K_EMBLOCK_SIZE,
        ED2K_EMBLOCK_SIZE + 1,
        3 * ED2K_EMBLOCK_SIZE + 17,
        ED2K_PART_SIZE - 1,
        ED2K_PART_SIZE,
        ED2K_PART_SIZE + 1,
        ED2K_PART_SIZE + ED2K_EMBLOCK_SIZE + 123,
        2 * ED2K_PART_SIZE + 4242,
        3 * ED2K_PART_SIZE - 1,
    ];
    let dir = crate::paths::unique_test_dir("aich_tree_xcheck");
    for (i, &size) in sizes.iter().enumerate() {
        let data = pattern(size as usize);
        let mut set = AichRecoveryHashSet::new(size);
        set.build_from_data(&data).unwrap();

        let payload_path = dir.join(format!("payload_{i}.bin"));
        let mut f = std::fs::File::create(&payload_path).unwrap();
        f.write_all(&data).unwrap();
        f.sync_all().unwrap();
        let independent = super::super::build_aich_hashset_from_payload(&payload_path, size).unwrap();
        assert_eq!(
            set.master_hash(),
            independent.master_hash,
            "master hash mismatch for size {size}"
        );
    }
}

#[test]
fn recovery_data_round_trip_and_single_block_salvage() {
    // A 2-part file. We "own" part 0 fully (the sharer), serve recovery data,
    // read it into a trusting downloader tree (only the master hash known),
    // verify it round-trips, then corrupt exactly one block of our local copy
    // and assert the salvage compute flags exactly that block.
    let size = ED2K_PART_SIZE + 3 * ED2K_EMBLOCK_SIZE + 555;
    let data = pattern(size as usize);

    // Sharer side: full tree from data.
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let master = sharer.master_hash();

    // Part 1 is the short trailing part.
    let part = 1u64;
    let recovery_body = sharer.create_part_recovery_data(part).unwrap();

    // Downloader side: only knows the trusted master hash.
    let mut downloader = AichRecoveryHashSet::new(size);
    downloader.set_master_hash(master);
    downloader
        .read_recovery_data(part, &recovery_body)
        .expect("recovery data must verify against the trusted master hash");

    let trusted = downloader.part_block_hashes(part).unwrap();

    let p_start = (part * ED2K_PART_SIZE) as usize;
    let p_size = (size - part * ED2K_PART_SIZE) as usize;
    let good_part = &data[p_start..p_start + p_size];

    // Clean part: everything recovers, nothing corrupt.
    let clean = compute_part_recovery(size, part, good_part, &trusted).unwrap();
    assert!(clean.corrupt_ranges.is_empty());
    let block_count = p_size.div_ceil(ED2K_EMBLOCK_SIZE as usize);
    assert_eq!(clean.recovered_ranges.len(), block_count);

    // Corrupt exactly one block (block index 1) and re-run.
    let mut corrupt = good_part.to_vec();
    let corrupt_block = 1usize;
    let cb_start = corrupt_block * ED2K_EMBLOCK_SIZE as usize;
    corrupt[cb_start] ^= 0xff;
    let out = compute_part_recovery(size, part, &corrupt, &trusted).unwrap();

    assert_eq!(out.corrupt_ranges.len(), 1, "exactly one block must be bad");
    assert_eq!(out.recovered_ranges.len(), block_count - 1);
    let abs_bad_start = part * ED2K_PART_SIZE + corrupt_block as u64 * ED2K_EMBLOCK_SIZE;
    assert_eq!(out.corrupt_ranges[0].0, abs_bad_start);
    assert_eq!(
        out.corrupt_ranges[0].1,
        abs_bad_start + ED2K_EMBLOCK_SIZE
    );
    // recovered bytes = whole part minus the one bad block.
    assert_eq!(out.recovered_bytes(), p_size as u64 - ED2K_EMBLOCK_SIZE);
}

#[test]
fn recovery_data_with_wrong_master_hash_is_rejected() {
    let size = ED2K_PART_SIZE + 2 * ED2K_EMBLOCK_SIZE + 99;
    let data = pattern(size as usize);
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let recovery_body = sharer.create_part_recovery_data(1).unwrap();

    // Downloader trusts a DIFFERENT master hash => verification must fail.
    let mut downloader = AichRecoveryHashSet::new(size);
    downloader.set_master_hash([0xab; 20]);
    assert!(downloader.read_recovery_data(1, &recovery_body).is_err());
}

#[test]
fn recovery_data_for_part_zero_round_trips() {
    // Part 0 is a full PARTSIZE part of a multi-part file.
    let size = 2 * ED2K_PART_SIZE + ED2K_EMBLOCK_SIZE + 1;
    let data = pattern(size as usize);
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let master = sharer.master_hash();
    let body = sharer.create_part_recovery_data(0).unwrap();

    let mut downloader = AichRecoveryHashSet::new(size);
    downloader.set_master_hash(master);
    downloader.read_recovery_data(0, &body).unwrap();
    let trusted = downloader.part_block_hashes(0).unwrap();
    // PARTSIZE / EMBLOCKSIZE = 9728000 / 184320 = 52.78 -> 53 blocks.
    let expected_blocks = (ED2K_PART_SIZE).div_ceil(ED2K_EMBLOCK_SIZE) as usize;
    assert_eq!(trusted.len(), expected_blocks);

    let good = &data[..ED2K_PART_SIZE as usize];
    let clean = compute_part_recovery(size, 0, good, &trusted).unwrap();
    assert!(clean.corrupt_ranges.is_empty());
}

#[test]
fn normal_file_recovery_uses_16bit_ident_framing() {
    // For files <= 4 GiB the body must use the 16-bit ident form: a leading
    // non-zero hash count (count1), then 16-bit-ident blocks, then a trailing
    // count2 = 0. The wire size per hash is HASHSIZE + 2.
    let size = ED2K_PART_SIZE + 2 * ED2K_EMBLOCK_SIZE + 99;
    let data = pattern(size as usize);
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let body = sharer.create_part_recovery_data(1).unwrap();

    let count1 = u16::from_le_bytes([body[0], body[1]]);
    assert!(count1 > 0, "16-bit form must lead with a non-zero count1");
    // count1 16-bit-ident hashes, then a trailing zero count2.
    let expected = 2 + usize::from(count1) * (20 + 2) + 2;
    assert_eq!(body.len(), expected, "16-bit framing size mismatch");
    let count2 = u16::from_le_bytes([body[body.len() - 2], body[body.len() - 1]]);
    assert_eq!(count2, 0, "16-bit form must trail with count2 = 0");
}

#[test]
fn large_file_32bit_ident_recovery_round_trips() {
    // The serve path for >4 GiB files emits 32-bit identifiers
    // (bUse32BitIdentifier). Build a small valid tree (the geometry is
    // size-independent), emit the body forced into the large-file 32-bit
    // framing, and confirm the existing 32-bit reader path verifies it.
    let size = 2 * ED2K_PART_SIZE + 3 * ED2K_EMBLOCK_SIZE + 777;
    let data = pattern(size as usize);
    let mut sharer = AichRecoveryHashSet::new(size);
    sharer.build_from_data(&data).unwrap();
    let master = sharer.master_hash();

    let part = 1u64;
    let body = sharer.create_part_recovery_data_force_32bit(part).unwrap();

    // Large-file framing: leading 16-bit count == 0, then the 32-bit-hash
    // count, then count * (20 + 4) bytes; no trailing 16-bit-count word.
    let count1 = u16::from_le_bytes([body[0], body[1]]);
    assert_eq!(count1, 0, "32-bit form must lead with count1 = 0");
    let count2 = u16::from_le_bytes([body[2], body[3]]);
    assert!(count2 > 0, "32-bit form must carry a non-zero count2");
    assert_eq!(
        body.len(),
        4 + usize::from(count2) * (20 + 4),
        "32-bit framing size mismatch"
    );

    // The downloader trusts only the master hash and reads the 32-bit body.
    let mut downloader = AichRecoveryHashSet::new(size);
    downloader.set_master_hash(master);
    downloader
        .read_recovery_data(part, &body)
        .expect("32-bit recovery body must verify against the trusted master hash");
    let trusted = downloader.part_block_hashes(part).unwrap();

    let p_start = (part * ED2K_PART_SIZE) as usize;
    let p_size = (size - part * ED2K_PART_SIZE).min(ED2K_PART_SIZE) as usize;
    let clean =
        compute_part_recovery(size, part, &data[p_start..p_start + p_size], &trusted).unwrap();
    assert!(clean.corrupt_ranges.is_empty(), "part must verify clean");
}
